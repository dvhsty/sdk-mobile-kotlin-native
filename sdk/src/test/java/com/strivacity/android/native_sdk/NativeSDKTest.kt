@file:OptIn(ExperimentalCoroutinesApi::class)

package com.strivacity.android.native_sdk

import FakeLogging
import TokenResponseBuilder
import com.strivacity.android.native_sdk.mocks.MutableTestClock
import com.strivacity.android.native_sdk.mocks.NativeSDKBuilder
import com.strivacity.android.native_sdk.mocks.captureParams
import com.strivacity.android.native_sdk.mocks.expiredAccessToken
import com.strivacity.android.native_sdk.mocks.fakeInitResponsePayload
import com.strivacity.android.native_sdk.mocks.missingAccessToken
import com.strivacity.android.native_sdk.mocks.respondFlowOAuthError
import com.strivacity.android.native_sdk.mocks.respondFlowRedirect
import com.strivacity.android.native_sdk.mocks.respondInit200
import com.strivacity.android.native_sdk.mocks.respondPostLoginRedirect
import com.strivacity.android.native_sdk.mocks.respondTokenExchange200
import com.strivacity.android.native_sdk.mocks.respondTokenExchangeException
import com.strivacity.android.native_sdk.mocks.storeProfile
import com.strivacity.android.native_sdk.mocks.validAccessToken
import com.strivacity.android.native_sdk.render.FallbackHandler
import com.strivacity.android.native_sdk.render.LoginController
import com.strivacity.android.native_sdk.render.models.Screen
import com.strivacity.android.native_sdk.service.HttpService
import com.strivacity.android.native_sdk.service.LoginHandlerService
import com.strivacity.android.native_sdk.service.OIDCHandlerService
import com.strivacity.android.native_sdk.service.OidcParams
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.fullPath
import io.ktor.http.headers
import io.ktor.http.headersOf
import kotlin.time.Duration.Companion.hours
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoMoreInteractions

internal abstract class NativeSDKTestBase {
  protected lateinit var sdkBuilder: NativeSDKBuilder
  protected lateinit var testClock: MutableTestClock
  protected lateinit var testSession: Session
  protected lateinit var testStorage: TestStorage

  @Before
  fun setUp() {
    testStorage = TestStorage()
    testSession = spy(Session(testStorage))
    testClock = MutableTestClock()
    sdkBuilder = NativeSDKBuilder {
      this.storage = testStorage
      this.session = testSession
      this.clock = testClock
    }
  }
}

internal class NativeSDKInit : NativeSDKTestBase() {

  @Test
  fun init_shouldLoadStoredSession() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.build()
    sdk.initializeSession()
    verify(testSession, atLeastOnce()).load()
  }

  @Test
  fun init_shouldAttemptRefresh() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.spy()
    sdk.initializeSession()
    verify(sdk).refreshTokensIfNeeded()
  }
}

internal class NativeSDKRefresh : NativeSDKTestBase() {

  @Test
  fun refresh_shortcuts_whenAccessTokenIsValid() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.store { validAccessToken() }.build()
    val wasRefreshed = sdk.refreshTokensIfNeeded()
    assertFalse(wasRefreshed)
  }

  @Test
  fun refresh_shortcuts_whenAccessTokenIsMissing() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.store { missingAccessToken() }.build()

    val wasRefreshed = sdk.refreshTokensIfNeeded()
    assertFalse(wasRefreshed)
  }

  @Test
  fun refresh_shouldClearStorage_whenRefreshTokenMissing() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.store { missingAccessToken() }.build()
    testClock.advanceBy(2.hours)
    val wasRefreshed = sdk.refreshTokensIfNeeded()
    assertFalse(wasRefreshed)
    // session.clear() nulls out profile as well
    assertNull(sdk.session.profile.value)
  }

  @Test
  fun refresh_shouldRetrieveNewTokenAndStore() = runTest {
    val updatedTokenResponse = TokenResponseBuilder().createAsTokenResponse()
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http { request ->
              when {
                request.url.encodedPath.startsWith("/oauth2/token") ->
                    respond(
                        content = Json.encodeToString(updatedTokenResponse),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                else -> null
              }
            }
            .store { expiredAccessToken() }
            .build()
    testClock.advanceBy(2.hours)

    val currentRefreshToken = sdk.session.profile.value!!.tokenResponse.refreshToken!!
    val wasRefreshed = sdk.refreshTokensIfNeeded()
    assertTrue(wasRefreshed)
    // refresh token was rotated
    assertNotEquals(currentRefreshToken, sdk.session.profile.value?.tokenResponse?.refreshToken)
    verify(testSession).update(updatedTokenResponse)
  }

  @Test
  fun refresh_shouldClearStorage_onUnauthorized() =
      do_refresh_shouldClearStorage(HttpStatusCode.Unauthorized)

  @Test
  fun refresh_shouldClearStorage_onForbidden() =
      do_refresh_shouldClearStorage(HttpStatusCode.Forbidden)

  private fun do_refresh_shouldClearStorage(statusCode: HttpStatusCode) = runTest {
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .store { expiredAccessToken() }
            .http { respond("", statusCode) }
            .build()
    testClock.advanceBy(2.hours)
    val wasRefreshed = sdk.refreshTokensIfNeeded()
    assertFalse(wasRefreshed)
    verify(testSession).clear()
  }
}

internal class NativeSDKIsAuthenticated : NativeSDKTestBase() {

  @Test
  fun isAuthenticated_shouldReturnFalse_whenSessionIsInvalid() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.store { missingAccessToken() }.build()
    assertFalse(sdk.isAuthenticated())
  }

  @Test
  fun isAuthenticated_shouldReturnTrue_whenSessionIsValid() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.store { validAccessToken() }.build()

    assertTrue(sdk.isAuthenticated())
  }

  @Test
  fun isAuthenticated_shouldAttemptRefresh() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.store { missingAccessToken() }.spy()

    sdk.isAuthenticated()

    verify(sdk).refreshTokensIfNeeded()
  }
}

internal class NativeSDKGetAccessToken : NativeSDKTestBase() {
  @Test
  fun getAccessToken_shouldReturnNull_whenTokenIsInvalid() = runTest {
    val sdk = sdkBuilder.store { missingAccessToken() }.apply { scheduler = testScheduler }.build()

    assertNull(sdk.getAccessToken())
  }

  @Test
  fun getAccessToken_shouldReturnToken_whenTokenIsValid() = runTest {
    val sdk = sdkBuilder.store { validAccessToken() }.apply { scheduler = testScheduler }.build()

    val accessToken = sdk.getAccessToken()
    assertNotNull(accessToken)
    assertEquals(accessToken, sdk.session.profile.value?.tokenResponse?.accessToken)
  }

  @Test
  fun getAccessToken_shouldAttemptRefresh() = runTest {
    val sdk = sdkBuilder.store { missingAccessToken() }.apply { scheduler = testScheduler }.spy()

    sdk.getAccessToken()

    verify(sdk).refreshTokensIfNeeded()
  }
}

internal class NativeSDKIsRedirect : NativeSDKTestBase() {
  @Test
  fun isRedirectExpected_shouldDefaultToFalse() {
    val sdk = sdkBuilder.build()
    val isRedirExpected = sdk.isRedirectExpected()
    assertFalse(isRedirExpected)
  }

  @Test
  fun isRedirectExpected_shouldReturnTrue_whenRedirectIsExpected() {
    val sdk = sdkBuilder.build()
    sdk.loginController = mock<LoginController> { on { isRedirectExpected } doReturn true }
    val isRedirExpected = sdk.isRedirectExpected()
    assertTrue(isRedirExpected)
    verify(sdk.loginController)!!.isRedirectExpected
    verifyNoMoreInteractions(sdk.loginController)
  }
}

internal class NativeSDKCancelFlow : NativeSDKTestBase() {
  @Test
  fun cancelFlow_returnsEarly_whenFlowWasNotStarted() {
    val sdk = sdkBuilder.build()
    assertNull(sdk.loginController)
    sdk.cancelFlow()
  }

  @Test
  fun cancelFlow_resetsInternalState() {
    val sdk = sdkBuilder.build()
    sdk.loginController = mock<LoginController> {}
    sdk.session.setLoginInProgress(true)

    sdk.cancelFlow()
    assertNull(sdk.loginController)
    assertFalse(sdk.session.loginInProgress.value)
  }

  @Test
  fun cancelFlow_shouldReturn_whenFlowWasNotStarted() {
    val sdk = sdkBuilder.build()
    sdk.loginController = null
    sdk.session.setLoginInProgress(true)
    // check indirectly if cleanup was ran
    assertTrue(sdk.session.loginInProgress.value)
  }

  @Test
  fun cancelFlow_shouldInvokeOnError_whenProvided() {
    val sdk = sdkBuilder.build()
    var ex: Throwable? = null
    sdk.loginController =
        mock<LoginController>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS) {
          on { oidcParams.onError } doReturn { error -> run { ex = error } }
        }

    val error = HostedFlowCanceledError()
    sdk.cancelFlow(error = error)
    assertSame(ex, error)
  }
}

internal class NativeSDKTest : NativeSDKTestBase() {

  @Test
  fun publicCtorApi_shouldNotBeBroken() {
    // tests if ctor signature is backward compatible
    val sdk =
        NativeSDK(
            issuer = "test://localhost",
            clientId = "clientId",
            redirectURI = "test://localhost/entry",
            postLogoutURI = "test://localhost/logout",
            storage = TestStorage(),
            mode = SdkMode.Android,
        )
    assertNotNull(sdk)
  }

  @Test
  fun continueFlow_shouldCancelFlow_whenUriIsNull() = runTest {
    val httpService =
        HttpService(
            logging = FakeLogging(),
            MockEngine { throw AssertionError("Test should never invoke HttpClient") },
        )
    val sdk =
        sdkBuilder
            .apply {
              scheduler = testScheduler
              this.httpService = httpService
            }
            .build()
    val loginHandlerService =
        LoginHandlerService(httpService, "http://localhost/", "test-session-id")
    lateinit var error: Error
    val loginController =
        LoginController(
            sdk,
            loginHandlerService,
            OidcParams(
                onSuccess = {},
                onError = { err -> error = err },
            ),
            fallbackHandler = {},
        )
    sdk.loginController = loginController

    sdk.continueFlow(null)

    assertTrue(error is HostedFlowCanceledError)
    assertNull(sdk.loginController)
  }
}

internal class NativeSDKLogout : NativeSDKTestBase() {

  @Test
  fun shouldReturn_whenIdTokenMissing() = runTest {
    val sdk = sdkBuilder.apply { scheduler = testScheduler }.build()
    assertNull(sdk.session.profile.value)
    sdk.logout()
    assertNull(sdk.session.profile.value)
  }

  @Test
  fun shouldPassRequiredParams(): Unit = runTest {
    val tokenResponse = TokenResponseBuilder().createAsTokenResponse()
    val profile = Profile(tokenResponse)

    lateinit var logoutParameters: Parameters
    val mockEngine = MockEngine { request ->
      with(request.url) {
        when {
          fullPath.startsWith("/oauth2/sessions/logout") -> {
            logoutParameters = parameters
            respond(
                content = "",
                status = HttpStatusCode.Found,
                headers =
                    headers {
                      set(HttpHeaders.ContentType, ContentType.Text.Html.contentType)
                      set(HttpHeaders.Location, "test-scheme://my-test-app/logoutCallback")
                    },
            )
          }
          else -> throw AssertionError("Unexpected http call to: ${request.url}")
        }
      }
    }
    val httpService = HttpService(logging = FakeLogging(), mockEngine)
    val oidcHandlerService = spy(OIDCHandlerService(httpService, logging = FakeLogging()))
    val sdk =
        sdkBuilder
            .store { storeProfile(profile) }
            .apply {
              scheduler = testScheduler
              this.oidcHandlerService = oidcHandlerService
            }
            .build()

    sdk.logout()

    assertTrue(
        "Logout should contain id_token_hint param",
        logoutParameters.contains("id_token_hint", tokenResponse.idToken),
    )
    assertTrue(
        "Logout should contain post_logout_redirect_uri",
        logoutParameters.contains(
            "post_logout_redirect_uri",
            "test-scheme://my-test-app/logoutCallback",
        ),
    )
  }
}

internal class NativeSDKLoginTest : NativeSDKTestBase() {
  @Test
  fun login_shouldBuildDefaultParams() = runTest {
    lateinit var requestParams: Parameters

    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(
                captureParams(MockRequestHandleScope::respondFlowRedirect) { params ->
                  requestParams = params
                }
            )
            .http(MockRequestHandleScope::respondInit200)
            .build()
    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = {},
        onError = {},
        fallbackHandler = testFallbackHandler,
        loginParameters = LoginParameters(),
    )
    assertEquals("response_type", requestParams["response_type"], "code")
    assertEquals("client_id", requestParams["client_id"], "test_client")
    assertEquals(
        "redirect_uri",
        requestParams["redirect_uri"],
        "test-scheme://my-test-app/redirUrl",
    )
    assertNotNull(requestParams["state"])
    assertNotNull(requestParams["nonce"])
    assertNotNull(requestParams["code_challenge"])
    assertEquals("code_challenge_method", requestParams["code_challenge_method"], "S256")
    assertEquals("sdk", requestParams["sdk"], SdkMode.Android.value)
    assertEquals("scope", requestParams["scope"], "openid profile")
    assertEquals("Number of parameters", requestParams.entries().count(), 9)
  }

  @Test
  fun login_shouldRespectScopesParam() = runTest {
    lateinit var requestParams: Parameters
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(
                captureParams(MockRequestHandleScope::respondFlowRedirect) { params ->
                  requestParams = params
                }
            )
            .http(MockRequestHandleScope::respondInit200)
            .build()

    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = {},
        onError = {},
        fallbackHandler = testFallbackHandler,
        loginParameters = LoginParameters(scopes = listOf("profile", "openid", "offline")),
    )

    assertEquals(requestParams["scope"], "profile openid offline")
  }

  @Test
  fun login_shouldRespectLoginHintParam() = runTest {
    lateinit var requestParams: Parameters
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(
                captureParams(MockRequestHandleScope::respondFlowRedirect) { params ->
                  requestParams = params
                }
            )
            .http(MockRequestHandleScope::respondInit200)
            .build()

    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = {},
        onError = {},
        fallbackHandler = testFallbackHandler,
        loginParameters = LoginParameters(loginHint = "some_login_hint"),
    )

    assertEquals(requestParams["login_hint"], "some_login_hint")
  }

  @Test
  fun login_shouldRespectAcrValueParam() = runTest {
    lateinit var requestParams: Parameters
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(
                captureParams(MockRequestHandleScope::respondFlowRedirect) { params ->
                  requestParams = params
                }
            )
            .http(MockRequestHandleScope::respondInit200)
            .build()

    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = {},
        onError = {},
        fallbackHandler = testFallbackHandler,
        loginParameters = LoginParameters(acrValue = "some_acr_value"),
    )

    assertEquals(requestParams["acr_values"], "some_acr_value")
  }

  @Test
  fun login_shouldRespectPromptParam() = runTest {
    lateinit var requestParams: Parameters
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(
                captureParams(MockRequestHandleScope::respondFlowRedirect) { params ->
                  requestParams = params
                }
            )
            .http(MockRequestHandleScope::respondInit200)
            .build()

    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = {},
        onError = {},
        fallbackHandler = testFallbackHandler,
        loginParameters = LoginParameters(prompt = "some_prompt"),
    )

    assertEquals(requestParams["prompt"], "some_prompt")
  }

  @Test
  fun login_shouldStartFlow() = runTest {
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http(MockRequestHandleScope::respondInit200)
            .build()

    var onSuccessCalled = false
    var onErrorCalled = false
    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = { onSuccessCalled = true },
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )

    assertFalse(onErrorCalled)
    assertTrue(testSession.loginInProgress.value)
    println(onSuccessCalled)
  }

  @Test
  fun login_shouldInvokeErrorHandler_whenOidcErrorIsReturned() = runTest {
    // session id is null, error and error_description params are set
    // expect to clear session, run cleanup and invoke onError
    val sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondFlowOAuthError)
            .build()

    var onErrorCalled = false
    val testFallbackHandler: FallbackHandler = { uri -> run { println(uri) } }
    sdk.login(
        onSuccess = {},
        onError = { ex ->
          run {
            assertTrue("Is OidcError", ex is OidcError)
            assertEquals((ex as OidcError).error, "test-error")
            assertEquals(ex.errorDescription, "SomeTestErrorDescription")
            onErrorCalled = true
          }
        },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    assertTrue("Error handler called", onErrorCalled)
    assertNull(testStorage.get("profile"))
    assertNull(testSession.profile.value)
    assertFalse(testSession.loginInProgress.value)
    assertNull(sdk.loginController)
  }

  @Test
  fun loginFinalize_shouldInvokeErrorHandler_whenStateDoesNotMatch() = runTest {
    // when state is set
    // expect state to be the same as oidcParams.state
    // invoke onError
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http { request -> respondFlowRedirect(request) }
            .http { request ->
              respondPostLoginRedirect(
                  withCode = sdk.loginController!!.oidcParams.codeVerifier,
                  request = request,
              )
            }
            .build()

    var onErrorCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = {},
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertTrue("Error handler called", onErrorCalled)
    assertNull(sdk.loginController)
    assertFalse(sdk.session.loginInProgress.value)
  }

  @Test
  fun loginFinalize_shouldThrow_whenCodeIsMissing() = runTest {
    // when state is set
    // expect state to be the same as oidcParams.state
    // invoke onError
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply {
              scheduler = testScheduler
              //              this.httpService = httpService
            }
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http { request ->
              respondPostLoginRedirect(
                  withState = sdk.loginController!!.oidcParams.state,
                  request = request,
              )
            }
            .build()

    var onErrorCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = {},
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertTrue("Error handler called", onErrorCalled)
    assertNull(sdk.loginController)
    assertFalse(sdk.session.loginInProgress.value)
  }

  @Test
  fun loginFinalize_shouldPerformTokenExchange() = runTest {
    // expect session to update with new tokenResponse
    // expect cleanup to happen
    // and onSuccess handler called
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http(MockRequestHandleScope::respondInit200)
            .http { request ->
              respondPostLoginRedirect(
                  withState = sdk.loginController!!.oidcParams.state,
                  withCode = sdk.loginController!!.oidcParams.codeVerifier,
                  request = request,
              )
            }
            .http { request ->
              respondTokenExchange200(
                  {
                    nonce = sdk.loginController!!.oidcParams.nonce
                    iss = "https://localhost/"
                  },
                  request,
              )
            }
            .build()

    var onErrorCalled = false
    var onSuccessCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = { onSuccessCalled = true },
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertTrue(onSuccessCalled)
    assertFalse(onErrorCalled)
    assertNotNull(testSession.profile.value)
  }

  @Test
  fun loginFinalize_shouldHandleError_whenNonceDoesNotMatch() = runTest {
    // after code exchange, if none do not match
    // expect onError to be called
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondInit200)
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http { request ->
              respondPostLoginRedirect(
                  withState = sdk.loginController!!.oidcParams.state,
                  withCode = sdk.loginController!!.oidcParams.codeVerifier,
                  request = request,
              )
            }
            .http { request ->
              respondTokenExchange200(
                  { nonce = "definitely-wont-match" },
                  request,
              )
            }
            .build()

    var onErrorCalled = false
    var onSuccessCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = { onSuccessCalled = true },
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertFalse(onSuccessCalled)
    assertTrue(onErrorCalled)
    assertNull(testSession.profile.value)
    assertNull(sdk.loginController)
  }

  @Test
  fun loginFinalize_shouldHandleError_whenIssuerClaimMismatch() = runTest {
    // after code exchange, if iss claim do not match
    // expect onError to be called
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondInit200)
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http { request ->
              respondPostLoginRedirect(
                  withState = sdk.loginController!!.oidcParams.state,
                  withCode = sdk.loginController!!.oidcParams.codeVerifier,
                  request = request,
              )
            }
            .http { request ->
              respondTokenExchange200(
                  {
                    nonce = sdk.loginController!!.oidcParams.nonce
                    iss = "random-domain"
                  },
                  request,
              )
            }
            .build()

    var onErrorCalled = false
    var onSuccessCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = { onSuccessCalled = true },
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertFalse(onSuccessCalled)
    assertTrue(onErrorCalled)
    assertNull(testSession.profile.value)
    assertNull(sdk.loginController)
  }

  @Test
  fun loginFinalize_shouldHandleError_whenAudienceClaimMismatch() = runTest {
    // after code exchange, if aud claim do not match
    // expect onError to be called
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondInit200)
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http { request ->
              respondPostLoginRedirect(
                  withState = sdk.loginController!!.oidcParams.state,
                  withCode = sdk.loginController!!.oidcParams.codeVerifier,
                  request = request,
              )
            }
            .http { request ->
              respondTokenExchange200(
                  {
                    nonce = sdk.loginController!!.oidcParams.nonce
                    iss = "https://localhost/"
                    aud = "[]"
                  },
                  request,
              )
            }
            .build()

    var onErrorCalled = false
    var onSuccessCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = { onSuccessCalled = true },
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertFalse(onSuccessCalled)
    assertTrue(onErrorCalled)
    assertNull(testSession.profile.value)
    assertNull(sdk.loginController)
  }

  @Test
  fun loginFinalize_shouldCatchExceptions_whenTokenExchangeThrows() = runTest {
    // after code exchange, if exception is thrown
    // expect onError to be called with UnknownError
    lateinit var sdk: NativeSDK
    sdk =
        sdkBuilder
            .apply { scheduler = testScheduler }
            .http(MockRequestHandleScope::respondFlowRedirect)
            .http { request ->
              respondPostLoginRedirect(
                  withState = sdk.loginController!!.oidcParams.state,
                  withCode = sdk.loginController!!.oidcParams.codeVerifier,
                  request = request,
              )
            }
            .http { request ->
              respondTokenExchangeException(
                  tokenResponseBuilder = {
                    TokenResponseBuilder(
                            nonce = sdk.loginController!!.oidcParams.nonce,
                        )
                        .buildAsString()
                  },
                  request,
              )
            }
            .build()

    var onErrorCalled = false
    var onSuccessCalled = false
    val testFallbackHandler: FallbackHandler = {}
    sdk.login(
        onSuccess = { onSuccessCalled = true },
        onError = { onErrorCalled = true },
        fallbackHandler = testFallbackHandler,
        loginParameters = null,
    )
    sdk.continueFlow("https://localhost/provider/oauth2/v1/finish?state=1234")
    assertFalse(onSuccessCalled)
    assertTrue(onErrorCalled)
    assertNull(testSession.profile.value)
    assertNull(sdk.loginController)
  }

  @Test
  fun screen_canBeDeserialized() {
    val json = Json {
      ignoreUnknownKeys = true
      explicitNulls = false
    }
    val screen = json.decodeFromString<Screen>(fakeInitResponsePayload)
    assertNotNull(screen)
  }
}
