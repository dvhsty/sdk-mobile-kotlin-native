package com.strivacity.android.native_sdk

import android.content.Context
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.net.toUri
import com.strivacity.android.native_sdk.render.FallbackHandler
import com.strivacity.android.native_sdk.render.LoginController
import com.strivacity.android.native_sdk.service.HttpService
import com.strivacity.android.native_sdk.service.LoginHandlerService
import com.strivacity.android.native_sdk.service.OIDCHandlerService
import com.strivacity.android.native_sdk.service.OidcParams
import com.strivacity.android.native_sdk.service.TokenExchangeParams
import com.strivacity.android.native_sdk.service.TokenRefreshParams
import io.ktor.http.Parameters
import io.ktor.http.URLBuilder
import io.ktor.http.path
import java.lang.ref.WeakReference
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

class NativeSDK
internal constructor(
    private val issuer: String,
    private val clientId: String,
    private val redirectURI: String,
    private val postLogoutURI: String,
    val session: Session,
    private val mode: SdkMode = SdkMode.Android,
    private val dispatchers: SDKDispatchers = DefaultSDKDispatchers,
    private val clock: Clock = Clock.systemUTC(),
    private val logging: Logging = DefaultLogging(),
    private val httpService: HttpService = HttpService(logging = logging),
    private val oidcHandlerService: OIDCHandlerService =
        OIDCHandlerService(httpService = httpService, logging = logging),
) {

  constructor(
      issuer: String,
      clientId: String,
      redirectURI: String,
      postLogoutURI: String,
      storage: Storage,
      mode: SdkMode = SdkMode.Android,
      logging: Logging = DefaultLogging(),
  ) : this(
      issuer = issuer,
      clientId = clientId,
      redirectURI = redirectURI,
      postLogoutURI = postLogoutURI,
      session = Session(storage),
      mode = mode,
      logging = logging,
  )

  var loginController: LoginController? = null

  internal val tokenRefreshMutex = Mutex()

  suspend fun initializeSession() =
      withContext(dispatchers.IO) {
        session.load()
        refreshTokensIfNeeded()
      }

  suspend fun login(
      fallbackHandler: FallbackHandler,
      onSuccess: () -> Unit,
      onError: (Error) -> Unit,
      loginParameters: LoginParameters? = null,
  ) =
      withContext(dispatchers.IO) {
        val oidcParams = OidcParams(onSuccess, onError)

        val url =
            URLBuilder(issuer)
                .apply {
                  path("/oauth2/auth")
                  parameters.append("response_type", "code")
                  parameters.append("client_id", clientId)
                  parameters.append("redirect_uri", redirectURI)
                  parameters.append("state", oidcParams.state)
                  parameters.append("nonce", oidcParams.nonce)
                  parameters.append("code_challenge", oidcParams.codeChallenge)
                  parameters.append("code_challenge_method", "S256")
                  parameters.append("sdk", mode.value)

                  val scopes = loginParameters?.scopes ?: listOf("openid", "profile")
                  parameters.append("scope", scopes.joinToString(separator = " "))

                  if (loginParameters?.loginHint != null) {
                    parameters.append("login_hint", loginParameters.loginHint)
                  }

                  if (loginParameters?.acrValue != null) {
                    parameters.append("acr_values", loginParameters.acrValue)
                  }

                  if (loginParameters?.prompt != null) {
                    parameters.append("prompt", loginParameters.prompt)
                  }
                }
                .build()

        try {
          val parameters = oidcHandlerService.handleCall(url)

          val sessionId = parameters["session_id"]
          if (sessionId == null) {
            continueFlow(oidcParams, parameters)
            return@withContext
          }

          val loginHandlerService = LoginHandlerService(httpService, issuer, sessionId)
          val loginController =
              LoginController(this@NativeSDK, loginHandlerService, oidcParams, fallbackHandler)

          loginController.initialize()
          this@NativeSDK.loginController = loginController

          session.setLoginInProgress(true)
        } catch (e: Exception) {
          onError(UnknownError(e))
        }
      }

  @Deprecated("Use login with fallbackHandler instead. This call will be removed in future version")
  suspend fun login(
      context: WeakReference<Context>,
      onSuccess: () -> Unit,
      onError: (Error) -> Unit,
      loginParameters: LoginParameters? = null,
  ) {
    val customTabsHandler: FallbackHandler = { uri ->
      run {
        val ctx = context.get() ?: throw IllegalStateException("Context is no longer available")

        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.launchUrl(ctx, uri.toUri())
      }
    }
    return login(
        fallbackHandler = customTabsHandler,
        onSuccess = onSuccess,
        onError = onError,
        loginParameters = loginParameters,
    )
  }

  suspend fun isAuthenticated(): Boolean =
      withContext(dispatchers.IO) {
        refreshTokensIfNeeded()
        session.profile.value != null
      }

  suspend fun getAccessToken(): String? =
      withContext(dispatchers.IO) {
        refreshTokensIfNeeded()
        val profile = session.profile.value ?: return@withContext null
        return@withContext profile.tokenResponse.accessToken
      }

  fun isRedirectExpected(): Boolean {
    return loginController?.isRedirectExpected ?: false
  }

  suspend fun continueFlow(uri: String?) =
      withContext(dispatchers.IO) {
        val oidcParams = loginController?.oidcParams ?: return@withContext

        if (uri == null) {
          cancelFlow(HostedFlowCanceledError())
          return@withContext
        }

        try {
          val parameters = oidcHandlerService.handleCall(URLBuilder(uri).build())
          continueFlow(oidcParams, parameters)
        } catch (e: Exception) {
          cleanup()
          oidcParams.onError(UnknownError(e))
        }
      }

  fun cancelFlow(error: Error? = null) {
    val loginController = loginController ?: return

    cleanup()
    if (error != null) {
      loginController.oidcParams.onError(error)
    }
  }

  suspend fun logout(): Unit =
      withContext(dispatchers.IO) {
        val idToken = session.profile.value?.tokenResponse?.idToken

        session.clear()

        if (idToken == null) {
          return@withContext
        }

        val url =
            URLBuilder(issuer)
                .apply {
                  path("/oauth2/sessions/logout")
                  parameters.append("id_token_hint", idToken)
                  parameters.append("post_logout_redirect_uri", postLogoutURI)
                }
                .build()

        try {
          oidcHandlerService.handleCall(url)
        } catch (e: Error) {
          logging.debug("Failed to call logout endpoint", e)
        }
      }

  private suspend fun continueFlow(oidcParams: OidcParams, parameters: Parameters) {
    val sessionId = parameters["session_id"]
    if (sessionId != null) {
      try {
        loginController?.initialize()
      } catch (e: Exception) {
        cleanup()
        oidcParams.onError(UnknownError(e))
      }

      return
    }

    val error = parameters["error"]
    val errorDescription = parameters["error_description"]
    if (error != null && errorDescription != null) {
      session.clear()
      cleanup()
      oidcParams.onError(OidcError(error, errorDescription))
      return
    }

    val state = parameters["state"]
    if (state != oidcParams.state) {
      cleanup()
      oidcParams.onError(InvalidCallbackError("State param did not matched expected value"))
      return
    }

    val code = parameters["code"] ?: throw IllegalStateException("Code missing from response")

    try {
      val tokenResponse =
          oidcHandlerService.tokenExchange(
              URLBuilder(issuer).apply { path("/oauth2/token") }.toString(),
              TokenExchangeParams(code, oidcParams.codeVerifier, redirectURI, clientId),
          )

      val claims = extractClaims(tokenResponse)
      val responseNonce = claims["nonce"] as? String
      if (responseNonce == null || oidcParams.nonce != responseNonce) {
        cleanup()
        oidcParams.onError(InvalidCallbackError("Nonce param did not matched expected value"))
        return
      }

      val responseIssuer = claims["iss"] as? String
      val normalizedIssuer = if (issuer.endsWith("/")) issuer else "$issuer/"
      if (responseIssuer == null || normalizedIssuer != responseIssuer) {
        cleanup()
        oidcParams.onError(InvalidCallbackError("Issuer param did not matched expected value"))
        return
      }

      val responseAudience = claims["aud"] as? List<*>
      if (responseAudience == null || !responseAudience.contains(clientId)) {
        cleanup()
        oidcParams.onError(InvalidCallbackError("Audience param did not matched expected value"))
        return
      }

      session.update(tokenResponse)

      cleanup()
      oidcParams.onSuccess()
    } catch (e: Exception) {
      cleanup()
      oidcParams.onError(UnknownError(e))
    }
  }

  /**
   * Check if access token should be refreshed and if so, attempt to do so
   *
   * @return Boolean `true` if access token was refreshed, `false` otherwise
   */
  internal suspend fun refreshTokensIfNeeded(): Boolean =
      tokenRefreshMutex.withLock {
        val accessTokenExpiresAt = session.profile.value?.accessTokenExpiresAt
        if (
            accessTokenExpiresAt == null ||
                accessTokenExpiresAt.isAfter(Instant.now(clock).plus(1, ChronoUnit.MINUTES))
        ) {
          return false
        }

        val refreshToken = session.profile.value?.tokenResponse?.refreshToken
        if (refreshToken == null) {
          session.clear()
          return false
        }

        try {
          val tokenResponse =
              oidcHandlerService.tokenRefresh(
                  URLBuilder(issuer).apply { path("/oauth2/token") }.toString(),
                  TokenRefreshParams(refreshToken, clientId),
              )

          session.update(tokenResponse)
          return true
        } catch (e: HttpError) {
          if (e.statusCode in listOf(401, 403)) {
            session.clear()
            return false
          }
          throw e
        }
      }

  private fun cleanup() {
    session.setLoginInProgress(false)
    loginController = null
  }
}

data class LoginParameters(
    val prompt: String? = null,
    val loginHint: String? = null,
    val acrValue: String? = null,
    val scopes: List<String>? = null,
)

enum class SdkMode(val value: String) {
  Android("android"),
  AndroidMinimal("android-minimal"),
}
