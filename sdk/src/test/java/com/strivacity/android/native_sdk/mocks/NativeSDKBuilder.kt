package com.strivacity.android.native_sdk.mocks

import FakeLogging
import com.strivacity.android.native_sdk.NativeSDK
import com.strivacity.android.native_sdk.Session
import com.strivacity.android.native_sdk.Storage
import com.strivacity.android.native_sdk.service.HttpService
import com.strivacity.android.native_sdk.service.OIDCHandlerService
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockEngineConfig
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.Parameters
import java.time.Clock
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler

internal class NativeSDKBuilder {

  constructor(block: NativeSDKBuilder.() -> Unit) {
    this.apply(block)
  }

  var storage: Storage? = null
  var clock: Clock = Clock.systemUTC()
  var scheduler: TestCoroutineScheduler? = null
  var httpService: HttpService? = null
  var oidcHandlerService: OIDCHandlerService? = null
  var session: Session? = null

  private val httpHandlers: MutableList<ChainedMockRequestHandler> = mutableListOf()

  fun build(): NativeSDK {
    assert(storage != null || session != null) { "Either storage or session must be provided" }
    val dispatchers = TestSDKDispatcher(StandardTestDispatcher(scheduler))
    lateinit var httpService: HttpService
    val logging = FakeLogging()
    if (this.httpService == null && httpHandlers.isNotEmpty()) {
      val engineConfig = MockEngineConfig()
      // such a handler that iterates over defined handlers and invokes the next until one
      // returns with a response
      // if none do and Exception will be throw
      engineConfig.addHandler { request ->
        run {
          for (handler in httpHandlers) {
            val response = handler(request)
            if (response != null) {
              println(response)
              return@run response
            }
          }
          throw Exception("Handler not defined for request: $request")
        }
      }
      httpService = HttpService(logging = logging, MockEngine(engineConfig))
    } else {
      httpService = this.httpService ?: HttpService(logging = logging)
    }
    val sdk =
        NativeSDK(
            issuer = "https://localhost",
            clientId = "test_client",
            redirectURI = "test-scheme://my-test-app/redirUrl",
            postLogoutURI = "test-scheme://my-test-app/logoutCallback",
            dispatchers = dispatchers,
            clock = clock,
            session = session ?: Session(storage!!),
            logging = logging,
            httpService = httpService,
            oidcHandlerService = oidcHandlerService ?: OIDCHandlerService(httpService, logging),
        )
    sdk.session.load()
    return sdk
  }

  fun spy(): NativeSDK {
    return org.mockito.kotlin.spy(build())
  }

  fun http(handler: ChainedMockRequestHandler): NativeSDKBuilder {
    httpHandlers.add(handler)
    return this
  }

  fun store(block: Storage.() -> Unit): NativeSDKBuilder {
    assert(storage != null) { "Storage had not been set" }
    storage?.block()
    return this
  }
}

fun captureParams(
    handler: ChainedMockRequestHandler,
    withParams: (Parameters) -> Unit,
): ChainedMockRequestHandler {
  return fun MockRequestHandleScope.(request: HttpRequestData): HttpResponseData? {
    val response = handler(request)
    if (response != null) {
      withParams(request.url.parameters)
    }
    return response
  }
}

typealias ChainedMockRequestHandler =
    MockRequestHandleScope.(request: HttpRequestData) -> HttpResponseData?
