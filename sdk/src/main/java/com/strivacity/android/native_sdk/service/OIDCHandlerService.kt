package com.strivacity.android.native_sdk.service

import com.strivacity.android.native_sdk.Error
import com.strivacity.android.native_sdk.HttpError
import com.strivacity.android.native_sdk.Logging
import com.strivacity.android.native_sdk.util.OIDCParamGenerator
import io.ktor.client.call.body
import io.ktor.client.statement.request
import io.ktor.http.ContentType
import io.ktor.http.Parameters
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.parameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal class OIDCHandlerService(
    private val httpService: HttpService,
    private val logging: Logging,
) {

  suspend fun handleCall(url: Url): Parameters {
    val location: Url
    if (url.protocol.name == "https") {
      val response = httpService.get(url, acceptHeader = ContentType.Text.Html)
      if (
          response.status.value == 200 &&
              response.request.url.host == url.host &&
              response.request.url.encodedPath == "/oauth2/error"
      ) {
        return response.request.url.parameters
      }

      if (response.status.value != 302 && response.status.value != 303) {
        throw HttpError(statusCode = response.status.value)
      }

      val locationHeader =
          response.headers["location"] ?: throw IllegalStateException("No location header found")
      location = URLBuilder(locationHeader).build()
    } else {
      location = url
    }

    return location.parameters
  }

  suspend fun tokenExchange(url: String, tokenExchangeParams: TokenExchangeParams): TokenResponse {
    logging.debug("Attempting token exchange")
    val httpResponse = httpService.postForm(url, tokenExchangeParams.toParameters())

    if (httpResponse.status.value != 200) {
      logging.info("Token exchange failed with status code ${httpResponse.status.value}")
      throw HttpError(statusCode = httpResponse.status.value)
    }
    logging.info("Token exchange succeeded")
    return httpResponse.body()
  }

  suspend fun tokenRefresh(url: String, tokenRefreshParams: TokenRefreshParams): TokenResponse {
    logging.debug("Attempting token refresh")
    val httpResponse = httpService.postForm(url, tokenRefreshParams.toParameters())

    if (httpResponse.status.value != 200) {
      logging.info("Token refresh failed with status code ${httpResponse.status.value}")
      throw HttpError(statusCode = httpResponse.status.value)
    }
    logging.info("Token refresh succeeded")
    return httpResponse.body()
  }
}

internal class OidcParams(
    val onSuccess: () -> Unit,
    val onError: (Error) -> Unit,
) {
  val codeVerifier: String = OIDCParamGenerator.generateRandomString(32)
  val codeChallenge: String = OIDCParamGenerator.generateCodeChallenge(codeVerifier)
  val state: String = OIDCParamGenerator.generateRandomString(16)
  val nonce: String = OIDCParamGenerator.generateRandomString(16)
}

internal data class TokenExchangeParams(
    val code: String,
    val codeVerifier: String,
    val redirectURI: String,
    val clientId: String,
    val nonce: String = OIDCParamGenerator.generateRandomString(16),
) {
  fun toParameters(): Parameters {
    return parameters {
      append("grant_type", "authorization_code")
      append("code", code)
      append("redirect_uri", redirectURI)
      append("client_id", clientId)
      append("code_verifier", codeVerifier)
      append("nonce", nonce)
    }
  }
}

internal data class TokenRefreshParams(val refreshToken: String, val clientId: String) {
  fun toParameters(): Parameters {
    return parameters {
      append("grant_type", "refresh_token")
      append("refresh_token", refreshToken)
      append("client_id", clientId)
    }
  }
}

@Serializable
internal data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("id_token") val idToken: String,
    @SerialName("expires_in") val expiresIn: Int,
    @SerialName("refresh_token") val refreshToken: String?,
)
