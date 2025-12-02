package com.strivacity.android.native_sdk.service

import com.strivacity.android.native_sdk.Logging
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.accept
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import java.util.Locale
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

internal class HttpService(
    private val logging: Logging,
    clientEngine: HttpClientEngine = Android.create(),
) {
  private val client =
      HttpClient(clientEngine) {
        install(ContentNegotiation) {
          json(
              Json {
                ignoreUnknownKeys = true
                explicitNulls = false
              }
          )
        }
        install(HttpCookies)
      }

  suspend fun get(
      url: Url,
      acceptHeader: ContentType = ContentType.Application.Json,
  ): HttpResponse {
    logging.debug("HTTP GET: ${url.encodedPath}")
    return client.get(url) { accept(acceptHeader) }
  }

  suspend fun post(
      url: Url,
      session: String,
      body: JsonObject? = null,
      acceptHeader: ContentType = ContentType.Application.Json,
  ): HttpResponse {
    logging.debug("HTTP POST: ${url.encodedPath}")
    return client.post(url) {
      accept(acceptHeader)
      contentType(ContentType.Application.Json)
      setBody(body)
      headers.apply {
        append("Authorization", "Bearer $session")
        append("Accept-Language", Locale.getDefault().language)
      }
    }
  }

  suspend fun postForm(
      url: String,
      body: Parameters,
      acceptHeader: ContentType = ContentType.Application.Json,
  ): HttpResponse {
    logging.debug("HTTP POST: ${Url(url).encodedPath}")
    return client.submitForm(url = url, formParameters = body) { accept(acceptHeader) }
  }
}
