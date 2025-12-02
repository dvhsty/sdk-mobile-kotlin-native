package com.strivacity.android.native_sdk

import android.util.Log

/**
 * Logging interface used by the SDK.
 *
 * **Thread safety:** Implementations of this interface must be thread-safe. Methods will be called
 * concurrently from multiple threads.
 *
 * **Exception handling:** Implementations should handle exceptions internally and not throw from
 * these methods, as that could disrupt the SDK's operation.
 */
interface Logging {
  fun debug(body: String, exception: Throwable? = null)

  fun info(body: String, exception: Throwable? = null)

  fun warn(body: String, exception: Throwable? = null)

  fun error(body: String, exception: Throwable? = null)
}

/**
 * Default implementation of the Logging interface that logs to Android's Logcat.
 *
 * Logcat is thread-safe, so this implementation is also thread-safe.
 */
class DefaultLogging : Logging {
  override fun debug(body: String, exception: Throwable?) {
    Log.d("NativeSDK", body, exception)
  }

  override fun info(body: String, exception: Throwable?) {
    Log.i("NativeSDK", body, exception)
  }

  override fun warn(body: String, exception: Throwable?) {
    Log.w("NativeSDK", body, exception)
  }

  override fun error(body: String, exception: Throwable?) {
    Log.e("NativeSDK", body, exception)
  }
}
