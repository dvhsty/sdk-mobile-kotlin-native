//import android.util.Log
//import androidx.annotation.VisibleForTesting
//import com.strivacity.android.native_sdk.LogLevel
//
//
///** Level of logging */
//enum class LogLevel() : Comparable<LogLevel> {
//  DEBUG,
//  INFO,
//  WARN,
//  ERROR,
//}
//internal class LoggingFat(private val logReceiver: LogReceiver = DefaultLogReceiver()) {
//
//  private val emitLock = Any()
//
//  private fun emit(level: LogLevel, body: String, exception: Throwable? = null) {
//    synchronized(emitLock) { logReceiver.notify(level, body, exception) }
//  }
//
//  companion object {
//    @VisibleForTesting @Volatile internal var instance: LoggingFat? = null
//    private val initLock = Any()
//
//    internal fun init(logReceiver: LogReceiver): LoggingFat {
//      instance?.let {
//        return it
//      } // Fast path without lock
//
//      return synchronized(initLock) { instance ?: LoggingFat(logReceiver).also { instance = it } }
//    }
//
//    fun debug(body: String, exception: Throwable? = null) {
//      instance?.emit(LogLevel.DEBUG, body, exception)
//    }
//
//    fun info(body: String, exception: Throwable? = null) {
//      instance?.emit(LogLevel.INFO, body, exception)
//    }
//
//    fun warn(body: String, exception: Throwable? = null) {
//      instance?.emit(LogLevel.WARN, body, exception)
//    }
//
//    fun error(body: String, exception: Throwable? = null) {
//      instance?.emit(LogLevel.ERROR, body, exception)
//    }
//  }
//}
//
///**
// * Abstract base class for receiving log messages from the SDK.
// *
// * **Thread Safety Guarantee:** The SDK serializes all calls to [onRecord], ensuring it will never
// * be invoked concurrently. Multiple threads logging simultaneously will be queued and [onRecord]
// * will execute sequentially.
// *
// * **State Management:** If your implementation maintains internal state (fields, properties), you
// * MUST synchronize access to that state when reading/writing it from methods other than [onRecord].
// * The SDK only protects calls to [onRecord] itself, not your other methods.
// *
// * Example of **UNSAFE** code:
// * ```
// * class MyReceiver : LogReceiver() {
// *   private val logs = mutableListOf<String>()
// *   override fun onRecord(...) { logs.add(body) }  // Protected by SDK
// *   fun getLogs() = logs.toList()  // ❌ NOT protected - race condition!
// * }
// * ```
// *
// * Example of **SAFE** code:
// * ```
// * class MyReceiver : LogReceiver() {
// *   private val logs = mutableListOf<String>()
// *   private val lock = Any()
// *   override fun onRecord(...) { synchronized(lock) { logs.add(body) } }
// *   fun getLogs() = synchronized(lock) { logs.toList() }  // ✅ Protected
// * }
// * ```
// *
// * **Performance Note:** Avoid blocking operations in [onRecord] as this delays all subsequent logs.
// *
// * @param minLevel Minimum log level to record. Messages below this level are filtered out.
// */
//abstract class LogReceiver(private val minLevel: LogLevel = LogLevel.DEBUG) {
//
//  internal fun notify(level: LogLevel, body: String, exception: Throwable? = null) {
//    if (level >= minLevel) {
//      onRecord(level, body, exception)
//    }
//  }
//
//  abstract fun onRecord(level: LogLevel, body: String, exception: Throwable? = null)
//}
//
//internal class DefaultLogReceiver : LogReceiver() {
//
//
//
//  override fun onRecord(level: LogLevel, body: String, exception: Throwable?) {
//    when (level) {
//      LogLevel.DEBUG -> Log.d("NativeSDK", body, exception)
//      LogLevel.INFO -> Log.i("NativeSDK", body, exception)
//      LogLevel.WARN -> Log.w("NativeSDK", body, exception)
//      LogLevel.ERROR -> Log.e("NativeSDK", body, exception)
//    }
//  }
//}
