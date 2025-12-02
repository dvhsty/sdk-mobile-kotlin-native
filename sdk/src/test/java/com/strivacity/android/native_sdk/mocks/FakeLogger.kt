import com.strivacity.android.native_sdk.Logging

internal class FakeLogging : Logging {
  private val lock = Any()

  private val logs = StringBuilder()

  val logMessages: String
    get() = synchronized(lock) { logs.toString() }

  override fun debug(body: String, exception: Throwable?) = logMessage("DEBUG", body, exception)

  override fun info(body: String, exception: Throwable?) = logMessage("INFO", body, exception)

  override fun warn(body: String, exception: Throwable?) = logMessage("WARN", body, exception)

  override fun error(body: String, exception: Throwable?) = logMessage("ERROR", body, exception)

  private fun logMessage(
      level: String,
      body: String,
      exception: Throwable?,
  ) {
    synchronized(lock) {
      logs.append("$level: $body")
      if (exception != null) {
        logs.append(" EXCEPTION: ${exception.message}")
      }
      logs.append("\n")
    }
  }
}
