package dev.connrelay.app

import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors

/**
 * Bridges Flutter to the device key and the Go core (dev.connrelay.core.mobile).
 * Go calls block (network, attestation), so they run on a worker thread;
 * results and events are posted back to the main thread.
 */
class MainActivity : FlutterActivity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val io = Executors.newSingleThreadExecutor() // input/resize must not queue behind connect
    private val main = Handler(Looper.getMainLooper())
    private val key by lazy { DeviceKey() }
    private var session: dev.connrelay.core.mobile.Session? = null
    private var sink: EventChannel.EventSink? = null

    private val events = object : dev.connrelay.core.mobile.Events {
        override fun onOutput(stream: Long, data: ByteArray) {
            main.post { sink?.success(mapOf("kind" to "output", "stream" to stream.toInt(), "data" to data)) }
        }

        override fun onEvent(kind: String, detail: String) {
            main.post { sink?.success(mapOf("kind" to kind, "detail" to detail)) }
        }
    }

    override fun configureFlutterEngine(engine: FlutterEngine) {
        super.configureFlutterEngine(engine)
        EventChannel(engine.dartExecutor.binaryMessenger, "connrelay/core/events").setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
                sink = events
            }

            override fun onCancel(arguments: Any?) {
                sink = null
            }
        })
        MethodChannel(engine.dartExecutor.binaryMessenger, "connrelay/core").setMethodCallHandler { call, result ->
            val pool = if (call.method == "input" || call.method == "resize") io else worker
            pool.execute {
                try {
                    val value = handle(call)
                    main.post { result.success(value) }
                } catch (e: Exception) {
                    // Go errors carry stable codes (e.g. access_grant_missing).
                    val code = (e.message ?: "error").lineSequence().first().take(64)
                    main.post { result.error(code, e.message, null) }
                }
            }
        }
    }

    private fun current(): dev.connrelay.core.mobile.Session = session ?: throw IllegalStateException("not_connected")

    private fun handle(call: MethodCall): Any? = when (call.method) {
        "publicKey" -> key.publicKeySPKI()
        "fingerprint" -> dev.connrelay.core.mobile.Mobile.fingerprint(call.argument<ByteArray>("spki"))
        "signPoP" -> dev.connrelay.core.mobile.Mobile.signPoP(
            call.argument<String>("purpose"), call.argument<String>("nonce"),
            call.argument<String>("spkiFp") ?: "", call.argument<String>("deviceId") ?: "", key,
        )
        "connect" -> {
            session?.close()
            session = null
            val s = dev.connrelay.core.mobile.Mobile.connect(
                call.argument<String>("api"), call.argument<String>("accessToken"), call.argument<String>("deviceId"),
                call.argument<String>("hostId"), call.argument<String>("pinnedFp"), call.argument<String>("mode") ?: "auto",
                30000L, key, events,
            )
            session = s
            s.path()
        }
        "open" -> current().open(call.argument<Int>("cols")!!.toLong(), call.argument<Int>("rows")!!.toLong())
        "attach" -> current().attach(call.argument<String>("id"), call.argument<Int>("cols")!!.toLong(), call.argument<Int>("rows")!!.toLong())
        "list" -> current().list()
        "input" -> { current().input(call.argument<Int>("stream")!!.toLong(), call.argument<ByteArray>("data")); null }
        "resize" -> { current().resize(call.argument<Int>("stream")!!.toLong(), call.argument<Int>("cols")!!.toLong(), call.argument<Int>("rows")!!.toLong()); null }
        "detach" -> { current().detach(call.argument<Int>("stream")!!.toLong()); null }
        "terminate" -> { current().terminate(call.argument<String>("id")); null }
        "close" -> { session?.close(); session = null; null }
        else -> throw IllegalArgumentException("unknown_method")
    }

    override fun onDestroy() {
        session?.close()
        session = null
        super.onDestroy()
    }
}
