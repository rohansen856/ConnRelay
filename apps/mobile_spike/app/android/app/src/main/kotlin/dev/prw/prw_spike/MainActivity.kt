package dev.prw.prw_spike

import android.content.Intent
import android.os.Bundle
import android.util.Log
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * Spike host activity. The Flutter UI calls the Go probe over a MethodChannel;
 * for unattended runs the same actions can be triggered with adb:
 *   adb shell am start -n dev.prw.prw_spike/.MainActivity --es action run \
 *     --es server http://HOST:PORT --es lab_id X --es mode auto --ez force_relay false
 * Results are logged under the PRWSPIKE tag.
 */
class MainActivity : FlutterActivity() {
    private val pool = Executors.newSingleThreadExecutor()
    private val signer by lazy { KeystoreSigner() }
    private var channel: MethodChannel? = null

    override fun configureFlutterEngine(engine: FlutterEngine) {
        super.configureFlutterEngine(engine)
        channel = MethodChannel(engine.dartExecutor.binaryMessenger, "prw/probe").apply {
            setMethodCallHandler { call, result ->
                when (call.method) {
                    "version" -> result.success(dev.prw.spike.probe.Probe.version())
                    "checkKey" -> pool.execute { reply(result, checkKey()) }
                    "run" -> pool.execute {
                        reply(result, run(
                            call.argument<String>("server")!!, call.argument<String>("labId") ?: "default",
                            call.argument<String>("mode") ?: "auto", call.argument<Boolean>("forceRelay") ?: false,
                            call.argument<Int>("bytes") ?: (1 shl 20), call.argument<Boolean>("hardwareKey") ?: true,
                        ))
                    }
                    else -> result.notImplemented()
                }
            }
        }
    }

    private fun reply(r: MethodChannel.Result, s: String) = runOnUiThread { r.success(s) }

    private fun checkKey(): String {
        val t0 = System.nanoTime()
        val go = JSONObject(dev.prw.spike.probe.Probe.checkSigner(signer))
        go.put("keystore", JSONObject(signer.describe()))
        go.put("total_ms", (System.nanoTime() - t0) / 1_000_000)
        return go.toString()
    }

    private fun run(server: String, labId: String, mode: String, forceRelay: Boolean, bytes: Int, hw: Boolean): String =
        dev.prw.spike.probe.Probe.run(server, labId, mode, forceRelay, bytes.toLong(), if (hw) signer else null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(i: Intent?) {
        val action = i?.getStringExtra("action") ?: return
        i.removeExtra("action")
        pool.execute {
            val out = when (action) {
                "version" -> dev.prw.spike.probe.Probe.version()
                "check_key" -> checkKey()
                "run" -> run(
                    i.getStringExtra("server") ?: "", i.getStringExtra("lab_id") ?: "default",
                    i.getStringExtra("mode") ?: "auto", i.getBooleanExtra("force_relay", false),
                    i.getIntExtra("bytes", 1 shl 20), i.getBooleanExtra("hardware_key", true),
                )
                else -> "unknown action $action"
            }
            Log.i("PRWSPIKE", "$action ${i.getStringExtra("tag") ?: ""} RESULT $out")
            runOnUiThread { channel?.invokeMethod("log", "$action: $out") }
        }
    }
}
