package com.quishinginspector.app

import android.content.Context
import android.graphics.Color
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.registerForActivityResult
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: android.content.SharedPreferences
    private lateinit var urlInput: EditText
    private lateinit var verdictText: TextView
    private lateinit var scoreText: TextView
    private lateinit var summaryText: TextView
    private lateinit var payloadText: TextView
    private lateinit var indicatorsText: TextView

    // Longer timeout: dynamic sandbox + Tor can take 10-20s.
    private val client = OkHttpClient.Builder()
        .callTimeout(40, TimeUnit.SECONDS)
        .readTimeout(40, TimeUnit.SECONDS)
        .build()

    // Launches the ZXing scanner and receives the decoded string.
    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            analyze(result.contents)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences("qi", Context.MODE_PRIVATE)
        urlInput = findViewById(R.id.urlInput)
        verdictText = findViewById(R.id.verdictText)
        scoreText = findViewById(R.id.scoreText)
        summaryText = findViewById(R.id.summaryText)
        payloadText = findViewById(R.id.payloadText)
        indicatorsText = findViewById(R.id.indicatorsText)

        urlInput.setText(prefs.getString("backend_url", ""))

        findViewById<Button>(R.id.saveBtn).setOnClickListener {
            val u = urlInput.text.toString().trim().trimEnd('/')
            prefs.edit().putString("backend_url", u).apply()
            Toast.makeText(this, "Backend URL saved", Toast.LENGTH_SHORT).show()
        }

        findViewById<Button>(R.id.scanBtn).setOnClickListener {
            val options = ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Point the camera at a QR code")
                setBeepEnabled(false)
                setOrientationLocked(true)
            }
            scanLauncher.launch(options)
        }
    }

    private fun analyze(payload: String) {
        val backend = (prefs.getString("backend_url", "") ?: "").trimEnd('/')
        if (backend.isEmpty()) {
            Toast.makeText(this, "Set the backend URL first", Toast.LENGTH_LONG).show()
            return
        }

        payloadText.text = payload
        verdictText.text = "Analysing…"
        verdictText.setTextColor(Color.parseColor("#94A3B8"))
        scoreText.text = ""
        summaryText.text = ""
        indicatorsText.text = ""

        val json = JSONObject().apply {
            put("payload", payload)
            put("perform_network_checks", true)
        }
        val body = json.toString().toRequestBody("application/json".toMediaType())
        val request = Request.Builder()
            .url("$backend/api/scan-payload")
            .post(body)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    verdictText.text = "SCAN FAILED"
                    verdictText.setTextColor(Color.parseColor("#F59E0B"))
                    summaryText.text = "Could not reach the backend. Check the URL and that the tunnel is running."
                }
            }

            override fun onResponse(call: Call, response: Response) {
                val text = response.body?.string() ?: ""
                runOnUiThread { render(text) }
            }
        })
    }

    private fun render(jsonStr: String) {
        try {
            val root = JSONObject(jsonStr)
            val details = root.optJSONObject("details")
            val risk = details?.optJSONObject("risk_assessment")

            if (!root.optBoolean("success", false) || risk == null) {
                verdictText.text = "SCAN FAILED"
                verdictText.setTextColor(Color.parseColor("#F59E0B"))
                summaryText.text = root.optString("message",
                    "Could not analyse this code — do not assume it is safe.")
                return
            }

            val verdict = risk.optString("verdict", "safe").lowercase()
            val score = risk.optInt("score", 0)
            val color = when (verdict) {
                "dangerous" -> "#EF4444"
                "caution" -> "#F59E0B"
                else -> "#10B981"
            }

            verdictText.text = verdict.uppercase()
            verdictText.setTextColor(Color.parseColor(color))
            scoreText.text = "$score / 100"
            summaryText.text = risk.optString("summary", "")

            val breakdown = risk.optJSONArray("breakdown")
            val sb = StringBuilder()
            if (breakdown != null) {
                for (i in 0 until breakdown.length()) {
                    val item = breakdown.getJSONObject(i)
                    sb.append("• ")
                        .append(item.optString("indicator"))
                        .append("  (+").append(item.optInt("points")).append(")\n\n")
                }
            }
            indicatorsText.text = if (sb.isEmpty()) "No threat indicators." else sb.toString().trim()

            payloadText.text = "Type: ${root.optString("classification", "?")}\n" +
                root.optString("payload", "")
        } catch (e: Exception) {
            verdictText.text = "ERROR"
            verdictText.setTextColor(Color.parseColor("#F59E0B"))
            summaryText.text = "Could not parse the backend response."
        }
    }
}
