package com.airlockai.app.firebase

import android.content.Context
import android.graphics.Bitmap
import com.airlockai.app.BuildConfig
import com.airlockai.app.core.*
import com.google.firebase.Firebase
import com.google.firebase.FirebaseApp
import com.google.firebase.ai.InferenceMode
import com.google.firebase.ai.InferenceSource
import com.google.firebase.ai.OnDeviceConfig
import com.google.firebase.ai.OnDeviceModelOption
import com.google.firebase.ai.ai
import com.google.firebase.ai.type.GenerativeBackend
import com.google.firebase.ai.type.PublicPreviewAPI
import com.google.firebase.ai.type.content
import com.google.firebase.appcheck.AppCheckProviderFactory
import com.google.firebase.appcheck.appCheck
import com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProviderFactory
import com.google.firebase.auth.auth
import com.google.firebase.firestore.Query
import com.google.firebase.firestore.firestore
import kotlinx.coroutines.tasks.await
import org.json.JSONObject

data class AndroidLocalAirlockOutput(
    val rawDoc: RawDocument,
    val candidateSanitized: String,
    val vault: AirlockVault,
    val gate1Count: Int,
    val gate2Count: Int,
    val customCount: Int = 0,
    val gate2UsedNano: Boolean,
    val residualRisk: ResidualRiskReport,
    val injectionGuard: PromptInjectionReport,
    val firewallResult: FirewallResult,
)

data class AndroidCloudAuditOutput(
    val sanitizedMarkdown: String,
    val rehydratedMarkdown: String,
    val usedServerTemplate: Boolean,
    val latencyMs: Long,
)

data class AndroidTriageOutput(
    val summary: String,
    val inferenceSource: String,
    val latencyMs: Long,
)

@OptIn(PublicPreviewAPI::class)
class AndroidAirlockHybridService(context: Context) {

    val isFirebaseReady: Boolean = FirebaseApp.getApps(context).isNotEmpty()

    init {
        if (isFirebaseReady) {
            val provider: AppCheckProviderFactory = if (BuildConfig.DEBUG) {
                runCatching {
                    val cls = Class.forName("com.google.firebase.appcheck.debug.DebugAppCheckProviderFactory")
                    cls.getMethod("getInstance").invoke(null) as AppCheckProviderFactory
                }.getOrElse { PlayIntegrityAppCheckProviderFactory.getInstance() }
            } else {
                PlayIntegrityAppCheckProviderFactory.getInstance()
            }
            Firebase.appCheck.installAppCheckProviderFactory(provider)
        }
    }

    private fun aiClient() = Firebase.ai(backend = GenerativeBackend.googleAI())

    /**
     * Gate 2 STRICTLY ON-DEVICE (Gemini Nano 4 Preview via AICore).
     * Never falls back to cloud; unsupported devices safely stay local with Gate 1.
     */
    suspend fun runLocalAirlock(
        rawText: String,
        policy: PolicyProfile,
        documentBitmap: Bitmap? = null,
        prevReceiptSha256: String? = null,
        strictSafeHarbor: Boolean = false,
        customSecrets: List<String> = emptyList(),
    ): AndroidLocalAirlockOutput {
        val vault = AirlockVault()
        var workingText = rawText.trim()
        val gate2Spans = mutableListOf<DetectedSpan>()
        var gate2UsedNano = false

        if (isFirebaseReady) {
            try {
                val localNanoModel = aiClient().generativeModel(
                    modelName = "gemini-3.5-flash-lite",
                    onDeviceConfig = OnDeviceConfig(
                        mode = InferenceMode.ONLY_ON_DEVICE,
                        modelOption = OnDeviceModelOption.PREVIEW,
                    ),
                )
                val prompt = content {
                    documentBitmap?.let { image(it) }
                    text(
                        "Return ONLY valid JSON: {\"extractedText\":\"...\",\"entities\":[{\"text\":\"...\",\"category\":\"PERSON|ORG|MEDICAL|SECRET_TERM\"}]}. " +
                            "Identify contextual PII under policy ${policy.name}. " +
                            if (documentBitmap != null) "Also transcribe visible text into extractedText." else "Document:\n$workingText"
                    )
                }
                val response = localNanoModel.generateContent(prompt)
                val rawJson = response.text?.trim()?.removePrefix("```json")?.removeSuffix("```")?.trim()
                if (!rawJson.isNullOrBlank()) {
                    val obj = JSONObject(rawJson)
                    if (workingText.isBlank()) {
                        workingText = obj.optString("extractedText", "")
                    }
                    val arr = obj.optJSONArray("entities")
                    if (arr != null && workingText.isNotBlank()) {
                        for (i in 0 until arr.length()) {
                            val item = arr.getJSONObject(i)
                            val entText = item.optString("text", "").trim()
                            val cat = runCatching {
                                EntityCategory.valueOf(item.optString("category", "SECRET_TERM"))
                            }.getOrDefault(EntityCategory.SECRET_TERM)
                            if (entText.length >= 3) {
                                var offset = 0
                                val lowerHay = workingText.lowercase()
                                val lowerNeedle = entText.lowercase()
                                while (offset < lowerHay.length) {
                                    val idx = lowerHay.indexOf(lowerNeedle, offset)
                                    if (idx == -1) break
                                    gate2Spans += DetectedSpan(
                                        start = idx,
                                        end = idx + entText.length,
                                        text = workingText.substring(idx, idx + entText.length),
                                        category = cat,
                                        detectedBy = DetectionSource.GATE2_NANO_ON_DEVICE,
                                    )
                                    offset = idx + entText.length
                                }
                            }
                        }
                    }
                    gate2UsedNano = true
                }
            } catch (_: Exception) {
                // AICore / Nano unavailable on this device: strictly stay local via Gate 1.
            }
        }

        val rawDoc = RawDocument(workingText)
        val gate1Spans = Gate1Regex.scanDeterministicPii(rawDoc)
        val safeHarborSpans = if (strictSafeHarbor) AndroidSecurityGuards.scanSafeHarborSpans(workingText) else emptyList()
        val customSpans = AndroidSecurityGuards.scanCustomSecretSpans(workingText, customSecrets)
        val merged = Gate1Regex.resolveOverlappingSpans(gate1Spans + safeHarborSpans + customSpans + gate2Spans)
        val rawCandidate = vault.redactSpans(rawDoc, merged)
        val injectionGuard = AndroidSecurityGuards.neutralizePromptInjections(rawCandidate)
        val candidateSanitized = injectionGuard.neutralizedText
        val residualRisk = AndroidSecurityGuards.analyzeResidualRisks(candidateSanitized, gate2UsedNano)

        val firewallResult = Gate3Firewall.verifyAndMintPayload(
            rawDoc = rawDoc,
            candidateSanitized = candidateSanitized,
            vault = vault,
            policyProfile = policy,
            prevReceiptSha256 = prevReceiptSha256,
        )

        return AndroidLocalAirlockOutput(
            rawDoc = rawDoc,
            candidateSanitized = candidateSanitized,
            vault = vault,
            gate1Count = gate1Spans.size + safeHarborSpans.size,
            gate2Count = gate2Spans.size,
            customCount = customSpans.size,
            gate2UsedNano = gate2UsedNano,
            residualRisk = residualRisk,
            injectionGuard = injectionGuard,
            firewallResult = firewallResult,
        )
    }

    /**
     * Hybrid Triage (PREFER_ON_DEVICE): runs on Gemini Nano if available, else falls back to cloud.
     * Accepts ONLY VerifiedSanitizedPayload at compile time.
     */
    suspend fun runHybridTriage(verified: VerifiedSanitizedPayload): AndroidTriageOutput {
        require(isFirebaseReady) { "Add google-services.json to apps/android/app/ to enable Firebase AI Logic." }
        val t0 = System.currentTimeMillis()
        val triageModel = aiClient().generativeModel(
            modelName = "gemini-3.5-flash-lite",
            onDeviceConfig = OnDeviceConfig(
                mode = InferenceMode.PREFER_ON_DEVICE,
                modelOption = OnDeviceModelOption.PREVIEW,
            ),
        )
        val response = triageModel.generateContent(
            "Give a 1-sentence risk triage using ONLY the existing placeholder tokens:\n\n${verified.sanitizedText}"
        )
        val latency = System.currentTimeMillis() - t0
        val source = if (response.inferenceSource == InferenceSource.ON_DEVICE) "ON_DEVICE" else "IN_CLOUD"
        return AndroidTriageOutput(
            summary = response.text ?: "(empty response)",
            inferenceSource = source,
            latencyMs = latency,
        )
    }

    /**
     * Deep Cloud Audit via locked Server Prompt Templates.
     * Accepts ONLY compile-time VerifiedSanitizedPayload.
     */
    suspend fun runDeepCloudAudit(
        verified: VerifiedSanitizedPayload,
        vault: AirlockVault,
        policy: PolicyProfile,
    ): AndroidCloudAuditOutput {
        require(isFirebaseReady) { "Add google-services.json to apps/android/app/ to enable Firebase AI Logic." }
        val t0 = System.currentTimeMillis()
        var usedTemplate = false

        val sanitizedMarkdown = try {
            val templateModel = aiClient().templateGenerativeModel()
            val response = templateModel.generateContent(
                templateId = policy.templateId,
                inputs = mapOf(
                    "sanitizedText" to verified.sanitizedText,
                    "policyProfile" to policy.name,
                ),
            )
            usedTemplate = true
            response.text ?: ""
        } catch (_: Exception) {
            val fallbackModel = aiClient().generativeModel(
                modelName = "gemini-3.5-flash-lite",
                onDeviceConfig = OnDeviceConfig(mode = InferenceMode.ONLY_IN_CLOUD),
            )
            val response = fallbackModel.generateContent(
                "You are AirlockAI (${policy.name}). Preserve placeholder tokens verbatim (e.g., [ORG_1]).\n" +
                    "Provide: 1) Risk Level, 2) Top 3 Risk Clauses, 3) Redline Fixes.\n\n${verified.sanitizedText}"
            )
            response.text ?: ""
        }

        val latency = System.currentTimeMillis() - t0
        val rehydrated = vault.rehydrate(sanitizedMarkdown)

        // Sync zero-PII SHA-256 receipt to the same Firestore Audit Ledger as Web & Extension
        runCatching {
            val auth = Firebase.auth
            val uid = auth.currentUser?.uid ?: auth.signInAnonymously().await().user!!.uid
            val risk = Regex("\\b(CRITICAL|HIGH|MEDIUM|LOW)\\b", RegexOption.IGNORE_CASE)
                .find(sanitizedMarkdown)?.value?.uppercase() ?: "MEDIUM"

            val r = verified.receipt
            val docData = hashMapOf(
                "receiptVersion" to r.receiptVersion,
                "rawDocSha256" to r.rawDocSha256,
                "sanitizedPayloadSha256" to r.sanitizedPayloadSha256,
                "prevReceiptSha256" to r.prevReceiptSha256,
                "receiptSha256" to r.receiptSha256,
                "redactedCount" to r.redactedCount,
                "checksPassed" to r.checksPassed,
                "firewallPassed" to r.firewallPassed,
                "policyProfile" to r.policyProfile.name,
                "inferenceSource" to "IN_CLOUD",
                "riskLevel" to risk,
                "sanitizedSummary" to "Android (${policy.name}): ${r.redactedCount} entities redacted, 6/6 firewall checks passed.",
                "timestampIso" to r.timestampIso,
            )
            Firebase.firestore.collection("users").document(uid)
                .collection("audit_ledger").add(docData).await()
        }

        return AndroidCloudAuditOutput(
            sanitizedMarkdown = sanitizedMarkdown,
            rehydratedMarkdown = rehydrated,
            usedServerTemplate = usedTemplate,
            latencyMs = latency,
        )
    }

    suspend fun fetchRecentLedgerSummaries(): List<String> {
        if (!isFirebaseReady) return emptyList()
        return runCatching {
            val auth = Firebase.auth
            val uid = auth.currentUser?.uid ?: auth.signInAnonymously().await().user!!.uid
            val snap = Firebase.firestore.collection("users").document(uid)
                .collection("audit_ledger")
                .orderBy("timestampIso", Query.Direction.DESCENDING)
                .limit(10)
                .get().await()
            snap.documents.map { d ->
                val hash = d.getString("receiptSha256")?.take(12) ?: "—"
                val summary = d.getString("sanitizedSummary") ?: ""
                "[$hash…] $summary"
            }
        }.getOrDefault(emptyList())
    }

    suspend fun fetchRecentLedgerHashesChronological(): List<String> {
        if (!isFirebaseReady) return emptyList()
        return runCatching {
            val auth = Firebase.auth
            val uid = auth.currentUser?.uid ?: auth.signInAnonymously().await().user!!.uid
            val snap = Firebase.firestore.collection("users").document(uid)
                .collection("audit_ledger")
                .orderBy("timestampIso", Query.Direction.ASCENDING)
                .limit(20)
                .get().await()
            snap.documents.mapNotNull { it.getString("receiptSha256") }
        }.getOrDefault(emptyList())
    }
}
