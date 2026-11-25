package com.airlockai.app.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.airlockai.app.core.*
import com.airlockai.app.firebase.AndroidAirlockHybridService
import com.airlockai.app.firebase.AndroidCloudAuditOutput
import com.airlockai.app.firebase.AndroidLocalAirlockOutput
import com.airlockai.app.firebase.AndroidTriageOutput
import kotlinx.coroutines.launch

private const val SAMPLE_NDA =
    "MUTUAL NDA (2026-11-15) between Helios Robotics Corp (elena.vance@helios.test, +1-415-890-4421) and Apex Foundry LLC. " +
        "Pricing cap $1,450,000.00, credential sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f, Lead Engineer SSN 912-45-6789, MRN-884210, ZIP 94107. " +
        "Recipient assumes unlimited liability with perpetual IP assignment."

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val hybridService = AndroidAirlockHybridService(applicationContext)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AirlockAndroidScreen(hybridService)
                }
            }
        }
    }
}

@Composable
private fun AirlockAndroidScreen(service: AndroidAirlockHybridService) {
    val scope = rememberCoroutineScope()
    var rawText by remember { mutableStateOf(SAMPLE_NDA) }
    var policy by remember { mutableStateOf(PolicyProfile.NDA_STRICT) }
    var strictSafeHarbor by remember { mutableStateOf(false) }
    var customSecrets by remember { mutableStateOf<List<String>>(emptyList()) }
    var overrideFailClosed by remember { mutableStateOf(false) }

    var busy by remember { mutableStateOf(false) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    var localOut by remember { mutableStateOf<AndroidLocalAirlockOutput?>(null) }
    var redTeamAlert by remember { mutableStateOf<String?>(null) }
    var injectionAlert by remember { mutableStateOf<String?>(null) }
    var triageOut by remember { mutableStateOf<AndroidTriageOutput?>(null) }
    var cloudOut by remember { mutableStateOf<AndroidCloudAuditOutput?>(null) }
    var showRehydrated by remember { mutableStateOf(true) }
    var ledgerItems by remember { mutableStateOf<List<String>>(emptyList()) }
    var merkleRoot by remember { mutableStateOf<String?>(null) }

    val verifiedPayload = (localOut?.firewallResult as? FirewallResult.Passed)?.payload
    val cloudLockedByFailClosed = (localOut?.residualRisk?.requiresReview == true) && !overrideFailClosed

    fun triggerLocalAirlock(nextSafeHarbor: Boolean = strictSafeHarbor, nextSecrets: List<String> = customSecrets) {
        scope.launch {
            busy = true
            errorMsg = null
            redTeamAlert = null
            triageOut = null
            cloudOut = null
            overrideFailClosed = false
            localOut = service.runLocalAirlock(
                rawText = rawText,
                policy = policy,
                strictSafeHarbor = nextSafeHarbor,
                customSecrets = nextSecrets,
            )
            busy = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("AirlockAI — Android Hybrid Airlock", style = MaterialTheme.typography.titleLarge)
        Text(
            text = if (service.isFirebaseReady) "Firebase AI Logic: CONNECTED" else "Local Firewall Mode (Add google-services.json for Cloud)",
            color = if (service.isFirebaseReady) Color(0xFF34D399) else Color(0xFFFBBF24),
            style = MaterialTheme.typography.labelMedium,
        )

        errorMsg?.let { Text(it, color = Color(0xFFF87171)) }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PolicyProfile.entries.forEach { p ->
                FilterChip(
                    selected = policy == p,
                    onClick = { policy = p },
                    label = { Text(p.name) },
                )
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = strictSafeHarbor,
                onClick = {
                    strictSafeHarbor = !strictSafeHarbor
                    if (localOut != null) triggerLocalAirlock(nextSafeHarbor = strictSafeHarbor)
                },
                label = { Text("Strict Safe Harbor (URL/IP/ZIP/ID): ${if (strictSafeHarbor) "ON" else "OFF"}") },
            )
        }

        OutlinedTextField(
            value = rawText,
            onValueChange = { rawText = it },
            label = { Text("Sensitive Local Document (Never Leaves Device)") },
            modifier = Modifier.fillMaxWidth().height(150.dp),
        )

        Button(
            onClick = { triggerLocalAirlock() },
            enabled = !busy && rawText.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (busy) "Running 3-Gate Local Airlock..." else "1. Run 3-Gate Local Airlock (0B Sent)")
        }

        localOut?.let { out ->
            if (!out.injectionGuard.clean) {
                Text(
                    "PROMPT INJECTION NEUTRALIZED LOCALLY: ${out.injectionGuard.findings.size} clause(s) (${out.injectionGuard.findings.joinToString { it.rule }})",
                    color = Color(0xFFF87171),
                    style = MaterialTheme.typography.labelMedium,
                )
            }

            if (out.residualRisk.requiresReview) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            "FAIL-CLOSED GUARD ACTIVE (Risk: ${out.residualRisk.riskLevel}) — Cloud Locked",
                            color = Color(0xFFFBBF24),
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            out.residualRisk.flaggedProperNouns.take(3).forEach { term ->
                                OutlinedButton(
                                    onClick = {
                                        val updated = (customSecrets + term).distinct()
                                        customSecrets = updated
                                        triggerLocalAirlock(nextSecrets = updated)
                                    }
                                ) { Text("+ Redact \"$term\"") }
                            }
                            TextButton(onClick = { overrideFailClosed = !overrideFailClosed }) {
                                Text(if (overrideFailClosed) "Re-Lock Cloud" else "Override")
                            }
                        }
                    }
                }
            }
        }

        verifiedPayload?.let { verified ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "6/6 Firewall Passed · ${verified.receipt.redactedCount} redacted · Risk: ${localOut?.residualRisk?.riskLevel ?: "LOW"} · SHA-256 ${verified.receipt.receiptSha256.take(14)}…",
                        color = Color(0xFF34D399),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    Text(verified.sanitizedText, fontFamily = FontFamily.Monospace)

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                val out = localOut ?: return@OutlinedButton
                                val poisoned = Gate3Firewall.injectRedTeamAttack(
                                    out.candidateSanitized,
                                    out.vault,
                                    RedTeamAttackType.BASE64_EXFILTRATION,
                                )
                                val blocked = Gate3Firewall.verifyAndMintPayload(
                                    out.rawDoc, poisoned, out.vault, policy
                                )
                                if (blocked is FirewallResult.Blocked) {
                                    redTeamAlert = "BLOCKED BASE64 EXFIL — 0B sent (${blocked.blockedBytes}B aborted). Vector: ${blocked.violations.first().vector}"
                                }
                            }
                        ) { Text("Base64") }

                        OutlinedButton(
                            onClick = {
                                val out = localOut ?: return@OutlinedButton
                                val poisoned = Gate3Firewall.injectRedTeamAttack(
                                    out.candidateSanitized,
                                    out.vault,
                                    RedTeamAttackType.CANARY_PROMPT_INJECTION,
                                )
                                val blocked = Gate3Firewall.verifyAndMintPayload(
                                    out.rawDoc, poisoned, out.vault, policy
                                )
                                if (blocked is FirewallResult.Blocked) {
                                    redTeamAlert = "BLOCKED CANARY INJECTION — 0B sent (${blocked.blockedBytes}B aborted). Vector: ${blocked.violations.first().vector}"
                                }
                            }
                        ) { Text("Canary") }

                        OutlinedButton(
                            onClick = {
                                val rep = AndroidSecurityGuards.neutralizePromptInjections(
                                    "${verified.sanitizedText}\n\n${AndroidSecurityGuards.SAMPLE_INJECTION_PAYLOAD}"
                                )
                                injectionAlert =
                                    "DISARMED ${rep.findings.size} INJECTION CLAUSE(S) (0B SENT): ${rep.findings.joinToString { it.rule }}"
                            }
                        ) { Text("Prompt Inj.") }
                    }

                    redTeamAlert?.let { Text(it, color = Color(0xFFF87171)) }
                    injectionAlert?.let { Text(it, color = Color(0xFF34D399)) }

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            enabled = !busy && service.isFirebaseReady && !cloudLockedByFailClosed,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    errorMsg = null
                                    runCatching { service.runHybridTriage(verified) }
                                        .onSuccess { triageOut = it }
                                        .onFailure { errorMsg = it.message }
                                    busy = false
                                }
                            }
                        ) { Text("2. Triage") }

                        Button(
                            enabled = !busy && service.isFirebaseReady && !cloudLockedByFailClosed,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    errorMsg = null
                                    runCatching {
                                        service.runDeepCloudAudit(verified, localOut!!.vault, policy)
                                    }.onSuccess {
                                        cloudOut = it
                                        ledgerItems = service.fetchRecentLedgerSummaries()
                                        val hashes = service.fetchRecentLedgerHashesChronological()
                                        merkleRoot = AndroidMerkleTree.buildTree(hashes).root
                                    }.onFailure { errorMsg = it.message }
                                    busy = false
                                }
                            }
                        ) { Text(if (cloudLockedByFailClosed) "Cloud Locked" else "3. Cloud Audit") }
                    }
                }
            }
        }

        triageOut?.let { t ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("Hybrid Triage [${t.inferenceSource} · ${t.latencyMs}ms]", color = Color(0xFF38BDF8))
                    Text(t.summary)
                }
            }
        }

        cloudOut?.let { c ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(
                            "Cloud Audit (${if (c.usedServerTemplate) policy.templateId else "ONLY_IN_CLOUD"}) · ${c.latencyMs}ms",
                            style = MaterialTheme.typography.titleSmall,
                        )
                        TextButton(onClick = { showRehydrated = !showRehydrated }) {
                            Text(if (showRehydrated) "Show Cloud View" else "Show Re-Hydrated")
                        }
                    }
                    Text(
                        if (showRehydrated) c.rehydratedMarkdown else c.sanitizedMarkdown,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }

        if (ledgerItems.isNotEmpty()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Cross-Device Firestore Zero-PII Ledger", style = MaterialTheme.typography.titleSmall)
                    merkleRoot?.let {
                        Text("SHA-256 Merkle Root: ${it.take(24)}…", color = Color(0xFF38BDF8), fontFamily = FontFamily.Monospace)
                    }
                    ledgerItems.forEach { Text(it, fontFamily = FontFamily.Monospace) }
                }
            }
        }
    }
}
