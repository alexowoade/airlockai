package com.airlockai.app.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class AirlockGoldenVectorParityTest {

    private fun loadSpec(): JSONObject {
        val candidates = listOf(
            File("../../../spec/vectors.json"),
            File("../../spec/vectors.json"),
            File("spec/vectors.json"),
        )
        val specFile = candidates.firstOrNull { it.exists() }
            ?: error("Could not locate spec/vectors.json from ${File(".").absolutePath}")
        return JSONObject(specFile.readText(Charsets.UTF_8))
    }

    @Test
    fun sha256SelfCheckMatchesCanonicalVector() {
        val check = loadSpec().getJSONObject("sha256SelfCheck")
        assertEquals(check.getString("expectedHex"), Gate3Firewall.sha256Hex(check.getString("input")))
    }

    @Test
    fun cleanVectorsMatchTypeScriptByteForByte() {
        val vectors = loadSpec().getJSONArray("cleanVectors")
        for (i in 0 until vectors.length()) {
            val vec = vectors.getJSONObject(i)
            val id = vec.getString("id")
            val raw = RawDocument(vec.getString("rawDoc"))
            val policy = PolicyProfile.valueOf(vec.getString("policyProfile"))
            val vault = AirlockVault("AIRLOCK-CANARY-FIXED001")

            val gate1 = Gate1Regex.scanDeterministicPii(raw)
            val gate2Arr = vec.getJSONArray("simulatedGate2Spans")
            val gate2 = mutableListOf<DetectedSpan>()
            for (j in 0 until gate2Arr.length()) {
                val item = gate2Arr.getJSONObject(j)
                val text = item.getString("text")
                val start = raw.value.indexOf(text)
                assertTrue("Span '$text' missing in $id", start >= 0)
                gate2 += DetectedSpan(
                    start = start,
                    end = start + text.length,
                    text = text,
                    category = EntityCategory.valueOf(item.getString("category")),
                    detectedBy = DetectionSource.GATE2_NANO_ON_DEVICE,
                )
            }

            val merged = Gate1Regex.resolveOverlappingSpans(gate1 + gate2)
            val sanitized = vault.redactSpans(raw, merged)
            assertEquals("Redaction mismatch on $id", vec.getString("expectedSanitized"), sanitized)

            val res = Gate3Firewall.verifyAndMintPayload(raw, sanitized, vault, policy)
            assertTrue("Expected clean pass on $id", res is FirewallResult.Passed)
            val passed = res as FirewallResult.Passed
            assertEquals(vec.getInt("expectedRedactedCount"), passed.payload.receipt.redactedCount)
            assertEquals(raw.value, vault.rehydrate(passed.payload.sanitizedText))
        }
    }

    @Test
    fun allSixAdversarialVectorsAreBlockedIdentically() {
        val vectors = loadSpec().getJSONArray("adversarialVectors")
        for (i in 0 until vectors.length()) {
            val adv = vectors.getJSONObject(i)
            val id = adv.getString("id")
            val secret = adv.getString("secret")
            val category = EntityCategory.valueOf(adv.getString("category"))
            val expectedVector = FirewallVector.valueOf(adv.getString("expectedVector"))

            val vault = AirlockVault("AIRLOCK-CANARY-FIXED001")
            if (category != EntityCategory.CANARY) {
                vault.register(secret, category, DetectionSource.GATE2_NANO_ON_DEVICE)
            }

            val res = Gate3Firewall.verifyAndMintPayload(
                rawDoc = RawDocument("Synthetic contract"),
                candidateSanitized = "Sanitized skeleton.${adv.getString("poisonedSuffix")}",
                vault = vault,
                policyProfile = PolicyProfile.NDA_STRICT,
            )
            assertTrue("Expected block on $id", res is FirewallResult.Blocked)
            val blocked = res as FirewallResult.Blocked
            assertTrue(
                "Expected vector $expectedVector on $id, got ${blocked.violations}",
                blocked.violations.any { it.vector == expectedVector },
            )
            assertTrue(blocked.blockedBytes > 0)
        }
    }
}
