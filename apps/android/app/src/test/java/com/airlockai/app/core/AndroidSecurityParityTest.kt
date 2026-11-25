package com.airlockai.app.core

import org.junit.Assert.*
import org.junit.Test

class AndroidSecurityParityTest {

    @Test
    fun safeHarborDetectsUrlsIpv4ZipAndRecordIds() {
        val sample =
            "Portal https://portal.helios.test/case/99 IP 10.24.88.15 ZIP 94107 record MRN-884210 invoice INV-2026-4410."
        val spans = AndroidSecurityGuards.scanSafeHarborSpans(sample)
        val texts = spans.map { it.text }
        assertTrue(texts.contains("https://portal.helios.test/case/99"))
        assertTrue(texts.contains("10.24.88.15"))
        assertTrue(texts.contains("94107"))
        assertTrue(texts.contains("MRN-884210"))
        assertTrue(texts.contains("INV-2026-4410"))
    }

    @Test
    fun failClosedResidualGuardFlagsUnredactedProperNounAndClearsWhenRedacted() {
        val unredacted = "Signed by [PERSON_1], with witness Kaelen reviewing the appendix."
        val report = AndroidSecurityGuards.analyzeResidualRisks(unredacted, gate2UsedNano = false)
        assertTrue(report.requiresReview)
        assertTrue(report.flaggedProperNouns.contains("Kaelen"))
        assertEquals("ELEVATED", report.riskLevel)

        val raw = RawDocument(unredacted)
        val vault = AirlockVault("AIRLOCK-CANARY-FIXED001")
        val customSpans = AndroidSecurityGuards.scanCustomSecretSpans(unredacted, listOf("Kaelen"))
        val scrubbed = vault.redactSpans(raw, customSpans)
        val cleanReport = AndroidSecurityGuards.analyzeResidualRisks(scrubbed, gate2UsedNano = false)
        assertFalse(cleanReport.requiresReview)
        assertEquals("LOW", cleanReport.riskLevel)
    }

    @Test
    fun indirectPromptInjectionDisarmsAllThreeAdversarialClausesIndependently() {
        val rep = AndroidSecurityGuards.neutralizePromptInjections(
            AndroidSecurityGuards.SAMPLE_INJECTION_PAYLOAD
        )
        assertFalse(rep.clean)
        assertEquals(3, rep.findings.size)
        val rules = rep.findings.map { it.rule }.toSet()
        assertTrue(rules.contains("INSTRUCTION_OVERRIDE"))
        assertTrue(rules.contains("RISK_MANIPULATION"))
        assertTrue(rules.contains("SECRET_EXFIL_DIRECTIVE"))
        assertTrue(rep.neutralizedText.contains("[INJECTION_NEUTRALIZED:INSTRUCTION_OVERRIDE]"))
        assertTrue(rep.neutralizedText.contains("[INJECTION_NEUTRALIZED:RISK_MANIPULATION]"))
        assertTrue(rep.neutralizedText.contains("[INJECTION_NEUTRALIZED:SECRET_EXFIL_DIRECTIVE]"))
    }

    @Test
    fun sha256MerkleTreeGeneratesValidOlogNProofsAndRejectsOneCharTamper() {
        val hashes = (1..5).map { Gate3Firewall.sha256Hex("receipt-$it") }
        val tree = AndroidMerkleTree.buildTree(hashes)
        assertEquals(5, tree.leafCount)
        assertEquals(3, tree.depth)
        assertNotNull(tree.root)

        for (i in hashes.indices) {
            val proof = AndroidMerkleTree.generateInclusionProof(tree, i)
            assertNotNull(proof)
            assertTrue("Proof failed for leaf $i", AndroidMerkleTree.verifyInclusionProof(proof!!))
        }

        val leaf2 = AndroidMerkleTree.generateInclusionProof(tree, 2)!!
        val tamperedStep = leaf2.proofPath.first().let { s ->
            val flip = if (s.hash.startsWith("0")) "1" else "0"
            s.copy(hash = flip + s.hash.substring(1))
        }
        val tamperedProof = leaf2.copy(proofPath = listOf(tamperedStep) + leaf2.proofPath.drop(1))
        assertFalse(AndroidMerkleTree.verifyInclusionProof(tamperedProof))
    }

    @Test
    fun bitmapRedactionBoxesClampSafelyToImageBounds() {
        val boxes = listOf(
            PixelRedactionBox(-20f, -10f, 150f, 80f, "[SSN_1]"),
            PixelRedactionBox(400f, 300f, 999f, 999f, "[ORG_1]"),
            PixelRedactionBox(50f, 50f, 50.5f, 51f, "[TOO_SMALL]"),
        )
        val clamped = AndroidBitmapRedactor.clampRedactionBoxes(boxes, width = 500, height = 400)
        assertEquals(2, clamped.size)
        assertEquals(0f, clamped[0].left, 0.01f)
        assertEquals(0f, clamped[0].top, 0.01f)
        assertEquals(500f, clamped[1].right, 0.01f)
        assertEquals(400f, clamped[1].bottom, 0.01f)
    }
}
