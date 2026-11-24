package com.airlockai.app.core

import java.net.URLEncoder
import java.security.MessageDigest
import java.text.Normalizer
import java.time.Instant
import java.util.Base64

enum class RedTeamAttackType {
    MISSED_ENTITY_ESCAPE,
    BASE64_EXFILTRATION,
    CANARY_PROMPT_INJECTION,
    ZERO_WIDTH_SMUGGLING,
}

object Gate3Firewall {
    private val genericPartialWords = setOf(
        "associates", "capital", "center", "clinic", "codename", "corporation",
        "diagnostics", "enterprises", "foundry", "group", "health", "healthcare",
        "holdings", "hospital", "imaging", "industries", "limited", "logistics",
        "medical", "oncology", "operation", "partners", "project", "robotics",
        "solutions", "systems", "technologies", "ventures",
    )

    private val zeroWidthRegex = Regex("[\u200B-\u200D\u2060\uFEFF]")
    private val nonAlnumRegex = Regex("[^a-zA-Z0-9]")

    fun sha256Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun toBase64Utf8(input: String): String =
        Base64.getEncoder().encodeToString(input.toByteArray(Charsets.UTF_8))

    private fun toHexUtf8(input: String): String =
        input.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }

    private fun collapseAlnum(input: String): String =
        nonAlnumRegex.replace(input, "").lowercase()

    fun injectRedTeamAttack(
        cleanSanitized: String,
        vault: AirlockVault,
        attack: RedTeamAttackType,
    ): String {
        val firstSecret = vault.getEntries(false).firstOrNull()?.original ?: "4111-1111-1111-1111"
        return when (attack) {
            RedTeamAttackType.MISSED_ENTITY_ESCAPE ->
                "$cleanSanitized\n[SIMULATED_NANO_MISS]: $firstSecret"
            RedTeamAttackType.BASE64_EXFILTRATION ->
                "$cleanSanitized\n[EXFIL_B64]: ${toBase64Utf8(firstSecret)}"
            RedTeamAttackType.CANARY_PROMPT_INJECTION ->
                "$cleanSanitized\n[INJECTED_ECHO]: ${vault.canaryToken}"
            RedTeamAttackType.ZERO_WIDTH_SMUGGLING ->
                "$cleanSanitized\n[ZWSP_SMUGGLE]: ${firstSecret.toCharArray().joinToString("\u200B")}"
        }
    }

    fun verifyAndMintPayload(
        rawDoc: RawDocument,
        candidateSanitized: String,
        vault: AirlockVault,
        policyProfile: PolicyProfile,
        prevReceiptSha256: String? = null,
    ): FirewallResult {
        val violations = mutableListOf<FirewallViolation>()
        val lowerPayload = candidateSanitized.lowercase()
        val collapsedPayload = collapseAlnum(candidateSanitized)
        val nfkcCleanPayload = zeroWidthRegex
            .replace(Normalizer.normalize(candidateSanitized, Normalizer.Form.NFKC), "")
            .lowercase()
        val nfkcChanged = nfkcCleanPayload != lowerPayload

        for (entry in vault.getEntries(includeCanary = true)) {
            val secret = entry.original
            val lowerSecret = secret.lowercase()
            val nfkcSecret = zeroWidthRegex
                .replace(Normalizer.normalize(secret, Normalizer.Form.NFKC), "")
                .lowercase()

            // Vector 6: Canary Trap
            if (entry.category == EntityCategory.CANARY) {
                if (lowerPayload.contains(lowerSecret) ||
                    nfkcCleanPayload.contains(nfkcSecret) ||
                    candidateSanitized.contains(toBase64Utf8(secret)) ||
                    lowerPayload.contains(toHexUtf8(secret))
                ) {
                    violations += FirewallViolation(
                        vector = FirewallVector.CANARY_TRAP,
                        token = entry.token,
                        category = EntityCategory.CANARY,
                        detail = "Prompt-injection canary leaked into outbound staging payload.",
                    )
                }
                continue
            }

            // Vector 1: Exact & case-insensitive leak
            if (lowerSecret.length >= 2 && lowerPayload.contains(lowerSecret)) {
                violations += FirewallViolation(
                    vector = FirewallVector.EXACT_OR_CASE_INSENSITIVE,
                    token = entry.token,
                    category = entry.category,
                    detail = "Raw ${entry.category} value escaped redaction.",
                )
                continue
            }

            // Vector 5: Unicode NFKC homoglyph or zero-width smuggling
            if (nfkcChanged && nfkcSecret.length >= 3 && nfkcCleanPayload.contains(nfkcSecret)) {
                violations += FirewallViolation(
                    vector = FirewallVector.UNICODE_NFKC_OR_ZERO_WIDTH,
                    token = entry.token,
                    category = entry.category,
                    detail = "Unicode homoglyph or zero-width obfuscated ${entry.category} detected.",
                )
                continue
            }

            // Vector 2: Collapsed alphanumeric leak
            val collapsedSecret = collapseAlnum(secret)
            if (collapsedSecret.length >= 6 && collapsedPayload.contains(collapsedSecret)) {
                violations += FirewallViolation(
                    vector = FirewallVector.COLLAPSED_ALPHANUMERIC,
                    token = entry.token,
                    category = entry.category,
                    detail = "Reformatted ${entry.category} sequence leaked after stripping punctuation.",
                )
                continue
            }

            // Vector 3: Partial-token / surname or trailing 6 digits leak
            if (entry.category == EntityCategory.PERSON ||
                entry.category == EntityCategory.ORG ||
                entry.category == EntityCategory.SECRET_TERM
            ) {
                val allWords = secret.split(Regex("\\s+"))
                val parts = allWords.filter {
                    it.length >= 5 && it.lowercase() !in genericPartialWords
                }
                if (allWords.size >= 2 && parts.isNotEmpty()) {
                    val leakedPart = parts.firstOrNull { part ->
                        Regex("\\b${Regex.escape(part)}\\b", RegexOption.IGNORE_CASE)
                            .containsMatchIn(candidateSanitized)
                    }
                    if (leakedPart != null) {
                        violations += FirewallViolation(
                            vector = FirewallVector.PARTIAL_TOKEN_OR_SURNAME,
                            token = entry.token,
                            category = entry.category,
                            detail = "Partial ${entry.category} token escaped redaction.",
                        )
                        continue
                    }
                }
            } else if ((entry.category == EntityCategory.CARD_OR_ACCOUNT ||
                    entry.category == EntityCategory.SSN ||
                    entry.category == EntityCategory.PHONE) &&
                collapsedSecret.length >= 9
            ) {
                val tail6 = collapsedSecret.takeLast(6)
                if (collapsedPayload.contains(tail6)) {
                    violations += FirewallViolation(
                        vector = FirewallVector.PARTIAL_TOKEN_OR_SURNAME,
                        token = entry.token,
                        category = entry.category,
                        detail = "Trailing 6 digits of ${entry.category} escaped redaction.",
                    )
                    continue
                }
            }

            // Vector 4: Encoded exfiltration (Base64, Hex, URL-encoded)
            if (secret.length >= 4) {
                val b64 = toBase64Utf8(secret)
                val hex = toHexUtf8(secret)
                val urlEnc = URLEncoder.encode(secret, "UTF-8").replace("+", "%20")
                val urlDiffers = urlEnc.lowercase() != lowerSecret

                if (candidateSanitized.contains(b64) ||
                    lowerPayload.contains(hex) ||
                    (urlDiffers && lowerPayload.contains(urlEnc.lowercase()))
                ) {
                    violations += FirewallViolation(
                        vector = FirewallVector.ENCODED_EXFILTRATION,
                        token = entry.token,
                        category = entry.category,
                        detail = "Encoded (Base64/Hex/URL) exfiltration of ${entry.category} detected.",
                    )
                }
            }
        }

        if (violations.isNotEmpty()) {
            return FirewallResult.Blocked(
                violations = violations,
                blockedBytes = candidateSanitized.toByteArray(Charsets.UTF_8).size,
            )
        }

        val timestampIso = Instant.now().toString()
        val rawDocSha256 = sha256Hex(rawDoc.value)
        val sanitizedPayloadSha256 = sha256Hex(candidateSanitized)
        val redactedCount = vault.getEntries(false).size

        val prevJson = if (prevReceiptSha256 == null) "null" else "\"$prevReceiptSha256\""
        val receiptPreimage =
            """{"receiptVersion":"airlock.v1","rawDocSha256":"$rawDocSha256","sanitizedPayloadSha256":"$sanitizedPayloadSha256","prevReceiptSha256":$prevJson,"redactedCount":$redactedCount,"policyProfile":"${policyProfile.name}","timestampIso":"$timestampIso"}"""
        val receiptSha256 = sha256Hex(receiptPreimage)

        val receipt = AirlockReceipt(
            rawDocSha256 = rawDocSha256,
            sanitizedPayloadSha256 = sanitizedPayloadSha256,
            prevReceiptSha256 = prevReceiptSha256,
            receiptSha256 = receiptSha256,
            redactedCount = redactedCount,
            policyProfile = policyProfile,
            timestampIso = timestampIso,
        )

        val payload = VerifiedSanitizedPayload(
            sanitizedText = candidateSanitized,
            entitySummary = vault.getEntries(false).map { EntitySummaryItem(it.token, it.category) },
            receipt = receipt,
        )
        return FirewallResult.Passed(payload)
    }
}
