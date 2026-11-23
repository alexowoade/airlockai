package com.airlockai.app.core

@JvmInline
value class RawDocument(val value: String)

enum class EntityCategory(val priority: Int) {
    CANARY(110),
    CARD_OR_ACCOUNT(100),
    IBAN(95),
    SSN(90),
    EMAIL(85),
    API_SECRET(80),
    PHONE(70),
    CURRENCY(60),
    DATE(50),
    PERSON(40),
    ORG(40),
    MEDICAL(40),
    SECRET_TERM(40),
}

enum class PolicyProfile(val templateId: String) {
    NDA_STRICT("airlock-nda-v1-0-0"),
    MEDICAL_HIPAA("airlock-hipaa-v1-0-0"),
    INVOICE_FINANCE("airlock-invoice-v1-0-0"),
}

enum class DetectionSource {
    GATE1_REGEX,
    GATE2_NANO_ON_DEVICE,
    SYSTEM_CANARY,
}

data class VaultEntry(
    val token: String,
    val original: String,
    val category: EntityCategory,
    val detectedBy: DetectionSource,
)

data class DetectedSpan(
    val start: Int,
    val end: Int,
    val text: String,
    val category: EntityCategory,
    val detectedBy: DetectionSource,
)

enum class FirewallVector {
    EXACT_OR_CASE_INSENSITIVE,
    COLLAPSED_ALPHANUMERIC,
    PARTIAL_TOKEN_OR_SURNAME,
    ENCODED_EXFILTRATION,
    UNICODE_NFKC_OR_ZERO_WIDTH,
    CANARY_TRAP,
}

data class FirewallViolation(
    val vector: FirewallVector,
    val token: String,
    val category: EntityCategory,
    val detail: String,
)

data class AirlockReceipt(
    val receiptVersion: String = "airlock.v1",
    val rawDocSha256: String,
    val sanitizedPayloadSha256: String,
    val prevReceiptSha256: String?,
    val receiptSha256: String,
    val redactedCount: Int,
    val checksPassed: Int = 6,
    val firewallPassed: Boolean = true,
    val policyProfile: PolicyProfile,
    val timestampIso: String,
)

data class EntitySummaryItem(
    val token: String,
    val category: EntityCategory,
)

/**
 * Compile-time zero-leak guarantee: only Gate3Firewall can mint this payload.
 */
class VerifiedSanitizedPayload internal constructor(
    val sanitizedText: String,
    val entitySummary: List<EntitySummaryItem>,
    val receipt: AirlockReceipt,
)

sealed interface FirewallResult {
    data class Passed(val payload: VerifiedSanitizedPayload) : FirewallResult
    data class Blocked(
        val violations: List<FirewallViolation>,
        val blockedBytes: Int,
    ) : FirewallResult
}
