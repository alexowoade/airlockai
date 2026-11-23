package com.airlockai.app.core

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class EncryptedVaultBlob(
    val alg: String = "AES-256-GCM",
    val ivBase64: String,
    val ciphertextBase64: String,
)

class AirlockVault(customCanary: String? = null) {
    private val byOriginal = linkedMapOf<String, VaultEntry>()
    private val byToken = linkedMapOf<String, VaultEntry>()
    private val categoryCounters = mutableMapOf<EntityCategory, Int>()

    val canaryToken: String = customCanary ?: generateCanary()

    init {
        register(canaryToken, EntityCategory.CANARY, DetectionSource.SYSTEM_CANARY)
    }

    fun register(
        original: String,
        category: EntityCategory,
        detectedBy: DetectionSource,
    ): VaultEntry {
        val trimmed = original.trim()
        val key = "${category.name}::${trimmed.lowercase()}"
        byOriginal[key]?.let { return it }

        val nextIdx = (categoryCounters[category] ?: 0) + 1
        categoryCounters[category] = nextIdx
        val token = "[${category.name}_$nextIdx]"

        val entry = VaultEntry(token, trimmed, category, detectedBy)
        byOriginal[key] = entry
        byToken[token] = entry
        return entry
    }

    fun redactSpans(rawDoc: RawDocument, spans: List<DetectedSpan>): String {
        if (spans.isEmpty()) return rawDoc.value
        val sb = StringBuilder()
        var cursor = 0
        for (span in spans) {
            if (span.start < cursor) continue
            val entry = register(span.text, span.category, span.detectedBy)
            sb.append(rawDoc.value, cursor, span.start)
            sb.append(entry.token)
            cursor = span.end
        }
        sb.append(rawDoc.value, cursor, rawDoc.value.length)
        return sb.toString()
    }

    fun rehydrate(sanitizedText: String): String {
        var result = sanitizedText
        for ((token, entry) in byToken) {
            if (entry.category == EntityCategory.CANARY) continue
            result = result.replace(token, entry.original)
        }
        return result
    }

    fun getEntries(includeCanary: Boolean = false): List<VaultEntry> =
        byToken.values.filter { includeCanary || it.category != EntityCategory.CANARY }

    fun encryptSnapshot(key: SecretKey): EncryptedVaultBlob {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val serialized = getEntries(true).joinToString("\n") { "${it.token}|${it.category}|${it.original}" }
        val encrypted = cipher.doFinal(serialized.toByteArray(Charsets.UTF_8))
        return EncryptedVaultBlob(
            ivBase64 = Base64.getEncoder().encodeToString(iv),
            ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted),
        )
    }

    companion object {
        private fun generateCanary(): String {
            val bytes = ByteArray(9).also { SecureRandom().nextBytes(it) }
            val hex = bytes.joinToString("") { "%02x".format(it) }
            return "AIRLOCK-CANARY-$hex"
        }

        fun generateEphemeralAesKey(): SecretKey =
            KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }
}
