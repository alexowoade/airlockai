package com.airlockai.app.core

import kotlin.math.ln

object Gate1Regex {
    private data class PatternRule(
        val category: EntityCategory,
        val regex: Regex,
        val validate: ((String) -> Boolean)? = null,
    )

    fun passesLuhn(rawDigits: String): Boolean {
        val digits = rawDigits.filter { it.isDigit() }
        if (digits.length !in 13..19) return false
        var sum = 0
        var shouldDouble = false
        for (i in digits.length - 1 downTo 0) {
            var digit = digits[i].digitToInt()
            if (shouldDouble) {
                digit *= 2
                if (digit > 9) digit -= 9
            }
            sum += digit
            shouldDouble = !shouldDouble
        }
        return sum % 10 == 0
    }

    fun shannonEntropy(input: String): Double {
        if (input.isEmpty()) return 0.0
        val freq = mutableMapOf<Char, Int>()
        for (ch in input) {
            freq[ch] = (freq[ch] ?: 0) + 1
        }
        var entropy = 0.0
        val ln2 = ln(2.0)
        for (count in freq.values) {
            val p = count.toDouble() / input.length
            entropy -= p * (ln(p) / ln2)
        }
        return entropy
    }

    private val rules = listOf(
        PatternRule(
            category = EntityCategory.CARD_OR_ACCOUNT,
            regex = Regex("""\b(?:\d[ -]?){13,19}\b"""),
            validate = ::passesLuhn,
        ),
        PatternRule(
            category = EntityCategory.IBAN,
            regex = Regex("""\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"""),
        ),
        PatternRule(
            category = EntityCategory.SSN,
            regex = Regex("""\b\d{3}-\d{2}-\d{4}\b"""),
        ),
        PatternRule(
            category = EntityCategory.EMAIL,
            regex = Regex("""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"""),
        ),
        PatternRule(
            category = EntityCategory.API_SECRET,
            regex = Regex("""\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{30,}|[A-Za-z0-9+/=_-]{24,64})\b"""),
            validate = { m ->
                if (m.startsWith("sk-") || m.startsWith("AIza") || m.startsWith("ghp_")) {
                    true
                } else {
                    m.any { it.isUpperCase() } &&
                        m.any { it.isLowerCase() } &&
                        m.any { it.isDigit() } &&
                        shannonEntropy(m) >= 4.0
                }
            },
        ),
        PatternRule(
            category = EntityCategory.PHONE,
            regex = Regex("""(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\w)"""),
        ),
        PatternRule(
            category = EntityCategory.CURRENCY,
            regex = Regex("""(?:[${'$'}€£₦]\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|EUR|GBP|NGN)\b)"""),
        ),
        PatternRule(
            category = EntityCategory.DATE,
            regex = Regex("""\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\b"""),
        ),
    )

    fun scanDeterministicPii(rawDoc: RawDocument): List<DetectedSpan> {
        val candidates = mutableListOf<DetectedSpan>()
        for (rule in rules) {
            for (match in rule.regex.findAll(rawDoc.value)) {
                val text = match.value
                if (rule.validate == null || rule.validate.invoke(text)) {
                    candidates += DetectedSpan(
                        start = match.range.first,
                        end = match.range.last + 1,
                        text = text,
                        category = rule.category,
                        detectedBy = DetectionSource.GATE1_REGEX,
                    )
                }
            }
        }
        return resolveOverlappingSpans(candidates)
    }

    fun resolveOverlappingSpans(spans: List<DetectedSpan>): List<DetectedSpan> {
        val sorted = spans.sortedWith(
            compareByDescending<DetectedSpan> { it.category.priority }
                .thenByDescending { it.end - it.start }
                .thenBy { it.start }
        )
        val accepted = mutableListOf<DetectedSpan>()
        for (span in sorted) {
            val overlaps = accepted.any { other -> span.start < other.end && span.end > other.start }
            if (!overlaps) accepted += span
        }
        return accepted.sortedBy { it.start }
    }
}
