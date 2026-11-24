package com.airlockai.app.core

import kotlin.math.ln

object Gate1Regex {
    private data class PatternRule(
        val category: EntityCategory,
        val regex: Regex,
        val captureGroup: Int? = null,
        val trimOrgLeading: Boolean = false,
        val validate: ((String) -> Boolean)? = null,
    )

    private val orgLeadingExcluded = setOf(
        "a", "against", "an", "and", "at", "between", "billed", "by", "client",
        "company", "contact", "discloser", "facility", "for", "from", "in",
        "into", "of", "on", "or", "party", "per", "recipient", "the", "to",
        "under", "vendor", "with",
    )

    private val nonPersonWords = setOf(
        "agreement", "amendment", "amount", "and", "annex", "annual", "appendix",
        "article", "assignment", "associates", "authorized", "backup", "balance",
        "bank", "between", "billed", "billing", "board", "breach", "business",
        "capital", "carcinoma", "card", "center", "charges", "chief", "clause",
        "client", "clinic", "code", "codename", "company", "confidential",
        "consequential", "contact", "contract", "corp", "corporation", "court",
        "courts", "credit", "damages", "date", "days", "department", "derivative",
        "diabetes", "diagnosis", "diagnostics", "director", "discloser",
        "disclosure", "dispute", "disputes", "division", "document", "due",
        "effective", "email", "employee", "engineer", "enterprises", "executive",
        "exhibit", "facility", "fee", "file", "final", "finance", "financial",
        "floor", "follow", "for", "foundry", "from", "full", "general",
        "governing", "group", "health", "healthcare", "hipaa", "holdings",
        "hospital", "iban", "imaging", "inc", "indemnity", "industries",
        "information", "instructions", "insurance", "intellectual", "invoice",
        "item", "january", "february", "march", "april", "may", "june", "july",
        "august", "september", "october", "november", "december", "monday",
        "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
        "jurisdiction", "key", "labs", "late", "law", "lead", "legal", "leukemia",
        "liability", "license", "licensing", "limited", "llc", "llp", "logistics",
        "ltd", "lymphoma", "manager", "master", "medical", "melanoma", "mellitus",
        "mutual", "nda", "net", "network", "new", "non", "note", "notice",
        "number", "officer", "on", "oncology", "operation", "order", "out",
        "outpatient", "panel", "partner", "partners", "party", "pathology",
        "patient", "payment", "penalty", "perpetual", "person", "personnel",
        "phone", "plan", "policy", "president", "pricing", "primary", "prior",
        "privacy", "project", "property", "recipient", "record", "ref",
        "remittance", "report", "representative", "robotics", "sarcoma",
        "schedule", "schematics", "section", "security", "senior", "service",
        "services", "settlement", "signer", "solicit", "solutions", "ssn",
        "stage", "statement", "street", "subject", "summary", "systems", "tax",
        "technologies", "term", "terms", "the", "thyroid", "to", "total", "type",
        "unpaid", "updated", "urgent", "vendor", "ventures", "vice", "weekly",
        "wire", "with", "within",
    )

    private val leadingWordRegex = Regex("""^([A-Za-z]+)(\s+)""")

    private const val NAME_PART = "(?:[A-Z][a-z]{0,20}[-'][A-Z][a-z]{1,20}|[A-Z][a-z]{1,20})"
    private const val ORG_SUFFIX_PATTERN =
        "(?:Corp\\.?|Corporation|Inc\\.?|LLC|LLP|Ltd\\.?|Limited|Group|Holdings|Foundry|" +
            "Robotics|Labs|Systems|Technologies|Solutions|Partners|Ventures|" +
            "Bank|Capital|Clinic|Hospital|Medical Center|Center|Health|Healthcare|" +
            "Diagnostics|Associates|Industries|Enterprises)"

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

    private fun isValidPersonPhrase(phrase: String): Boolean {
        val words = phrase.trim().split(Regex("""\s+"""))
        if (words.size < 2) return false
        return words.all { it.lowercase() !in nonPersonWords }
    }

    private fun trimLeadingOrgWords(text: String, start: Int): Triple<Int, Int, String>? {
        var curText = text
        var curStart = start
        while (true) {
            val m = leadingWordRegex.find(curText) ?: break
            val word = m.groupValues[1]
            if (word.lowercase() in orgLeadingExcluded) {
                val adv = m.value.length
                curText = curText.substring(adv)
                curStart += adv
            } else {
                break
            }
        }
        if (!curText.contains(' ')) return null
        return Triple(curStart, curStart + curText.length, curText)
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
        // Deterministic Named-Entity Fallback Rules (parity with TypeScript Gate 1)
        PatternRule(
            category = EntityCategory.ORG,
            regex = Regex(
                "\\b[A-Z][A-Za-z0-9'.-]+(?:\\s+(?:&\\s+)?[A-Z][A-Za-z0-9'.-]+){0,4}\\s+$ORG_SUFFIX_PATTERN(?=\\b|[^A-Za-z0-9])"
            ),
            trimOrgLeading = true,
        ),
        PatternRule(
            category = EntityCategory.SECRET_TERM,
            regex = Regex("""\b(?:Project|Operation|Codename)\s+[A-Z][a-zA-Z0-9-]+(?:\s+[A-Z][a-zA-Z0-9-]+)?\b"""),
        ),
        PatternRule(
            category = EntityCategory.MEDICAL,
            regex = Regex(
                """\b(?:Stage\s+(?:I{1,3}V?|IV|[1-4])[A-B]?\s+[A-Z][a-zA-Z-]+(?:\s+[A-Z][a-zA-Z-]+){0,3}|Type\s+[12]\s+Diabetes(?:\s+Mellitus)?|(?:[A-Z][a-zA-Z-]+\s+){0,2}(?:Carcinoma|Lymphoma|Leukemia|Melanoma|Sarcoma|Diabetes|Hypertension|Pneumonia|Hepatitis|Asthma|Arthritis|Neuropathy|Sclerosis|Infarction))\b"""
            ),
        ),
        PatternRule(
            category = EntityCategory.PERSON,
            regex = Regex("\\b(?:Dr\\.|Mr\\.|Mrs\\.|Ms\\.|Prof\\.)\\s+$NAME_PART(?:\\s+$NAME_PART)?\\b"),
        ),
        PatternRule(
            category = EntityCategory.PERSON,
            regex = Regex(
                "\\b(?:Patient|Authorized Signer|Signer|Lead Engineer|Chief Executive Officer|Chief Financial Officer|CEO|CFO|Director|Manager|Contact|Attn|Employee|Physician|Doctor|Counsel)\\s*:?\\s+($NAME_PART\\s+$NAME_PART)\\b"
            ),
            captureGroup = 1,
            validate = ::isValidPersonPhrase,
        ),
        PatternRule(
            category = EntityCategory.PERSON,
            regex = Regex("\\b$NAME_PART\\s+$NAME_PART\\b"),
            validate = ::isValidPersonPhrase,
        ),
    )

    fun scanDeterministicPii(rawDoc: RawDocument): List<DetectedSpan> {
        val candidates = mutableListOf<DetectedSpan>()
        for (rule in rules) {
            for (match in rule.regex.findAll(rawDoc.value)) {
                var start: Int
                var end: Int
                var text: String

                val grp = rule.captureGroup?.let { match.groups[it] }
                if (grp != null) {
                    start = grp.range.first
                    end = grp.range.last + 1
                    text = grp.value
                } else {
                    start = match.range.first
                    end = match.range.last + 1
                    text = match.value
                }

                if (rule.trimOrgLeading) {
                    val trimmed = trimLeadingOrgWords(text, start) ?: continue
                    start = trimmed.first
                    end = trimmed.second
                    text = trimmed.third
                }

                if (rule.validate == null || rule.validate.invoke(text)) {
                    candidates += DetectedSpan(
                        start = start,
                        end = end,
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
