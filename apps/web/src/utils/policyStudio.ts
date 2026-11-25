import type { DetectedSpan, EntityCategory } from "@airlock/core";

export type CompliancePackId = "PCI_DSS" | "GDPR_EU" | "SOC2_CLOUD";

export interface CompliancePackMeta {
  readonly id: CompliancePackId;
  readonly label: string;
  readonly summary: string;
}

export interface CustomRegexRule {
  readonly id: string;
  readonly name: string;
  readonly pattern: string;
  readonly category: EntityCategory;
  readonly enabled: boolean;
}

export const COMPLIANCE_PACKS: ReadonlyArray<CompliancePackMeta> = [
  {
    id: "PCI_DSS",
    label: "PCI-DSS",
    summary: "SWIFT/BIC codes, 9-digit ABA routing numbers, CVV/CVC labels",
  },
  {
    id: "GDPR_EU",
    label: "GDPR-EU",
    summary: "EU VAT IDs, labeled passport numbers, national/tax IDs",
  },
  {
    id: "SOC2_CLOUD",
    label: "SOC2 Cloud",
    summary: "AWS ARNs, JWT bearer tokens, PEM key headers, RFC1918 VPC CIDRs",
  },
];

export const PRESET_CUSTOM_REGEX_RULES: ReadonlyArray<{
  readonly name: string;
  readonly pattern: string;
  readonly category: EntityCategory;
}> = [
  {
    name: "Internal Deal Code",
    pattern: "\\bDEAL-[0-9]{4}-[A-Z]{2}\\b",
    category: "SECRET_TERM",
  },
  {
    name: "Employee Badge ID",
    pattern: "\\bEMP-[0-9]{5,7}\\b",
    category: "PERSON",
  },
];

interface PackPattern {
  readonly regex: RegExp;
  readonly category: EntityCategory;
  readonly useGroup1?: boolean;
}

const PACK_PATTERNS: Record<CompliancePackId, ReadonlyArray<PackPattern>> = {
  PCI_DSS: [
    {
      regex: /\b(?:swift|bic)\s*(?:code|#|:)?\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi,
      category: "SECRET_TERM",
      useGroup1: true,
    },
    {
      regex: /\b(?:aba|routing)\s*(?:no\.?|number|#|:)?\s*(\d{9})\b/gi,
      category: "SECRET_TERM",
      useGroup1: true,
    },
    {
      regex: /\b(?:cvv|cvc|security\s+code)\s*(?:#|:)?\s*(\d{3,4})\b/gi,
      category: "SECRET_TERM",
      useGroup1: true,
    },
  ],
  GDPR_EU: [
    {
      regex: /\b(?:DE|FR|NL|ES|IT|IE|BE|AT|SE|PL)\d{8,12}\b/g,
      category: "SECRET_TERM",
    },
    {
      regex: /\b(?:passport)\s*(?:no\.?|number|#|:)?\s*([A-Z0-9]{6,12})\b/gi,
      category: "SSN",
      useGroup1: true,
    },
    {
      regex: /\b(?:national\s+id|tax\s+id|nin)\s*(?:no\.?|#|:)?\s*([A-Z0-9-]{6,16})\b/gi,
      category: "SSN",
      useGroup1: true,
    },
  ],
  SOC2_CLOUD: [
    {
      regex: /\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s,;)]+/gi,
      category: "API_SECRET",
    },
    {
      regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      category: "API_SECRET",
    },
    {
      regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
      category: "API_SECRET",
    },
    {
      regex: /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/g,
      category: "SECRET_TERM",
    },
  ],
};

/**
 * Validates and compiles a user-supplied regex with ReDoS safety checks
 * (max length, rejects nested quantifiers and backreferences).
 */
export function validateAndCompileCustomRegex(
  pattern: string
): { readonly ok: true; readonly regex: RegExp } | { readonly ok: false; readonly error: string } {
  const trimmed = pattern.trim();
  if (trimmed.length < 2) {
    return { ok: false, error: "Regex pattern must be at least 2 characters." };
  }
  if (trimmed.length > 120) {
    return { ok: false, error: "Regex pattern exceeds 120-character safety cap." };
  }
  if (/(\([^)]*[+*][^)]*\)\s*[+*?{])|([+*?]\s*[+*])|(\\[1-9])/.test(trimmed)) {
    return {
      ok: false,
      error: "ReDoS Guard rejected unsafe nested quantifier or backreference.",
    };
  }
  try {
    const regex = new RegExp(trimmed, "gi");
    return { ok: true, regex };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Invalid regular expression syntax.",
    };
  }
}

function runSafeRegex(
  text: string,
  regex: RegExp,
  category: EntityCategory,
  useGroup1 = false
): DetectedSpan[] {
  const spans: DetectedSpan[] = [];
  const rx = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`);
  let m: RegExpExecArray | null;
  let guard = 0;

  while ((m = rx.exec(text)) !== null && guard < 64) {
    guard += 1;
    if (m[0].length === 0) {
      rx.lastIndex += 1;
      continue;
    }
    if (useGroup1 && m[1]) {
      const val = m[1];
      const end = m.index + m[0].length;
      const start = end - val.length;
      if (val.length >= 3) {
        spans.push({ start, end, text: val, category, detectedBy: "GATE1_REGEX" });
      }
    } else if (m[0].length >= 3) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        category,
        detectedBy: "GATE1_REGEX",
      });
    }
  }
  return spans;
}

export function scanPolicyAsCodeSpans(
  text: string,
  enabledPacks: ReadonlyArray<CompliancePackId>,
  customRules: ReadonlyArray<CustomRegexRule>
): DetectedSpan[] {
  const spans: DetectedSpan[] = [];

  for (const packId of enabledPacks) {
    for (const p of PACK_PATTERNS[packId] ?? []) {
      spans.push(...runSafeRegex(text, p.regex, p.category, p.useGroup1));
    }
  }

  for (const rule of customRules) {
    if (!rule.enabled) continue;
    const compiled = validateAndCompileCustomRegex(rule.pattern);
    if (compiled.ok) {
      spans.push(...runSafeRegex(text, compiled.regex, rule.category, false));
    }
  }

  return spans;
}
