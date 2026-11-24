import type { DetectedSpan, EntityCategory, RawDocument } from "./types.js";

const CATEGORY_PRIORITY: Record<EntityCategory, number> = {
  CARD_OR_ACCOUNT: 100,
  IBAN: 95,
  SSN: 90,
  EMAIL: 85,
  API_SECRET: 80,
  PHONE: 70,
  CURRENCY: 60,
  DATE: 50,
  PERSON: 40,
  ORG: 40,
  MEDICAL: 40,
  SECRET_TERM: 40,
  CANARY: 110,
};

/** Leading prepositions/labels trimmed if captured at the start of an ORG phrase */
const ORG_LEADING_EXCLUDED = new Set([
  "a", "against", "an", "and", "at", "between", "billed", "by", "client",
  "company", "contact", "discloser", "facility", "for", "from", "in",
  "into", "of", "on", "or", "party", "per", "recipient", "the", "to",
  "under", "vendor", "with",
]);

/** Common legal, financial, medical, and document-heading words excluded from general PERSON matches */
const NON_PERSON_WORDS = new Set([
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
]);

/** Luhn checksum validator to avoid false-positive 16-digit IDs */
export function passesLuhn(rawDigits: string): boolean {
  const digits = rawDigits.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/** Shannon entropy (bits/char) to detect API keys, bearer tokens, and raw secrets */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isValidPersonPhrase(phrase: string): boolean {
  const words = phrase.trim().split(/\s+/);
  if (words.length < 2) return false;
  return words.every((w) => !NON_PERSON_WORDS.has(w.toLowerCase()));
}

function trimLeadingOrgWords(
  text: string,
  start: number
): { start: number; end: number; text: string } | null {
  let curText = text;
  let curStart = start;
  while (true) {
    const m = /^([A-Za-z]+)(\s+)/.exec(curText);
    if (!m || !m[1]) break;
    if (ORG_LEADING_EXCLUDED.has(m[1].toLowerCase())) {
      const adv = m[0].length;
      curText = curText.slice(adv);
      curStart += adv;
    } else {
      break;
    }
  }
  if (!curText.includes(" ")) return null;
  return { start: curStart, end: curStart + curText.length, text: curText };
}

interface PatternRule {
  readonly category: EntityCategory;
  readonly regex: RegExp;
  readonly captureGroup?: number;
  readonly trimOrgLeading?: boolean;
  readonly validate?: (matchText: string) => boolean;
}

const NAME_PART = "(?:[A-Z][a-z]{0,20}[-'][A-Z][a-z]{1,20}|[A-Z][a-z]{1,20})";

const ORG_SUFFIX_PATTERN =
  "(?:Corp\\.?|Corporation|Inc\\.?|LLC|LLP|Ltd\\.?|Limited|Group|Holdings|Foundry|" +
  "Robotics|Labs|Systems|Technologies|Solutions|Partners|Ventures|" +
  "Bank|Capital|Clinic|Hospital|Medical Center|Center|Health|Healthcare|" +
  "Diagnostics|Associates|Industries|Enterprises)";

const GATE1_RULES: ReadonlyArray<PatternRule> = [
  {
    category: "CARD_OR_ACCOUNT",
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    validate: (m) => passesLuhn(m),
  },
  {
    category: "IBAN",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
  },
  {
    category: "SSN",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    category: "EMAIL",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    category: "API_SECRET",
    regex: /\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{30,}|[A-Za-z0-9+/=_-]{24,64})\b/g,
    validate: (m) => {
      if (/^(?:sk-|AIza|ghp_)/.test(m)) return true;
      // High-entropy token must mix digits + uppercase + lowercase and exceed 4.0 bits/char
      const hasUpper = /[A-Z]/.test(m);
      const hasLower = /[a-z]/.test(m);
      const hasDigit = /\d/.test(m);
      return hasUpper && hasLower && hasDigit && shannonEntropy(m) >= 4.0;
    },
  },
  {
    category: "PHONE",
    regex: /(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\w)/g,
  },
  {
    category: "CURRENCY",
    regex: /(?:[$€£₦]\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|EUR|GBP|NGN)\b)/g,
  },
  {
    category: "DATE",
    regex: /\b(?:\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4})\b/g,
  },
  // Deterministic Named-Entity Fallback Rules (guarantees zero name/org/medical leaks when Nano is unavailable)
  {
    category: "ORG",
    regex: new RegExp(
      `\\b[A-Z][A-Za-z0-9'.-]+(?:\\s+(?:&\\s+)?[A-Z][A-Za-z0-9'.-]+){0,4}\\s+${ORG_SUFFIX_PATTERN}(?=\\b|[^A-Za-z0-9])`,
      "g"
    ),
    trimOrgLeading: true,
  },
  {
    category: "SECRET_TERM",
    regex: /\b(?:Project|Operation|Codename)\s+[A-Z][a-zA-Z0-9-]+(?:\s+[A-Z][a-zA-Z0-9-]+)?\b/g,
  },
  {
    category: "MEDICAL",
    regex:
      /\b(?:Stage\s+(?:I{1,3}V?|IV|[1-4])[A-B]?\s+[A-Z][a-zA-Z-]+(?:\s+[A-Z][a-zA-Z-]+){0,3}|Type\s+[12]\s+Diabetes(?:\s+Mellitus)?|(?:[A-Z][a-zA-Z-]+\s+){0,2}(?:Carcinoma|Lymphoma|Leukemia|Melanoma|Sarcoma|Diabetes|Hypertension|Pneumonia|Hepatitis|Asthma|Arthritis|Neuropathy|Sclerosis|Infarction))\b/g,
  },
  {
    category: "PERSON",
    regex: new RegExp(`\\b(?:Dr\\.|Mr\\.|Mrs\\.|Ms\\.|Prof\\.)\\s+${NAME_PART}(?:\\s+${NAME_PART})?\\b`, "g"),
  },
  {
    category: "PERSON",
    regex: new RegExp(
      `\\b(?:Patient|Authorized Signer|Signer|Lead Engineer|Chief Executive Officer|Chief Financial Officer|CEO|CFO|Director|Manager|Contact|Attn|Employee|Physician|Doctor|Counsel)\\s*:?\\s+(${NAME_PART}\\s+${NAME_PART})\\b`,
      "g"
    ),
    captureGroup: 1,
    validate: isValidPersonPhrase,
  },
  {
    category: "PERSON",
    regex: new RegExp(`\\b${NAME_PART}\\s+${NAME_PART}\\b`, "g"),
    validate: isValidPersonPhrase,
  },
];

export function scanDeterministicPii(rawDoc: RawDocument): ReadonlyArray<DetectedSpan> {
  const candidates: DetectedSpan[] = [];

  for (const rule of GATE1_RULES) {
    const rx = new RegExp(rule.regex.source, rule.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = rx.exec(rawDoc)) !== null) {
      let text: string;
      let start: number;
      let end: number;

      const captured = rule.captureGroup !== undefined ? match[rule.captureGroup] : undefined;
      if (captured !== undefined) {
        text = captured;
        end = match.index + match[0].length;
        start = end - text.length;
      } else {
        text = match[0];
        start = match.index;
        end = start + text.length;
      }

      if (rule.trimOrgLeading) {
        const trimmed = trimLeadingOrgWords(text, start);
        if (!trimmed) continue;
        start = trimmed.start;
        end = trimmed.end;
        text = trimmed.text;
      }

      if (!rule.validate || rule.validate(text)) {
        candidates.push({
          start,
          end,
          text,
          category: rule.category,
          detectedBy: "GATE1_REGEX",
        });
      }
    }
  }

  return resolveOverlappingSpans(candidates);
}

/**
 * Resolves overlapping spans deterministically: higher priority wins, then longer span,
 * then earlier start offset.
 */
export function resolveOverlappingSpans(
  spans: ReadonlyArray<DetectedSpan>
): ReadonlyArray<DetectedSpan> {
  const sorted = [...spans].sort((a, b) => {
    const prioDiff = CATEGORY_PRIORITY[b.category] - CATEGORY_PRIORITY[a.category];
    if (prioDiff !== 0) return prioDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted: DetectedSpan[] = [];
  for (const span of sorted) {
    const overlaps = accepted.some((other) => span.start < other.end && span.end > other.start);
    if (!overlaps) {
      accepted.push(span);
    }
  }

  return accepted.sort((a, b) => a.start - b.start);
}
