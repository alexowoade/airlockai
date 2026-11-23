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

interface PatternRule {
  readonly category: EntityCategory;
  readonly regex: RegExp;
  readonly validate?: (matchText: string) => boolean;
}

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
];

export function scanDeterministicPii(rawDoc: RawDocument): ReadonlyArray<DetectedSpan> {
  const candidates: DetectedSpan[] = [];

  for (const rule of GATE1_RULES) {
    const rx = new RegExp(rule.regex.source, rule.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = rx.exec(rawDoc)) !== null) {
      const text = match[0];
      if (!rule.validate || rule.validate(text)) {
        candidates.push({
          start: match.index,
          end: match.index + text.length,
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
