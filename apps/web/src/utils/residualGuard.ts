import type { DetectedSpan } from "@airlock/core";

export type QuasiIdentifierKind = "URL" | "IP_ADDRESS" | "ZIP_CODE" | "DOC_ID";

export interface QuasiIdentifierHit {
  readonly kind: QuasiIdentifierKind;
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

export type ResidualRiskLevel = "LOW" | "MODERATE" | "ELEVATED";

export interface ResidualRiskReport {
  readonly riskLevel: ResidualRiskLevel;
  readonly residualProperNouns: ReadonlyArray<string>;
  readonly quasiIdentifiers: ReadonlyArray<QuasiIdentifierHit>;
  readonly failClosedRecommended: boolean;
  readonly summary: string;
}

const COMMON_CAPITALIZED_WORDS = new Set([
  "a", "account", "agreement", "all", "amount", "an", "and", "annex", "any",
  "appendix", "article", "assignment", "attorney", "authorized", "balance",
  "bank", "beneficiary", "between", "billed", "billing", "by", "california",
  "clause", "client", "clinic", "code", "codename", "company", "confidential",
  "confidentiality", "contact", "contract", "counsel", "court", "courts",
  "critical", "date", "days", "delaware", "department", "diagnosis", "director",
  "discloser", "discloser's", "disclosure", "dispute", "doctor", "document",
  "due", "effective", "email", "employee", "engineer", "escrow", "eu", "exhibit",
  "facility", "fee", "final", "finance", "financial", "floor", "follow", "for",
  "from", "general", "governing", "group", "headquarters", "health", "healthcare",
  "high", "hipaa", "hospital", "iban", "immediately", "in", "indemnity",
  "information", "instructions", "insurance", "intellectual", "invoice", "ip",
  "item", "january", "february", "march", "april", "may", "june", "july",
  "august", "september", "october", "november", "december", "jurisdiction",
  "key", "law", "lead", "legal", "liability", "license", "licensing", "limited",
  "low", "manager", "master", "medical", "medium", "mutual", "nda", "net", "new",
  "no", "non", "note", "notice", "number", "of", "officer", "on", "operation",
  "or", "order", "page", "panel", "partner", "party", "patient", "patient's",
  "payable", "payment", "penalty", "perpetual", "person", "personnel", "phone",
  "plan", "policy", "portal", "pricing", "primary", "prior", "privacy", "project",
  "property", "receiver", "recipient", "recipient's", "record", "ref",
  "remittance", "report", "representative", "review", "routing", "schedule",
  "schematics", "section", "secure", "security", "sender", "service", "services",
  "settlement", "signer", "solicit", "ssn", "stage", "state", "statement",
  "states", "strict", "subject", "summary", "swift", "tax", "term", "terms",
  "texas", "the", "this", "to", "total", "type", "uk", "under", "united",
  "unpaid", "url", "us", "usa", "vendor", "wire", "with", "within", "york", "zip",

  // Localized German/French/Spanish legal nouns (prevents false proper-noun locks on EU contracts)
  "anlage", "auftraggeber", "auftragnehmer", "gegenstand", "entwicklung", "preisobergrenze",
  "vergütung", "zahlungsweg", "überweisung", "haftung", "empfänger", "übertragung", "rechte",
  "kontakt", "unterzeichner", "geheimhaltungsvereinbarung", "annexe", "client", "prestataire",
  "signataire", "objet", "plafond", "compte", "responsabilité", "orden", "emisor", "receptor",
  "firmante", "referencia", "importe", "cuenta", "cláusula", "caller", "counterparty",
  "engagement", "reference", "instructed", "transfer", "audit", "warning", "voice", "memo",
  "executive", "treasury", "call",
]);

/**
 * Scans raw text for HIPAA Safe Harbor quasi-identifiers (URLs, IPv4, US ZIP codes,
 * and invoice/MRN/case reference IDs).
 */
export function scanQuasiIdentifiers(text: string): QuasiIdentifierHit[] {
  const hits: QuasiIdentifierHit[] = [];
  const rules: Array<{ kind: QuasiIdentifierKind; regex: RegExp }> = [
    { kind: "URL", regex: /https?:\/\/[^\s)>"']+/gi },
    { kind: "IP_ADDRESS", regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
    { kind: "DOC_ID", regex: /\b(?:INV|MRN|CASE|REF|ACCT|PO)-[A-Z0-9-]{4,20}\b/gi },
    { kind: "ZIP_CODE", regex: /\b(?:ZIP|Postal|CA|NY|TX|FL|WA|MA|IL)\s*:?\s*(\d{5}(?:-\d{4})?)\b/gi },
  ];

  for (const rule of rules) {
    const rx = new RegExp(rule.regex.source, rule.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      if (rule.kind === "ZIP_CODE" && m[1]) {
        const val = m[1];
        const end = m.index + m[0].length;
        const start = end - val.length;
        hits.push({ kind: rule.kind, text: val, start, end });
      } else {
        hits.push({
          kind: rule.kind,
          text: m[0],
          start: m.index,
          end: m.index + m[0].length,
        });
      }
    }
  }
  return hits;
}

export function quasiHitsToSpans(text: string): DetectedSpan[] {
  return scanQuasiIdentifiers(text).map((h) => ({
    start: h.start,
    end: h.end,
    text: h.text,
    category: "SECRET_TERM",
    detectedBy: "GATE1_REGEX",
  }));
}

/**
 * Post-Gate-1/2 residual analyzer:
 * Detects unexpected mid-sentence capitalized proper nouns and remaining HIPAA Safe Harbor
 * quasi-identifiers in the sanitized skeleton.
 */
export function analyzeResidualRisks(
  sanitizedText: string,
  nanoUsed: boolean
): ResidualRiskReport {
  const withoutTokens = sanitizedText.replace(/\[[A-Z_]+_\d+\]/g, " ");
  const quasiIdentifiers = scanQuasiIdentifiers(withoutTokens);

  const properNounSet = new Set<string>();
  const sentences = withoutTokens.split(/(?:[.!?\n]+|\s{2,})/);
  for (const sentence of sentences) {
    const trimmed = sentence.trim();
    if (!trimmed) continue;
    const words = trimmed.split(/\s+/);
    for (let i = 1; i < words.length; i++) {
      const rawWord = words[i] ?? "";
      const cleaned = rawWord.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9'-]+$/g, "");
      if (cleaned.length < 3) continue;
      if (!/^[A-Z][a-z]{2,}(?:[-'][A-Z][a-z]+)?$/.test(cleaned)) continue;
      if (COMMON_CAPITALIZED_WORDS.has(cleaned.toLowerCase())) continue;
      const prev = words[i - 1] ?? "";
      if (/^\d+\.$/.test(prev)) continue;
      properNounSet.add(cleaned);
    }
  }

  const residualProperNouns = Array.from(properNounSet).slice(0, 12);
  const totalFlags = residualProperNouns.length + quasiIdentifiers.length;

  let riskLevel: ResidualRiskLevel = "LOW";
  if (residualProperNouns.length >= 2 || totalFlags >= 3) {
    riskLevel = "ELEVATED";
  } else if (totalFlags >= 1) {
    riskLevel = "MODERATE";
  }

  const failClosedRecommended = !nanoUsed && residualProperNouns.length > 0;
  const summary =
    totalFlags === 0
      ? "Zero residual proper nouns or HIPAA Safe Harbor quasi-identifiers detected."
      : `${residualProperNouns.length} unredacted proper noun(s) and ${quasiIdentifiers.length} quasi-identifier(s) remain in skeleton.`;

  return {
    riskLevel,
    residualProperNouns,
    quasiIdentifiers,
    failClosedRecommended,
    summary,
  };
}
