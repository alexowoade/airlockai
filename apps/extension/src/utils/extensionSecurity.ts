import {
  bytesToBase64,
  type DetectedSpan,
  type PolicyProfile,
  type VaultEntry,
} from "@airlock/core";

export interface ExtensionResidualReport {
  readonly riskLevel: "LOW" | "MODERATE" | "ELEVATED";
  readonly residualProperNouns: ReadonlyArray<string>;
  readonly quasiCount: number;
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
]);

export function scanSafeHarborSpans(text: string): DetectedSpan[] {
  const spans: DetectedSpan[] = [];
  const rules: Array<{ isZip?: boolean; regex: RegExp }> = [
    { regex: /https?:\/\/[^\s)>"']+/gi },
    { regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
    { regex: /\b(?:INV|MRN|CASE|REF|ACCT|PO)-[A-Z0-9-]{4,20}\b/gi },
    { isZip: true, regex: /\b(?:ZIP|Postal|CA|NY|TX|FL|WA|MA|IL)\s*:?\s*(\d{5}(?:-\d{4})?)\b/gi },
  ];

  for (const rule of rules) {
    const rx = new RegExp(rule.regex.source, rule.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      if (rule.isZip && m[1]) {
        const val = m[1];
        const end = m.index + m[0].length;
        spans.push({
          start: end - val.length,
          end,
          text: val,
          category: "SECRET_TERM",
          detectedBy: "GATE1_REGEX",
        });
      } else {
        spans.push({
          start: m.index,
          end: m.index + m[0].length,
          text: m[0],
          category: "SECRET_TERM",
          detectedBy: "GATE1_REGEX",
        });
      }
    }
  }
  return spans;
}

export function analyzeExtensionResidualRisks(
  sanitizedText: string,
  nanoUsed: boolean
): ExtensionResidualReport {
  const withoutTokens = sanitizedText.replace(/\[[A-Z_]+_\d+\]/g, " ");
  const quasiCount = scanSafeHarborSpans(withoutTokens).length;

  const properSet = new Set<string>();
  const sentences = withoutTokens.split(/(?:[.!?\n]+|\s{2,})/);
  for (const sentence of sentences) {
    const trimmed = sentence.trim();
    if (!trimmed) continue;
    const words = trimmed.split(/\s+/);
    for (let i = 1; i < words.length; i++) {
      const cleaned = (words[i] ?? "").replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9'-]+$/g, "");
      if (cleaned.length < 3) continue;
      if (!/^[A-Z][a-z]{2,}(?:[-'][A-Z][a-z]+)?$/.test(cleaned)) continue;
      if (COMMON_CAPITALIZED_WORDS.has(cleaned.toLowerCase())) continue;
      if (/^\d+\.$/.test(words[i - 1] ?? "")) continue;
      properSet.add(cleaned);
    }
  }

  const residualProperNouns = Array.from(properSet).slice(0, 10);
  const totalFlags = residualProperNouns.length + quasiCount;

  let riskLevel: "LOW" | "MODERATE" | "ELEVATED" = "LOW";
  if (residualProperNouns.length >= 2 || totalFlags >= 3) {
    riskLevel = "ELEVATED";
  } else if (totalFlags >= 1) {
    riskLevel = "MODERATE";
  }

  const failClosedRecommended = !nanoUsed && residualProperNouns.length > 0;
  const summary =
    totalFlags === 0
      ? "Zero residual proper nouns or Safe Harbor quasi-identifiers."
      : `${residualProperNouns.length} proper noun(s) and ${quasiCount} quasi-identifier(s) remain.`;

  return {
    riskLevel,
    residualProperNouns,
    quasiCount,
    failClosedRecommended,
    summary,
  };
}

function toArrayBufferBytes(str: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(str);
  const copy = new Uint8Array(encoded.byteLength);
  copy.set(encoded);
  return copy;
}

/**
 * Exports a PBKDF2-SHA256 (100k) + AES-256-GCM .airlock.enc vault file that is 100%
 * interoperable with the AirlockAI Web PWA (AirlockAI.EncryptedVault.v1).
 */
export async function exportCrossSurfaceEncryptedVault(params: {
  passphrase: string;
  policyProfile: PolicyProfile;
  receiptSha256: string;
  entries: ReadonlyArray<VaultEntry>;
  sanitizedText: string;
  sanitizedAuditMarkdown: string | null;
}): Promise<{ readonly json: string; readonly entryCount: number }> {
  const trimmed = params.passphrase.trim();
  if (trimmed.length < 6) {
    throw new Error("Passphrase must be at least 6 characters.");
  }

  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);

  const exportedAtIso = new Date().toISOString();
  const cleanEntries = params.entries.filter((e) => e.category !== "CANARY");
  const payload = {
    vaultVersion: "airlock.vault.v1",
    exportedAtIso,
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entries: cleanEntries,
    sanitizedText: params.sanitizedText,
    sanitizedAuditMarkdown: params.sanitizedAuditMarkdown,
  };

  const keyMaterial = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBufferBytes(trimmed),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await globalThis.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const encryptedBuf = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    toArrayBufferBytes(JSON.stringify(payload))
  );

  const envelope = {
    format: "AirlockAI.EncryptedVault.v1",
    kdf: "PBKDF2-SHA256",
    iterations: 100000,
    cipher: "AES-256-GCM",
    exportedAtIso,
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entryCount: cleanEntries.length,
    saltBase64: bytesToBase64(salt),
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(encryptedBuf)),
  };

  return { json: JSON.stringify(envelope, null, 2), entryCount: cleanEntries.length };
}
