import type {
  AirlockReceipt,
  FirewallResult,
  FirewallViolation,
  PolicyProfile,
  RawDocument,
  VerifiedSanitizedPayload,
} from "./types.js";
import { AirlockVault, bytesToBase64 } from "./vault.js";

const encoder = new TextEncoder();
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060\uFEFF]/g;
const GENERIC_PARTIAL_WORDS = new Set([
  "associates", "capital", "center", "clinic", "codename", "corporation",
  "diagnostics", "enterprises", "foundry", "group", "health", "healthcare",
  "holdings", "hospital", "imaging", "industries", "limited", "logistics",
  "medical", "oncology", "operation", "partners", "project", "robotics",
  "solutions", "systems", "technologies", "ventures",
]);

export async function sha256Hex(input: string): Promise<string> {
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(input));
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64Utf8(input: string): string {
  return bytesToBase64(encoder.encode(input));
}

function toHexUtf8(input: string): string {
  return Array.from(encoder.encode(input))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function collapseAlnum(input: string): string {
  return input.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface VerifyAirlockOptions {
  readonly rawDoc: RawDocument;
  readonly candidateSanitized: string;
  readonly vault: AirlockVault;
  readonly policyProfile: PolicyProfile;
  readonly prevReceiptSha256?: string | null;
}

/**
 * Gate 3: Hard 6-Vector Pre-Flight Leak Firewall.
 * Verifies the outbound staging text against every vault secret across 6 adversarial vectors
 * and mints a SHA-256 hash-chained AirlockReceipt only on a 6/6 clean pass.
 */
export async function verifyAndMintPayload(
  options: VerifyAirlockOptions
): Promise<FirewallResult> {
  const {
    rawDoc,
    candidateSanitized,
    vault,
    policyProfile,
    prevReceiptSha256 = null,
  } = options;

  const violations: FirewallViolation[] = [];
  const lowerPayload = candidateSanitized.toLowerCase();
  const collapsedPayload = collapseAlnum(candidateSanitized);
  const nfkcCleanPayload = candidateSanitized
    .normalize("NFKC")
    .replace(ZERO_WIDTH_REGEX, "")
    .toLowerCase();
  const nfkcChanged = nfkcCleanPayload !== lowerPayload;

  const entries = vault.getEntries(true);

  for (const entry of entries) {
    const secret = entry.original;
    const lowerSecret = secret.toLowerCase();
    const nfkcSecret = secret.normalize("NFKC").replace(ZERO_WIDTH_REGEX, "").toLowerCase();

    // Vector 6: Canary Trap (checked first so prompt injection gets explicit classification)
    if (entry.category === "CANARY") {
      const b64Canary = toBase64Utf8(secret);
      const hexCanary = toHexUtf8(secret);
      if (
        lowerPayload.includes(lowerSecret) ||
        nfkcCleanPayload.includes(nfkcSecret) ||
        candidateSanitized.includes(b64Canary) ||
        lowerPayload.includes(hexCanary)
      ) {
        violations.push({
          vector: "CANARY_TRAP",
          token: entry.token,
          category: "CANARY",
          detail: "Prompt-injection canary leaked into outbound staging payload.",
        });
      }
      continue;
    }

    // Vector 1: Exact & case-insensitive leak
    if (lowerSecret.length >= 2 && lowerPayload.includes(lowerSecret)) {
      violations.push({
        vector: "EXACT_OR_CASE_INSENSITIVE",
        token: entry.token,
        category: entry.category,
        detail: `Raw ${entry.category} value escaped redaction.`,
      });
      continue;
    }

    // Vector 5: Unicode NFKC homoglyph or zero-width smuggling
    if (nfkcChanged && nfkcSecret.length >= 3 && nfkcCleanPayload.includes(nfkcSecret)) {
      violations.push({
        vector: "UNICODE_NFKC_OR_ZERO_WIDTH",
        token: entry.token,
        category: entry.category,
        detail: `Unicode homoglyph or zero-width obfuscated ${entry.category} detected.`,
      });
      continue;
    }

    // Vector 2: Punctuation / whitespace collapsed leak (e.g., 555-123-4567 -> 5551234567)
    const collapsedSecret = collapseAlnum(secret);
    if (collapsedSecret.length >= 6 && collapsedPayload.includes(collapsedSecret)) {
      violations.push({
        vector: "COLLAPSED_ALPHANUMERIC",
        token: entry.token,
        category: entry.category,
        detail: `Reformatted ${entry.category} sequence leaked after stripping punctuation.`,
      });
      continue;
    }

    // Vector 3: Partial-token / surname or last-6-digits leak
    if (entry.category === "PERSON" || entry.category === "ORG" || entry.category === "SECRET_TERM") {
      const allWords = secret.split(/\s+/);
      const parts = allWords.filter(
        (p) => p.length >= 5 && !GENERIC_PARTIAL_WORDS.has(p.toLowerCase())
      );
      if (allWords.length >= 2 && parts.length >= 1) {
        const leakedPart = parts.find((part) => {
          const rx = new RegExp(`\\b${escapeRegExp(part)}\\b`, "i");
          return rx.test(candidateSanitized);
        });
        if (leakedPart) {
          violations.push({
            vector: "PARTIAL_TOKEN_OR_SURNAME",
            token: entry.token,
            category: entry.category,
            detail: `Partial ${entry.category} token escaped redaction.`,
          });
          continue;
        }
      }
    } else if (
      (entry.category === "CARD_OR_ACCOUNT" || entry.category === "SSN" || entry.category === "PHONE") &&
      collapsedSecret.length >= 9
    ) {
      const tail6 = collapsedSecret.slice(-6);
      if (collapsedPayload.includes(tail6)) {
        violations.push({
          vector: "PARTIAL_TOKEN_OR_SURNAME",
          token: entry.token,
          category: entry.category,
          detail: `Trailing 6 digits of ${entry.category} escaped redaction.`,
        });
        continue;
      }
    }

    // Vector 4: Encoded exfiltration (Base64, URL-encoded, Hex)
    if (secret.length >= 4) {
      const b64 = toBase64Utf8(secret);
      const hex = toHexUtf8(secret);
      const urlEnc = encodeURIComponent(secret);
      const urlDiffers = urlEnc.toLowerCase() !== lowerSecret;

      if (
        candidateSanitized.includes(b64) ||
        lowerPayload.includes(hex) ||
        (urlDiffers && lowerPayload.includes(urlEnc.toLowerCase()))
      ) {
        violations.push({
          vector: "ENCODED_EXFILTRATION",
          token: entry.token,
          category: entry.category,
          detail: `Encoded (Base64/Hex/URL) exfiltration of ${entry.category} detected.`,
        });
      }
    }
  }

  if (violations.length > 0) {
    return {
      ok: false,
      violations,
      blockedBytes: encoder.encode(candidateSanitized).byteLength,
    };
  }

  // Mint tamper-evident SHA-256 Airlock Attestation Receipt
  const timestampIso = new Date().toISOString();
  const rawDocSha256 = await sha256Hex(rawDoc);
  const sanitizedPayloadSha256 = await sha256Hex(candidateSanitized);
  const redactedCount = vault.getEntries(false).length;

  const receiptPreimage = JSON.stringify({
    receiptVersion: "airlock.v1",
    rawDocSha256,
    sanitizedPayloadSha256,
    prevReceiptSha256,
    redactedCount,
    policyProfile,
    timestampIso,
  });
  const receiptSha256 = await sha256Hex(receiptPreimage);

  const receipt: AirlockReceipt = {
    receiptVersion: "airlock.v1",
    rawDocSha256,
    sanitizedPayloadSha256,
    prevReceiptSha256,
    receiptSha256,
    redactedCount,
    checksPassed: 6,
    firewallPassed: true,
    policyProfile,
    timestampIso,
  };

  const payload = {
    sanitizedText: candidateSanitized,
    entitySummary: vault.getEntries(false).map((e) => ({
      token: e.token,
      category: e.category,
    })),
    receipt,
  } as unknown as VerifiedSanitizedPayload;

  return { ok: true, payload };
}
