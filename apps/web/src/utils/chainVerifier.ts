import { sha256Hex, type VerifiedSanitizedPayload } from "@airlock/core";
import type { LedgerRecord } from "../services/firebase.js";

export interface ChainVerificationReport {
  readonly ok: boolean;
  readonly totalLinks: number;
  readonly verifiedHashes: number;
  readonly verifiedLinks: number;
  readonly brokenLinkNumber: number | null;
  readonly expectedHash: string | null;
  readonly actualHash: string | null;
  readonly detail: string;
}

/**
 * Cryptographically recomputes every receiptSha256 and verifies prevReceiptSha256 linkage
 * across the Firestore audit ledger (walks oldest -> newest).
 */
export async function verifyLedgerChain(
  recordsNewestFirst: ReadonlyArray<LedgerRecord>
): Promise<ChainVerificationReport> {
  const totalLinks = recordsNewestFirst.length;
  if (totalLinks === 0) {
    return {
      ok: true,
      totalLinks: 0,
      verifiedHashes: 0,
      verifiedLinks: 0,
      brokenLinkNumber: null,
      expectedHash: null,
      actualHash: null,
      detail: "No audit receipts in ledger yet. Run a Deep Cloud Audit to mint Genesis Link #1.",
    };
  }

  const chronological = [...recordsNewestFirst].reverse();
  let verifiedHashes = 0;
  let verifiedLinks = 0;

  for (let i = 0; i < chronological.length; i++) {
    const entry = chronological[i]!;
    const linkNumber = i + 1;

    const preimage = JSON.stringify({
      receiptVersion: entry.receiptVersion,
      rawDocSha256: entry.rawDocSha256,
      sanitizedPayloadSha256: entry.sanitizedPayloadSha256,
      prevReceiptSha256: entry.prevReceiptSha256,
      redactedCount: entry.redactedCount,
      policyProfile: entry.policyProfile,
      timestampIso: entry.timestampIso,
    });

    const recomputed = await sha256Hex(preimage);
    if (recomputed !== entry.receiptSha256) {
      return {
        ok: false,
        totalLinks,
        verifiedHashes,
        verifiedLinks,
        brokenLinkNumber: linkNumber,
        expectedHash: recomputed,
        actualHash: entry.receiptSha256,
        detail: `TAMPER DETECTED AT LINK #${linkNumber}: Recomputed SHA-256 (${recomputed.slice(0, 14)}…) does not match stored receipt (${entry.receiptSha256.slice(0, 14)}…).`,
      };
    }
    verifiedHashes += 1;

    if (i > 0) {
      const prev = chronological[i - 1]!;
      if (entry.prevReceiptSha256 !== prev.receiptSha256) {
        return {
          ok: false,
          totalLinks,
          verifiedHashes,
          verifiedLinks,
          brokenLinkNumber: linkNumber,
          expectedHash: prev.receiptSha256,
          actualHash: entry.prevReceiptSha256 ?? "null",
          detail: `CHAIN BREAK AT LINK #${linkNumber}: prevReceiptSha256 (${(entry.prevReceiptSha256 ?? "null").slice(0, 14)}…) does not link to Link #${linkNumber - 1} (${prev.receiptSha256.slice(0, 14)}…).`,
        };
      }
      verifiedLinks += 1;
    }
  }

  const genesisStatus =
    chronological[0]!.prevReceiptSha256 === null ? "Genesis anchored" : "Window anchored";
  return {
    ok: true,
    totalLinks,
    verifiedHashes,
    verifiedLinks,
    brokenLinkNumber: null,
    expectedHash: null,
    actualHash: null,
    detail: `CHAIN VERIFIED (${verifiedHashes}/${totalLinks} SHA-256 hashes intact, ${verifiedLinks}/${Math.max(0, totalLinks - 1)} chain links verified · ${genesisStatus}).`,
  };
}

/**
 * Mutates a single hex character in memory on the latest receipt to prove the verifier
 * immediately detects even 1-byte tampering.
 */
export function simulateOneByteTamper(
  recordsNewestFirst: ReadonlyArray<LedgerRecord>
): LedgerRecord[] {
  if (recordsNewestFirst.length === 0) return [];
  const head = recordsNewestFirst[0]!;
  const firstChar = head.rawDocSha256[0] ?? "0";
  const flippedChar = firstChar === "0" ? "1" : "0";
  const tamperedHead: LedgerRecord = {
    ...head,
    rawDocSha256: `${flippedChar}${head.rawDocSha256.slice(1)}`,
  };
  return [tamperedHead, ...recordsNewestFirst.slice(1)];
}

/**
 * Triggers a clean local file download in the browser (zero network traffic).
 */
export function triggerLocalDownload(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Triggers a local PNG download from an already-redacted Canvas data URL.
 */
export function triggerDataUrlDownload(filename: string, dataUrl: string): void {
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/**
 * Builds a zero-PII JSON compliance certificate suitable for legal/security archiving.
 */
export function buildComplianceProofJson(params: {
  projectId: string;
  verifiedPayload: VerifiedSanitizedPayload | null;
  ledger: ReadonlyArray<LedgerRecord>;
  verification: ChainVerificationReport | null;
}): string {
  const bundle = {
    certificateType: "AirlockAI.ZeroPiiComplianceProof",
    protocolVersion: "airlock.v1",
    exportedAtIso: new Date().toISOString(),
    firebaseProjectId: params.projectId,
    containsRawPii: false,
    activeSessionAttestation: params.verifiedPayload
      ? {
          receipt: params.verifiedPayload.receipt,
          redactedTokens: params.verifiedPayload.entitySummary,
        }
      : null,
    chainVerification: params.verification,
    ledgerHistory: params.ledger.map((item) => ({
      docId: item.docId,
      receiptVersion: item.receiptVersion,
      policyProfile: item.policyProfile,
      riskLevel: item.riskLevel,
      inferenceSource: item.inferenceSource,
      redactedCount: item.redactedCount,
      checksPassed: item.checksPassed,
      firewallPassed: item.firewallPassed,
      timestampIso: item.timestampIso,
      receiptSha256: item.receiptSha256,
      prevReceiptSha256: item.prevReceiptSha256,
      rawDocSha256: item.rawDocSha256,
      sanitizedPayloadSha256: item.sanitizedPayloadSha256,
      sanitizedSummary: item.sanitizedSummary,
    })),
  };
  return JSON.stringify(bundle, null, 2);
}
