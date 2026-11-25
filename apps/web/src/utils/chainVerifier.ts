import { sha256Hex, type AirlockReceipt, type VerifiedSanitizedPayload } from "@airlock/core";
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

export interface ExternalProofAuditReport {
  readonly ok: boolean;
  readonly fileName: string;
  readonly projectId: string;
  readonly exportedAtIso: string;
  readonly zeroPiiClean: boolean;
  readonly piiFindings: ReadonlyArray<string>;
  readonly chainReport: ChainVerificationReport;
  readonly verdict: string;
}

/**
 * Cryptographically recomputes every receiptSha256 and verifies prevReceiptSha256 linkage
 * across the audit ledger (walks oldest -> newest).
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
      detail: "No audit receipts in ledger yet. Run a Deep Cloud Audit or Queue Offline Receipt to mint Link #1.",
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
 * Independent, 100% offline auditor for any exported AirlockAI.ZeroPiiComplianceProof JSON file.
 * Verifies schema, zero raw PII leakage, every SHA-256 receipt preimage, and prevReceiptSha256 linkage.
 */
export async function verifyExternalProofJson(
  fileName: string,
  rawJsonText: string
): Promise<ExternalProofAuditReport> {
  const emptyChain: ChainVerificationReport = {
    ok: false,
    totalLinks: 0,
    verifiedHashes: 0,
    verifiedLinks: 0,
    brokenLinkNumber: null,
    expectedHash: null,
    actualHash: null,
    detail: "No valid ledgerHistory found in certificate.",
  };

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(rawJsonText) as Record<string, unknown>;
  } catch {
    return {
      ok: false,
      fileName,
      projectId: "unknown",
      exportedAtIso: "unknown",
      zeroPiiClean: false,
      piiFindings: ["File is not valid JSON."],
      chainReport: emptyChain,
      verdict: "EXTERNAL PROOF REJECTED — Invalid JSON certificate.",
    };
  }

  const certType = String(parsed.certificateType ?? "");
  const proto = String(parsed.protocolVersion ?? "");
  const projectId = String(parsed.firebaseProjectId ?? "unknown");
  const exportedAtIso = String(parsed.exportedAtIso ?? "unknown");

  if (certType !== "AirlockAI.ZeroPiiComplianceProof" || proto !== "airlock.v1") {
    return {
      ok: false,
      fileName,
      projectId,
      exportedAtIso,
      zeroPiiClean: false,
      piiFindings: [`Unexpected certificateType (${certType || "missing"}) or protocolVersion (${proto || "missing"}).`],
      chainReport: emptyChain,
      verdict: "EXTERNAL PROOF REJECTED — Unrecognized certificate schema.",
    };
  }

  // Zero-PII scan over the entire exported JSON certificate
  const piiFindings: string[] = [];
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(rawJsonText)) {
    piiFindings.push("Raw email pattern detected in certificate JSON.");
  }
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(rawJsonText)) {
    piiFindings.push("Raw SSN pattern detected in certificate JSON.");
  }
  if (/\b(?:\d{4}[- ]?){3}\d{4}\b/.test(rawJsonText)) {
    piiFindings.push("Raw 16-digit card pattern detected in certificate JSON.");
  }
  if (/\b(?:sk-live-|AIza[0-9A-Za-z_-]{10,}|ghp_[0-9A-Za-z]{10,})/.test(rawJsonText)) {
    piiFindings.push("Raw API secret prefix detected in certificate JSON.");
  }

  let attestationChecked = false;
  let attestationError: string | null = null;
  if (parsed.activeSessionAttestation !== null && parsed.activeSessionAttestation !== undefined) {
    if (typeof parsed.activeSessionAttestation !== "object") {
      attestationError = "activeSessionAttestation is malformed.";
    } else {
      const att = parsed.activeSessionAttestation as { receipt?: Partial<AirlockReceipt> };
      const rec = att.receipt;
      if (!rec || typeof rec !== "object" || typeof rec.receiptSha256 !== "string") {
        attestationError = "activeSessionAttestation.receipt is missing or malformed.";
      } else if (rec.firewallPassed !== true || rec.checksPassed !== 6) {
        attestationError = "activeSessionAttestation.receipt failed 6/6 firewall assertion.";
      } else {
        const preimage = JSON.stringify({
          receiptVersion: rec.receiptVersion,
          rawDocSha256: rec.rawDocSha256,
          sanitizedPayloadSha256: rec.sanitizedPayloadSha256,
          prevReceiptSha256: rec.prevReceiptSha256 ?? null,
          redactedCount: rec.redactedCount,
          policyProfile: rec.policyProfile,
          timestampIso: rec.timestampIso,
        });
        const recomputed = await sha256Hex(preimage);
        if (recomputed !== rec.receiptSha256) {
          attestationError = `ACTIVE SESSION ATTESTATION TAMPERED: Recomputed SHA-256 (${recomputed.slice(0, 14)}…) does not match stored receipt (${rec.receiptSha256.slice(0, 14)}…).`;
        } else {
          attestationChecked = true;
        }
      }
    }
  }

  const rawHistory = Array.isArray(parsed.ledgerHistory) ? (parsed.ledgerHistory as LedgerRecord[]) : [];
  const chainReport = await verifyLedgerChain(rawHistory);
  const zeroPiiClean = piiFindings.length === 0 && parsed.containsRawPii === false;
  const ok = zeroPiiClean && attestationError === null && chainReport.ok && rawHistory.length > 0;

  const verdict = ok
    ? `EXTERNAL PROOF VERIFIED OFFLINE — ${chainReport.verifiedHashes}/${chainReport.totalLinks} SHA-256 receipts & ${chainReport.verifiedLinks}/${Math.max(0, chainReport.totalLinks - 1)} chain links${attestationChecked ? " + active session attestation" : ""} intact · Zero raw PII detected.`
    : !zeroPiiClean
      ? `EXTERNAL PROOF REJECTED — Raw PII violation (${piiFindings.join(" ")})`
      : attestationError !== null
        ? `EXTERNAL PROOF REJECTED — ${attestationError}`
        : rawHistory.length === 0
          ? "EXTERNAL PROOF INCOMPLETE — Certificate contains 0 ledger receipts."
          : `EXTERNAL PROOF REJECTED — ${chainReport.detail}`;

  return {
    ok,
    fileName,
    projectId,
    exportedAtIso,
    zeroPiiClean,
    piiFindings,
    chainReport,
    verdict,
  };
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
