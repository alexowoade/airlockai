import { writeZeroPiiAuditLedger, type LedgerEntry, type LedgerRecord } from "../services/firebase.js";

const STORAGE_KEY = "airlock_offline_ledger_queue_v1";

export interface PendingLedgerRecord extends LedgerRecord {
  readonly syncStatus: "PENDING_SYNC";
}

function toStrictLedgerEntry(entry: LedgerEntry): LedgerEntry {
  return {
    receiptVersion: entry.receiptVersion,
    rawDocSha256: entry.rawDocSha256,
    sanitizedPayloadSha256: entry.sanitizedPayloadSha256,
    prevReceiptSha256: entry.prevReceiptSha256,
    receiptSha256: entry.receiptSha256,
    redactedCount: entry.redactedCount,
    checksPassed: entry.checksPassed,
    firewallPassed: entry.firewallPassed,
    policyProfile: entry.policyProfile,
    inferenceSource: entry.inferenceSource,
    riskLevel: entry.riskLevel,
    sanitizedSummary: entry.sanitizedSummary,
    timestampIso: entry.timestampIso,
  };
}

export function loadPendingQueue(): PendingLedgerRecord[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is PendingLedgerRecord =>
        typeof item === "object" &&
        item !== null &&
        typeof (item as PendingLedgerRecord).receiptSha256 === "string" &&
        (item as PendingLedgerRecord).receiptSha256.length === 64
    );
  } catch {
    return [];
  }
}

export function savePendingQueue(records: ReadonlyArray<PendingLedgerRecord>): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
  } catch {
    // Storage quota or private mode fallback
  }
}

export function enqueueOfflineReceipt(entry: LedgerEntry): {
  readonly added: boolean;
  readonly queue: PendingLedgerRecord[];
} {
  const existing = loadPendingQueue();
  if (existing.some((item) => item.receiptSha256 === entry.receiptSha256)) {
    return { added: false, queue: existing };
  }
  const clean = toStrictLedgerEntry(entry);
  const record: PendingLedgerRecord = {
    ...clean,
    docId: `pending-${clean.receiptSha256.slice(0, 12)}`,
    syncStatus: "PENDING_SYNC",
  };
  const next = [record, ...existing];
  savePendingQueue(next);
  return { added: true, queue: next };
}

export interface QueueFlushResult {
  readonly flushedCount: number;
  readonly remaining: PendingLedgerRecord[];
  readonly errorMessage: string | null;
}

/**
 * Flushes queued zero-PII receipts chronologically (oldest -> newest) to Cloud Firestore,
 * preserving prevReceiptSha256 chain order and strict firestore.rules key whitelist.
 */
export async function flushPendingQueueToFirestore(): Promise<QueueFlushResult> {
  const current = loadPendingQueue();
  if (current.length === 0) {
    return { flushedCount: 0, remaining: [], errorMessage: null };
  }

  const chronological = [...current].reverse();
  const failed: PendingLedgerRecord[] = [];
  let flushedCount = 0;
  let errorMessage: string | null = null;

  for (let i = 0; i < chronological.length; i++) {
    const item = chronological[i]!;
    try {
      const docId = await writeZeroPiiAuditLedger(toStrictLedgerEntry(item));
      if (!docId) {
        errorMessage = "Firebase is not configured; offline receipts remain queued locally.";
        failed.push(...chronological.slice(i));
        break;
      }
      flushedCount += 1;
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : "Failed to sync queued receipt to Firestore.";
      failed.push(...chronological.slice(i));
      break;
    }
  }

  const remainingNewestFirst = [...failed].reverse();
  savePendingQueue(remainingNewestFirst);
  return {
    flushedCount,
    remaining: remainingNewestFirst,
    errorMessage,
  };
}
