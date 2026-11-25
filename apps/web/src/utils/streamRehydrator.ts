import type { AirlockVault } from "@airlock/core";

export interface StreamFsmMetrics {
  readonly ttftMs: number | null;
  readonly chunkCount: number;
  readonly heldBoundarySplits: number;
  readonly tokensResolved: number;
  readonly localRehydrateMs: number;
}

export interface StreamingAuditSnapshot {
  readonly sanitizedSoFar: string;
  readonly rehydratedSoFar: string;
  readonly metrics: StreamFsmMetrics;
  readonly done: boolean;
}

const VALID_PARTIAL_TOKEN_RX = /^\[[A-Z0-9_]{0,24}$/;
const COMPLETE_TOKEN_RX = /\[[A-Z_]+_\d+\]/g;

/**
 * Deterministic Token-Boundary Finite State Machine for Firebase AI Logic generateContentStream().
 * Holds incomplete placeholder prefixes (e.g., "[OR" or "[CURRENCY_") across arbitrary network
 * chunk boundaries until the closing "]" arrives, guaranteeing clean zero-knowledge re-hydration
 * in browser RAM with O(n) single-pass overhead.
 */
export class TokenBoundaryStreamFsm {
  private pending = "";
  private sanitizedSoFar = "";
  private rehydratedSoFar = "";
  private readonly startedAtMs: number;
  private ttftMs: number | null = null;
  private chunkCount = 0;
  private heldBoundarySplits = 0;
  private tokensResolved = 0;
  private localRehydrateMs = 0;
  private readonly knownTokens: Set<string>;
  private readonly vault: AirlockVault;

  constructor(vault: AirlockVault, startedAtMs: number = performance.now()) {
    this.vault = vault;
    this.startedAtMs = startedAtMs;
    this.knownTokens = new Set(vault.getEntries(false).map((e) => e.token));
  }

  public pushChunk(chunkText: string): StreamingAuditSnapshot {
    const t0 = performance.now();
    if (chunkText.length > 0) {
      if (this.ttftMs === null) {
        this.ttftMs = Math.max(1, Math.round(t0 - this.startedAtMs));
      }
      this.chunkCount += 1;
    }

    const combined = this.pending + chunkText;
    const lastOpen = combined.lastIndexOf("[");
    let emitSlice = combined;
    this.pending = "";

    if (lastOpen !== -1) {
      const tail = combined.slice(lastOpen);
      if (!tail.includes("]") && VALID_PARTIAL_TOKEN_RX.test(tail)) {
        emitSlice = combined.slice(0, lastOpen);
        this.pending = tail;
        this.heldBoundarySplits += 1;
      }
    }

    this.commitSlice(emitSlice);
    this.localRehydrateMs += performance.now() - t0;
    return this.snapshot(false);
  }

  public flush(): StreamingAuditSnapshot {
    const t0 = performance.now();
    if (this.pending.length > 0) {
      const rem = this.pending;
      this.pending = "";
      this.commitSlice(rem);
    }
    this.localRehydrateMs += performance.now() - t0;
    return this.snapshot(true);
  }

  private commitSlice(slice: string): void {
    if (!slice) return;
    const matches = slice.match(COMPLETE_TOKEN_RX);
    if (matches) {
      for (const tok of matches) {
        if (this.knownTokens.has(tok)) {
          this.tokensResolved += 1;
        }
      }
    }
    this.sanitizedSoFar += slice;
    this.rehydratedSoFar += this.vault.rehydrate(slice);
  }

  private snapshot(done: boolean): StreamingAuditSnapshot {
    return {
      sanitizedSoFar: this.sanitizedSoFar,
      rehydratedSoFar: this.rehydratedSoFar,
      metrics: {
        ttftMs: this.ttftMs,
        chunkCount: this.chunkCount,
        heldBoundarySplits: this.heldBoundarySplits,
        tokensResolved: this.tokensResolved,
        localRehydrateMs: Number(this.localRehydrateMs.toFixed(2)),
      },
      done,
    };
  }
}
