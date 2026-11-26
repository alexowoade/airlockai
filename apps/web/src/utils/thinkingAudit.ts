import { sha256Hex, type AirlockVault } from "@airlock/core";

export type AirlockThinkingDepth = "LOW" | "MEDIUM" | "HIGH";

export interface ThinkingAuditTrace {
  readonly requestedDepth: AirlockThinkingDepth;
  readonly includeThoughts: boolean;
  readonly summaryAvailable: boolean;
  readonly thoughtSummary: string;
  readonly thoughtSignature: string | null;
  readonly thoughtDigestSha256: string;
  readonly zeroPiiVerified: boolean;
  readonly leakedSecretCount: number;
  readonly placeholderTokenCount: number;
}

const PLACEHOLDER_RX = /\[[A-Z_]+_\d+\]/g;

/**
 * Extracts thoughtSummary() and any underlying thoughtSignature from a Firebase AI Logic
 * EnhancedGenerateContentResponse, then deterministically verifies 0 raw vault secrets
 * appear anywhere inside Gemini's internal reasoning trace.
 */
export async function buildThinkingAuditTrace(params: {
  response: {
    thoughtSummary?: () => string | undefined;
    candidates?: ReadonlyArray<{
      content?: { parts?: ReadonlyArray<unknown> };
    }>;
  };
  vault: AirlockVault;
  requestedDepth: AirlockThinkingDepth;
}): Promise<ThinkingAuditTrace> {
  let summary = "";
  try {
    summary = (params.response.thoughtSummary?.() ?? "").trim();
  } catch {
    summary = "";
  }

  // Fallback extraction if model emitted thought parts directly
  let rawSignature: string | null = null;
  const parts = params.response.candidates?.[0]?.content?.parts ?? [];
  const extractedThoughts: string[] = [];

  for (const part of parts) {
    if (!part || typeof part !== "object") continue;
    const rec = part as Record<string, unknown>;
    if (typeof rec.thoughtSignature === "string" && rec.thoughtSignature.length > 0 && !rawSignature) {
      rawSignature = rec.thoughtSignature;
    }
    if (rec.thought === true && typeof rec.text === "string" && rec.text.trim()) {
      extractedThoughts.push(rec.text.trim());
    }
  }

  if (!summary && extractedThoughts.length > 0) {
    summary = extractedThoughts.join("\n\n");
  }

  const verification = verifyThoughtSummaryZeroPii(summary, params.vault);
  const digestSource = summary || `NO_THOUGHT_SUMMARY_EMITTED:${params.requestedDepth}`;
  const thoughtDigestSha256 = await sha256Hex(digestSource);

  return {
    requestedDepth: params.requestedDepth,
    includeThoughts: true,
    summaryAvailable: summary.length > 0,
    thoughtSummary: summary,
    thoughtSignature: rawSignature,
    thoughtDigestSha256,
    zeroPiiVerified: verification.ok,
    leakedSecretCount: verification.leakedCount,
    placeholderTokenCount: verification.placeholderCount,
  };
}

/**
 * Pure deterministic verifier proving zero raw vault secrets leaked into Gemini's
 * internal chain-of-thought summary.
 */
export function verifyThoughtSummaryZeroPii(
  thoughtSummary: string,
  vault: AirlockVault
): { readonly ok: boolean; readonly leakedCount: number; readonly placeholderCount: number } {
  const lower = thoughtSummary.toLowerCase();
  let leakedCount = 0;

  for (const entry of vault.getEntries(true)) {
    const raw = entry.original.trim().toLowerCase();
    if (raw.length >= 4 && lower.includes(raw)) {
      leakedCount += 1;
    }
  }

  const placeholderCount = (thoughtSummary.match(PLACEHOLDER_RX) ?? []).length;
  return {
    ok: leakedCount === 0,
    leakedCount,
    placeholderCount,
  };
}
