import {
  AirlockVault,
  asRawDocument,
  resolveOverlappingSpans,
  scanDeterministicPii,
  verifyAndMintPayload,
  type DetectedSpan,
  type FirewallResult,
  type PolicyProfile,
  type VaultEntry,
  type VerifiedSanitizedPayload,
} from "@airlock/core";
import type { Part } from "firebase/ai";
import { getFirebaseHandles, writeZeroPiiAuditLedger } from "./firebase.js";
import { wireTap } from "./wireTap.js";
import { neutralizePromptInjections, type PromptInjectionReport } from "../utils/promptInjectionGuard.js";
import { executeLocalZkOracle, type OracleCallTrace } from "../utils/zkOracleTools.js";

export interface CoRefMatrixRow {
  readonly token: string;
  readonly category: string;
  readonly inDocA: boolean;
  readonly inDocB: boolean;
}

export interface DealRoomAirlockOutput {
  readonly vault: AirlockVault;
  readonly docATitle: string;
  readonly docBTitle: string;
  readonly sanitizedDocA: string;
  readonly sanitizedDocB: string;
  readonly combinedSanitized: string;
  readonly entityMatrix: ReadonlyArray<CoRefMatrixRow>;
  readonly injectionGuard: PromptInjectionReport;
  readonly firewallResult: FirewallResult;
}

export interface DealRoomOracleAuditOutput {
  readonly sanitizedVerdictMarkdown: string;
  readonly rehydratedVerdictMarkdown: string;
  readonly oracleTraces: ReadonlyArray<OracleCallTrace>;
  readonly toolRounds: number;
  readonly latencyMs: number;
}

function propagateAcrossDoc(
  docText: string,
  seedSpans: ReadonlyArray<DetectedSpan>
): DetectedSpan[] {
  const extra: DetectedSpan[] = [];
  const seen = new Set<string>();
  const lowerDoc = docText.toLowerCase();

  for (const s of seedSpans) {
    const needle = s.text.trim();
    const key = `${s.category}:${needle.toLowerCase()}`;
    if (needle.length < 4 || seen.has(key)) continue;
    seen.add(key);

    const lowerNeedle = needle.toLowerCase();
    let offset = 0;
    while (offset < lowerDoc.length) {
      const idx = lowerDoc.indexOf(lowerNeedle, offset);
      if (idx === -1) break;
      const before = idx > 0 ? docText[idx - 1]! : " ";
      const after = idx + needle.length < docText.length ? docText[idx + needle.length]! : " ";
      if (!/[A-Za-z0-9]/.test(before) && !/[A-Za-z0-9]/.test(after)) {
        extra.push({
          start: idx,
          end: idx + needle.length,
          text: docText.slice(idx, idx + needle.length),
          category: s.category,
          detectedBy: s.detectedBy,
        });
      }
      offset = idx + needle.length;
    }
  }
  return extra;
}

export async function runDealRoomLocalAirlock(params: {
  docATitle: string;
  docAText: string;
  docBTitle: string;
  docBText: string;
  policyProfile: PolicyProfile;
  prevReceiptSha256: string | null;
}): Promise<DealRoomAirlockOutput> {
  const t0 = performance.now();
  const vault = new AirlockVault();

  const rawA = asRawDocument(params.docAText.trim());
  const rawB = asRawDocument(params.docBText.trim());

  // Pass 1: Independent scan; Pass 2: Cross-document shared-vault propagation
  const baseSpansA = scanDeterministicPii(rawA);
  const baseSpansB = scanDeterministicPii(rawB);

  const spansA: ReadonlyArray<DetectedSpan> = resolveOverlappingSpans([
    ...baseSpansA,
    ...propagateAcrossDoc(rawA, baseSpansB),
  ]);
  const redactedA = vault.redactSpans(rawA, spansA);

  const spansB: ReadonlyArray<DetectedSpan> = resolveOverlappingSpans([
    ...baseSpansB,
    ...propagateAcrossDoc(rawB, baseSpansA),
  ]);
  const redactedB = vault.redactSpans(rawB, spansB);

  const combinedRaw = asRawDocument(
    `=== ${params.docATitle} ===\n${rawA}\n\n=== ${params.docBTitle} ===\n${rawB}`
  );
  const rawCombinedCandidate = `=== ${params.docATitle} ===\n${redactedA}\n\n=== ${params.docBTitle} ===\n${redactedB}`;
  const injectionGuard = neutralizePromptInjections(rawCombinedCandidate);

  const sanitizedDocA = neutralizePromptInjections(redactedA).neutralizedText;
  const sanitizedDocB = neutralizePromptInjections(redactedB).neutralizedText;
  const combinedSanitized = injectionGuard.neutralizedText;

  const entries: ReadonlyArray<VaultEntry> = vault.getEntries(false);
  const entityMatrix: CoRefMatrixRow[] = entries.map((e) => ({
    token: e.token,
    category: e.category,
    inDocA: sanitizedDocA.includes(e.token),
    inDocB: sanitizedDocB.includes(e.token),
  }));

  const firewallResult = await verifyAndMintPayload({
    rawDoc: combinedRaw,
    candidateSanitized: combinedSanitized,
    vault,
    policyProfile: params.policyProfile,
    prevReceiptSha256: params.prevReceiptSha256,
  });

  const sharedCount = entityMatrix.filter((r) => r.inDocA && r.inDocB).length;
  const latencyMs = Math.max(1, Math.round(performance.now() - t0));

  wireTap.record({
    stage: firewallResult.ok ? "GATE3_FIREWALL_PASS" : "GATE3_FIREWALL_BLOCK",
    inferenceSource: firewallResult.ok ? "DETERMINISTIC_LOCAL" : "BLOCKED",
    latencyMs,
    bytesSent: 0,
    payloadPreview: firewallResult.ok
      ? `DEAL ROOM SHARED VAULT READY — ${entries.length} total tokens (${sharedCount} co-referenced across Doc A & Doc B), 6/6 firewall passed (0B sent).`
      : `DEAL ROOM BLOCKED — ${firewallResult.violations[0]?.vector}: ${firewallResult.violations[0]?.detail}`,
  });

  return {
    vault,
    docATitle: params.docATitle,
    docBTitle: params.docBTitle,
    sanitizedDocA,
    sanitizedDocB,
    combinedSanitized,
    entityMatrix,
    injectionGuard,
    firewallResult,
  };
}

export async function runDealRoomOracleAudit(params: {
  verified: VerifiedSanitizedPayload;
  vault: AirlockVault;
  policyProfile: PolicyProfile;
  onLedgerSynced?: (docId: string) => void;
}): Promise<DealRoomOracleAuditOutput> {
  const handles = getFirebaseHandles();
  if (!handles) {
    throw new Error("Configure Firebase keys in apps/web/.env.local to run Zero-Knowledge Oracle Audit.");
  }

  const t0 = performance.now();
  const chat = handles.zkOracleModel.startChat();
  const oracleTraces: OracleCallTrace[] = [];

  const prompt = [
    "You are AirlockAI's Zero-Knowledge Cross-Contract Fraud Auditor.",
    "Two related documents have been redacted through a shared zero-knowledge vault so identical entities share identical placeholder tokens.",
    "MANDATORY PROTOCOL:",
    "1. NEVER guess quantitative comparisons between masked tokens. You MUST call your local oracle tools:",
    "   - Call compare_currency_tokens on the contract cap token vs. invoice amount token.",
    "   - Call compare_date_tokens on the contract expiration date token vs. invoice settlement date token.",
    "   - Call verify_iban_jurisdiction on the invoice IBAN token against the authorized 2-letter country code stated in Doc A.",
    "   - Call check_token_identity to compare the authorized IBAN token in Doc A vs. the remittance IBAN token in Doc B.",
    "2. Preserve ALL redacted placeholder tokens like [ORG_1], [CURRENCY_1], [CURRENCY_2], [DATE_1], [DATE_2], [IBAN_1], [IBAN_2] verbatim in your final report so the browser can re-hydrate locally.",
    "3. Output a concise executive verdict: Overall Risk Level (CRITICAL/HIGH/MEDIUM/LOW), exact Oracle-Verified Contradictions (citing the ratios, days delta, and jurisdiction mismatch proven by the tools), and Recommended Action.",
    "",
    params.verified.sanitizedText,
  ].join("\n");

  let result = await chat.sendMessage(prompt);
  let toolRounds = 0;

  while (toolRounds < 5) {
    const calls = result.response.functionCalls();
    if (!calls || calls.length === 0) break;
    toolRounds += 1;

    const responseParts: Part[] = calls.map((call) => {
      const argsObj = (call.args ?? {}) as Record<string, unknown>;
      const { response, trace } = executeLocalZkOracle(call.name, argsObj, params.vault);
      oracleTraces.push(trace);

      wireTap.record({
        stage: "ORACLE_TOOL_CALL",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: trace.latencyMs,
        bytesSent: 0,
        payloadPreview: `LOCAL ORACLE ${call.name}(${JSON.stringify(argsObj)}) -> ${JSON.stringify(response)} [0B Raw PII]`,
      });

      return {
        type: "functionResponse",
        functionResponse: {
          name: call.name,
          response,
        },
      };
    });

    result = await chat.sendMessage(responseParts);
  }

  const sanitizedVerdictMarkdown = result.response.text();
  const rehydratedVerdictMarkdown = params.vault.rehydrate(sanitizedVerdictMarkdown);
  const latencyMs = Math.round(performance.now() - t0);

  wireTap.record({
    stage: "CLOUD_TEMPLATE_AUDIT",
    inferenceSource: "IN_CLOUD",
    latencyMs,
    bytesSent: new TextEncoder().encode(params.verified.sanitizedText).byteLength,
    payloadPreview: `ZK ORACLE DEAL ROOM VERDICT — ${oracleTraces.length} local tool calls across ${toolRounds} round(s), 0B raw PII revealed.`,
  });

  const riskLevel =
    sanitizedVerdictMarkdown.match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i)?.[1]?.toUpperCase() ??
    "CRITICAL";

  void writeZeroPiiAuditLedger({
    ...params.verified.receipt,
    inferenceSource: "IN_CLOUD",
    riskLevel,
    sanitizedSummary: `Deal Room ZK-Oracle Audit (${params.policyProfile}): ${oracleTraces.length} local oracle calls, ${params.verified.receipt.redactedCount} shared vault tokens, 6/6 firewall passed.`,
  })
    .then((id) => {
      if (id) params.onLedgerSynced?.(id);
    })
    .catch(() => {});

  return {
    sanitizedVerdictMarkdown,
    rehydratedVerdictMarkdown,
    oracleTraces,
    toolRounds,
    latencyMs,
  };
}
