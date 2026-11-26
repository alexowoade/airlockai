import {
  AirlockVault,
  asRawDocument,
  resolveOverlappingSpans,
  scanDeterministicPii,
  verifyAndMintPayload,
  type DetectedSpan,
  type EntityCategory,
  type FirewallResult,
  type PolicyProfile,
  type RawDocument,
  type VerifiedSanitizedPayload,
} from "@airlock/core";
import type { Part } from "firebase/ai";
import {
  checkLocalNanoStatus,
  createThinkingModel,
  getFirebaseHandles,
  POLICY_TEMPLATES,
  writeZeroPiiAuditLedger,
  type AirlockPolicyConfig,
} from "./firebase.js";
import { wireTap } from "./wireTap.js";
import { neutralizePromptInjections, type PromptInjectionReport } from "../utils/promptInjectionGuard.js";
import { scanPolicyAsCodeSpans, type CompliancePackId, type CustomRegexRule } from "../utils/policyStudio.js";
import { TokenBoundaryStreamFsm, type StreamFsmMetrics, type StreamingAuditSnapshot } from "../utils/streamRehydrator.js";
import { buildThinkingAuditTrace, type AirlockThinkingDepth, type ThinkingAuditTrace } from "../utils/thinkingAudit.js";
import {
  analyzeResidualRisks,
  quasiHitsToSpans,
  type ResidualRiskReport,
} from "../utils/residualGuard.js";

export interface LocalAirlockOutput {
  readonly rawDoc: RawDocument;
  readonly candidateSanitized: string;
  readonly vault: AirlockVault;
  readonly mergedSpans: ReadonlyArray<DetectedSpan>;
  readonly gate1Count: number;
  readonly gate2Count: number;
  readonly customCount: number;
  readonly gate2UsedNano: boolean;
  readonly residualRisk: ResidualRiskReport;
  readonly injectionGuard: PromptInjectionReport;
  readonly firewallResult: FirewallResult;
}

export interface OfflineTriageOutput {
  readonly documentType: string;
  readonly quickRiskLevel: string;
  readonly oneLineSummary: string;
  readonly inferenceSource: "ON_DEVICE" | "IN_CLOUD";
  readonly latencyMs: number;
}

export interface StructuredRedlineClause {
  readonly clauseTitle: string;
  readonly severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  readonly issue: string;
  readonly quotedExcerpt: string;
  readonly redlineCounterProposal: string;
}

export interface StructuredAuditPayload {
  readonly overallRiskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  readonly executiveSummary: string;
  readonly clauses: ReadonlyArray<StructuredRedlineClause>;
}

export interface CloudAuditOutput {
  readonly mode: "SERVER_TEMPLATE" | "STRUCTURED_JSON";
  readonly sanitizedMarkdown: string;
  readonly rehydratedMarkdown: string;
  readonly structured: StructuredAuditPayload | null;
  readonly usedServerTemplate: boolean;
  readonly templateId: string;
  readonly inferenceSource: "IN_CLOUD";
  readonly latencyMs: number;
  readonly ledgerDocId: string | null;
  readonly streamMetrics?: StreamFsmMetrics;
  readonly thinkingTrace?: ThinkingAuditTrace | null;
}

interface NanoExtractionJson {
  extractedText?: string;
  entities?: Array<{ text: string; category: "PERSON" | "ORG" | "MEDICAL" | "SECRET_TERM" }>;
}

function findAllOccurrences(
  haystack: string,
  needle: string,
  category: EntityCategory,
  detectedBy: "GATE1_REGEX" | "GATE2_NANO_ON_DEVICE" = "GATE2_NANO_ON_DEVICE"
): DetectedSpan[] {
  const spans: DetectedSpan[] = [];
  const trimmed = needle.trim();
  if (trimmed.length < 3) return spans;
  const lowerHay = haystack.toLowerCase();
  const lowerNeedle = trimmed.toLowerCase();

  let offset = 0;
  while (offset < lowerHay.length) {
    const idx = lowerHay.indexOf(lowerNeedle, offset);
    if (idx === -1) break;
    spans.push({
      start: idx,
      end: idx + trimmed.length,
      text: haystack.slice(idx, idx + trimmed.length),
      category,
      detectedBy,
    });
    offset = idx + trimmed.length;
  }
  return spans;
}

function normalizeRisk(value: unknown): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  const s = String(value ?? "MEDIUM").toUpperCase();
  if (s.includes("CRITICAL")) return "CRITICAL";
  if (s.includes("HIGH")) return "HIGH";
  if (s.includes("LOW")) return "LOW";
  return "MEDIUM";
}

function formatStructuredToMarkdown(structured: StructuredAuditPayload): string {
  const lines: string[] = [
    `Overall Risk Level: ${structured.overallRiskLevel}`,
    "",
    structured.executiveSummary,
    "",
    "Clause Redlines:",
  ];
  structured.clauses.forEach((c, idx) => {
    lines.push(`${idx + 1}. [${c.severity}] ${c.clauseTitle}`);
    lines.push(`   Issue: ${c.issue}`);
    if (c.quotedExcerpt) lines.push(`   Excerpt: "${c.quotedExcerpt}"`);
    lines.push(`   Redline: ${c.redlineCounterProposal}`);
  });
  return lines.join("\n");
}

/**
 * Runs Gate 1 (Deterministic PII + NER + Optional Safe Harbor + Custom Secrets)
 * -> Guarded Gate 2 (ONLY_ON_DEVICE Nano)
 * -> Gate 3 (6-Vector Firewall) + Residual Risk Analysis.
 */
export async function runLocalAirlock(params: {
  rawText: string;
  imageBase64?: { mimeType: "image/png" | "image/jpeg"; data: string };
  policy: AirlockPolicyConfig;
  prevReceiptSha256: string | null;
  customSecrets?: ReadonlyArray<string>;
  strictSafeHarbor?: boolean;
  policyPacks?: ReadonlyArray<CompliancePackId>;
  customRegexRules?: ReadonlyArray<CustomRegexRule>;
}): Promise<LocalAirlockOutput> {
  const handles = getFirebaseHandles();
  const vault = new AirlockVault();
  let workingText = params.rawText.trim();
  let gate2Spans: DetectedSpan[] = [];
  let gate2UsedNano = false;

  // Guarded Gate 2: STRICTLY ON-DEVICE (Enforces #10635 guard before calling Firebase AI Logic)
  const nanoStatus = await checkLocalNanoStatus();
  if (handles && nanoStatus === "available") {
    const t0 = performance.now();
    try {
      const promptText =
        `Extract contextual sensitive entities (PERSON names, ORG company/hospital names, MEDICAL diagnoses/treatments, SECRET_TERM project codenames) ` +
        `under policy ${params.policy.profile}. ` +
        (params.imageBase64
          ? "Also transcribe all visible text from the attached document image into extractedText."
          : `Analyze this document:\n${workingText}`);

      const parts: string | (string | Part)[] = params.imageBase64
        ? [
            { type: "text", text: promptText },
            {
              type: "inlineData",
              inlineData: { mimeType: params.imageBase64.mimeType, data: params.imageBase64.data },
            },
          ]
        : promptText;

      const res = await handles.localPiiModel.generateContent(parts);
      const parsed = JSON.parse(res.response.text()) as NanoExtractionJson;

      if (!workingText && parsed.extractedText) {
        workingText = parsed.extractedText;
      }
      if (parsed.entities && workingText) {
        for (const ent of parsed.entities) {
          gate2Spans.push(...findAllOccurrences(workingText, ent.text, ent.category, "GATE2_NANO_ON_DEVICE"));
        }
      }
      gate2UsedNano = true;

      wireTap.record({
        stage: "GATE2_NANO_ON_DEVICE",
        inferenceSource: "ON_DEVICE",
        latencyMs: Math.round(performance.now() - t0),
        bytesSent: 0,
        payloadPreview: `Gemini Nano scanned locally (${gate2Spans.length} semantic spans, 0 bytes transmitted).`,
      });
    } catch (err) {
      wireTap.record({
        stage: "GATE2_NANO_ON_DEVICE",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: Math.round(performance.now() - t0),
        bytesSent: 0,
        payloadPreview: `Nano local scan skipped (${err instanceof Error ? err.message : "unavailable"}). Protected by Gate 1 deterministic NER + #10635 guard.`,
      });
    }
  } else {
    wireTap.record({
      stage: "GATE2_NANO_ON_DEVICE",
      inferenceSource: "DETERMINISTIC_LOCAL",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: `SDK #10635 Guard Active (Nano status: ${nanoStatus}). Hard-blocked raw cloud fallback; Gate 1 deterministic PII + NER fallback active (0B sent).`,
    });
  }

  // Gate 1: Deterministic Regex + Luhn + Shannon Entropy + Named-Entity Rules (< 5ms)
  const g1Start = performance.now();
  const rawDoc = asRawDocument(workingText);
  const gate1Spans = scanDeterministicPii(rawDoc);

  // Optional Strict HIPAA Safe Harbor quasi-identifier spans + user Custom Secrets
  const safeHarborSpans = params.strictSafeHarbor ? quasiHitsToSpans(workingText) : [];
  const customSpans: DetectedSpan[] = [];
  for (const term of params.customSecrets ?? []) {
    customSpans.push(...findAllOccurrences(workingText, term, "SECRET_TERM", "GATE1_REGEX"));
  }

  const policyAsCodeSpans = scanPolicyAsCodeSpans(
    workingText,
    params.policyPacks ?? [],
    params.customRegexRules ?? []
  );
  const allLocalSpans = [...gate1Spans, ...safeHarborSpans, ...policyAsCodeSpans, ...customSpans];
  const uniqueCategories = Array.from(new Set(allLocalSpans.map((s) => s.category))).join(", ");
  wireTap.record({
    stage: "GATE1_REGEX",
    inferenceSource: "DETERMINISTIC_LOCAL",
    latencyMs: Math.max(1, Math.round(performance.now() - g1Start)),
    bytesSent: 0,
    payloadPreview: `Deterministic scanner matched ${gate1Spans.length} core + ${safeHarborSpans.length} Safe Harbor + ${policyAsCodeSpans.length} policy-as-code + ${customSpans.length} custom spans (${uniqueCategories || "none"}).`,
  });

  const mergedSpans = resolveOverlappingSpans([...allLocalSpans, ...gate2Spans]);
  const rawCandidate = vault.redactSpans(rawDoc, mergedSpans);
  const injectionGuard = neutralizePromptInjections(rawCandidate);
  const candidateSanitized = injectionGuard.neutralizedText;
  if (!injectionGuard.clean) {
    wireTap.record({
      stage: "PROMPT_INJECTION_GUARD",
      inferenceSource: "BLOCKED",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: `NEUTRALIZED ${injectionGuard.findings.length} indirect prompt-injection clause(s) locally before cloud send (${injectionGuard.findings.map((f) => f.rule).join(", ")}).`,
    });
  }
  const residualRisk = analyzeResidualRisks(candidateSanitized, gate2UsedNano);

  // Gate 3: Hard 6-Vector Pre-Flight Leak Firewall
  const firewallResult = await verifyAndMintPayload({
    rawDoc,
    candidateSanitized,
    vault,
    policyProfile: params.policy.profile,
    prevReceiptSha256: params.prevReceiptSha256,
  });

  if (!firewallResult.ok) {
    wireTap.record({
      stage: "GATE3_FIREWALL_BLOCK",
      inferenceSource: "BLOCKED",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: `BLOCKED (${firewallResult.blockedBytes} bytes stopped): ${firewallResult.violations
        .map((v) => `${v.vector} (${v.category})`)
        .join(", ")}`,
    });
  } else {
    wireTap.record({
      stage: "GATE3_FIREWALL_PASS",
      inferenceSource: "DETERMINISTIC_LOCAL",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: `6/6 firewall vectors passed — SHA-256 ${firewallResult.payload.receipt.receiptSha256.slice(0, 16)}… minted (${firewallResult.payload.receipt.redactedCount} entities redacted, 0B sent).`,
    });
  }

  return {
    rawDoc,
    candidateSanitized,
    vault,
    mergedSpans,
    gate1Count: gate1Spans.length + safeHarborSpans.length + policyAsCodeSpans.length,
    gate2Count: gate2Spans.length,
    customCount: customSpans.length,
    gate2UsedNano,
    residualRisk,
    injectionGuard,
    firewallResult,
  };
}

/**
 * Offline-First Triage: PREFER_ON_DEVICE on VerifiedSanitizedPayload ONLY.
 */
export async function runHybridTriage(
  verified: VerifiedSanitizedPayload
): Promise<OfflineTriageOutput> {
  const handles = getFirebaseHandles();
  if (!handles) {
    throw new Error("Configure Firebase keys in apps/web/.env.local to run AI Logic triage.");
  }

  const t0 = performance.now();
  const res = await handles.hybridTriageModel.generateContent(
    `Classify and give a one-sentence risk summary of this sanitized document:\n\n${verified.sanitizedText}`
  );
  const latencyMs = Math.round(performance.now() - t0);
  const rawSource = (res.response.inferenceSource ?? "IN_CLOUD").toUpperCase();
  const inferenceSource: "ON_DEVICE" | "IN_CLOUD" =
    rawSource.includes("ON_DEVICE") ? "ON_DEVICE" : "IN_CLOUD";

  const parsed = JSON.parse(res.response.text()) as {
    documentType: string;
    quickRiskLevel: string;
    oneLineSummary: string;
  };

  wireTap.record({
    stage: "OFFLINE_TRIAGE",
    inferenceSource,
    latencyMs,
    bytesSent: inferenceSource === "ON_DEVICE" ? 0 : new TextEncoder().encode(verified.sanitizedText).byteLength,
    payloadPreview: `[${inferenceSource}] ${parsed.documentType} (${parsed.quickRiskLevel}): ${parsed.oneLineSummary}`,
  });

  return {
    ...parsed,
    inferenceSource,
    latencyMs,
  };
}

/**
 * Deep Cloud Audit: Accepts ONLY compile-time VerifiedSanitizedPayload.
 * Supports both Firebase Server Prompt Templates and Structured JSON Clause Redline Schema.
 */
export async function runDeepCloudAudit(params: {
  verified: VerifiedSanitizedPayload;
  vault: AirlockVault;
  policyProfile: PolicyProfile;
  templateIdOverride?: string;
  auditMode?: "SERVER_TEMPLATE" | "STRUCTURED_JSON";
  thinkingDepth?: AirlockThinkingDepth;
  onLedgerSynced?: (docId: string) => void;
  onStreamUpdate?: (snapshot: StreamingAuditSnapshot) => void;
}): Promise<CloudAuditOutput> {
  const handles = getFirebaseHandles();
  if (!handles) {
    throw new Error("Configure Firebase keys in apps/web/.env.local to run Cloud Audit.");
  }

  const requestedMode = params.auditMode ?? "SERVER_TEMPLATE";
  const templateId = params.templateIdOverride ?? POLICY_TEMPLATES[params.policyProfile];
  const t0 = performance.now();
  let sanitizedMarkdown = "";
  let structured: StructuredAuditPayload | null = null;
  let usedServerTemplate = false;
  let effectiveMode: "SERVER_TEMPLATE" | "STRUCTURED_JSON" = requestedMode;
  let streamMetrics: StreamFsmMetrics | undefined;
  let thinkingTrace: ThinkingAuditTrace | null = null;
  const thinkingDepth: AirlockThinkingDepth = params.thinkingDepth ?? "MEDIUM";

  if (requestedMode === "STRUCTURED_JSON") {
    const schemaPrompt =
      `You are AirlockAI's compliance auditor (${params.policyProfile}). ` +
      `Return structured JSON matching the schema with 3 high-impact clause redlines. ` +
      `CRITICAL RULE: Preserve all redacted placeholder tokens like [ORG_1], [PERSON_1], [CURRENCY_1], [SECRET_TERM_1] verbatim so the client can re-hydrate locally.\n\n` +
      `Sanitized Document:\n${params.verified.sanitizedText}`;
    const parseStructuredJson = (rawText: string): Partial<StructuredAuditPayload> => {
      const cleaned = rawText
        .trim()
        .replace(/^```(?:json)?\s*/i, "")
        .replace(/\s*```$/i, "")
        .trim();
      return JSON.parse(cleaned) as Partial<StructuredAuditPayload>;
    };

    let res;
    let rawJson: Partial<StructuredAuditPayload>;
    try {
      const thinkingStructModel = createThinkingModel({
        ai: handles.ai,
        depth: thinkingDepth,
        structuredSchema: handles.structuredAuditModel.generationConfig?.responseSchema as never,
        maxOutputTokens: thinkingDepth === "HIGH" ? 8192 : thinkingDepth === "MEDIUM" ? 4096 : 2048,
      });
      res = await thinkingStructModel.generateContent(schemaPrompt);
      thinkingTrace = await buildThinkingAuditTrace({
        response: res.response,
        vault: params.vault,
        requestedDepth: thinkingDepth,
      });
      rawJson = parseStructuredJson(res.response.text());
    } catch {
      res = await handles.structuredAuditModel.generateContent(schemaPrompt);
      if (!thinkingTrace) {
        thinkingTrace = await buildThinkingAuditTrace({
          response: res.response,
          vault: params.vault,
          requestedDepth: thinkingDepth,
        });
      }
      rawJson = parseStructuredJson(res.response.text());
    }
    wireTap.record({
      stage: "THINKING_AUDIT",
      inferenceSource: "DETERMINISTIC_LOCAL",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: `STRUCTURED JSON THOUGHT AUDIT (${thinkingDepth}): zeroPii=${thinkingTrace.zeroPiiVerified}, summary=${thinkingTrace.summaryAvailable ? `${thinkingTrace.thoughtSummary.length} chars` : "compact"}, sha256=${thinkingTrace.thoughtDigestSha256.slice(0, 14)}…`,
    });
    const normalizedClauses: StructuredRedlineClause[] = Array.isArray(rawJson.clauses)
      ? rawJson.clauses.slice(0, 5).map((c) => ({
          clauseTitle: String(c.clauseTitle ?? "Compliance Clause"),
          severity: normalizeRisk(c.severity),
          issue: String(c.issue ?? ""),
          quotedExcerpt: String(c.quotedExcerpt ?? ""),
          redlineCounterProposal: String(c.redlineCounterProposal ?? ""),
        }))
      : [];
    structured = {
      overallRiskLevel: normalizeRisk(rawJson.overallRiskLevel),
      executiveSummary: String(rawJson.executiveSummary ?? ""),
      clauses: normalizedClauses,
    };
    sanitizedMarkdown = formatStructuredToMarkdown(structured);
    effectiveMode = "STRUCTURED_JSON";
  } else {
    let finalSnap: StreamingAuditSnapshot | null = null;
    try {
      const fsm = new TokenBoundaryStreamFsm(params.vault, t0);
      const streamRes = await handles.templateAuditModel.generateContentStream({
        templateId,
        templateVariables: {
          sanitizedText: params.verified.sanitizedText,
          policyProfile: params.policyProfile,
        },
      });
      for await (const chunk of streamRes.stream) {
        const delta = chunk.text();
        if (delta) {
          params.onStreamUpdate?.(fsm.pushChunk(delta));
        }
      }
      finalSnap = fsm.flush();
      params.onStreamUpdate?.(finalSnap);
      sanitizedMarkdown = finalSnap.sanitizedSoFar;
      streamMetrics = finalSnap.metrics;
      usedServerTemplate = true;
      try {
        const agg = await streamRes.response;
        thinkingTrace = await buildThinkingAuditTrace({
          response: agg,
          vault: params.vault,
          requestedDepth: thinkingDepth,
        });
      } catch {
        thinkingTrace = null;
      }
    } catch {
      const fsm = new TokenBoundaryStreamFsm(params.vault, t0);
      const fallbackPrompt =
        `You are AirlockAI's compliance auditor (${params.policyProfile}). ` +
        `Preserve all redacted tokens like [ORG_1] or [CURRENCY_1] verbatim so the client can re-hydrate locally.\n` +
        `Provide:\n1. Overall Risk Level (LOW/MEDIUM/HIGH/CRITICAL)\n2. Top 3 Risk Clauses\n3. Redline Counter-Proposals\n\n` +
        `Sanitized Document:\n${params.verified.sanitizedText}`;
      const streamRes = await handles.cloudAuditFallbackModel.generateContentStream(fallbackPrompt);
      for await (const chunk of streamRes.stream) {
        const delta = chunk.text();
        if (delta) {
          params.onStreamUpdate?.(fsm.pushChunk(delta));
        }
      }
      finalSnap = fsm.flush();
      params.onStreamUpdate?.(finalSnap);
      sanitizedMarkdown = finalSnap.sanitizedSoFar;
      streamMetrics = finalSnap.metrics;
    }

    if (streamMetrics) {
      wireTap.record({
        stage: "STREAM_FSM",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: Math.max(1, Math.round(streamMetrics.localRehydrateMs)),
        bytesSent: 0,
        payloadPreview: `STREAMING TOKEN-BOUNDARY FSM — TTFT ${streamMetrics.ttftMs ?? 0}ms · ${streamMetrics.chunkCount} chunks · ${streamMetrics.heldBoundarySplits} split token(s) held safely · ${streamMetrics.tokensResolved} local RAM pills resolved (${streamMetrics.localRehydrateMs}ms overhead).`,
      });
    }
  }

  const latencyMs = Math.round(performance.now() - t0);
  const rehydratedMarkdown = params.vault.rehydrate(sanitizedMarkdown);

  wireTap.record({
    stage: "CLOUD_TEMPLATE_AUDIT",
    inferenceSource: "IN_CLOUD",
    latencyMs,
    bytesSent: new TextEncoder().encode(params.verified.sanitizedText).byteLength,
    payloadPreview:
      effectiveMode === "STRUCTURED_JSON"
        ? `Structured JSON Schema audited sanitized skeleton (${structured?.clauses.length ?? 0} redline cards, ${params.verified.receipt.redactedCount} redacted tokens).`
        : usedServerTemplate
          ? `Server Prompt Template (${templateId}) audited sanitized skeleton (${params.verified.receipt.redactedCount} redacted tokens).`
          : `ONLY_IN_CLOUD fallback audited sanitized skeleton (${params.verified.receipt.redactedCount} redacted tokens).`,
  });

  const riskLevel =
    structured?.overallRiskLevel ??
    sanitizedMarkdown.match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i)?.[1]?.toUpperCase() ??
    "MEDIUM";
  const sanitizedSummary = `Policy ${params.policyProfile} (${effectiveMode === "STRUCTURED_JSON" ? "JSON Schema" : "Template"}) audit: ${params.verified.receipt.redactedCount} entities redacted, 6/6 firewall vectors passed.`;

  const ledgerDocId: string | null = null;
  void writeZeroPiiAuditLedger({
    ...params.verified.receipt,
    inferenceSource: "IN_CLOUD",
    riskLevel,
    sanitizedSummary,
  })
    .then((id) => {
      if (id) params.onLedgerSynced?.(id);
    })
    .catch(() => {
      // Offline or Firestore rules not yet deployed — audit result still succeeds locally
    });

  return {
    mode: effectiveMode,
    sanitizedMarkdown,
    rehydratedMarkdown,
    structured,
    usedServerTemplate,
    templateId,
    inferenceSource: "IN_CLOUD",
    latencyMs,
    ledgerDocId,
    streamMetrics,
    thinkingTrace,
  };
}
