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
  getFirebaseHandles,
  POLICY_TEMPLATES,
  writeZeroPiiAuditLedger,
  type AirlockPolicyConfig,
} from "./firebase.js";
import { wireTap } from "./wireTap.js";

export interface LocalAirlockOutput {
  readonly rawDoc: RawDocument;
  readonly candidateSanitized: string;
  readonly vault: AirlockVault;
  readonly gate1Count: number;
  readonly gate2Count: number;
  readonly gate2UsedNano: boolean;
  readonly firewallResult: FirewallResult;
}

export interface OfflineTriageOutput {
  readonly documentType: string;
  readonly quickRiskLevel: string;
  readonly oneLineSummary: string;
  readonly inferenceSource: "ON_DEVICE" | "IN_CLOUD";
  readonly latencyMs: number;
}

export interface CloudAuditOutput {
  readonly sanitizedMarkdown: string;
  readonly rehydratedMarkdown: string;
  readonly usedServerTemplate: boolean;
  readonly templateId: string;
  readonly inferenceSource: "IN_CLOUD";
  readonly latencyMs: number;
  readonly ledgerDocId: string | null;
}

interface NanoExtractionJson {
  extractedText?: string;
  entities?: Array<{ text: string; category: "PERSON" | "ORG" | "MEDICAL" | "SECRET_TERM" }>;
}

function findAllOccurrences(
  haystack: string,
  needle: string,
  category: EntityCategory
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
      detectedBy: "GATE2_NANO_ON_DEVICE",
    });
    offset = idx + trimmed.length;
  }
  return spans;
}

/**
 * Runs Gate 1 (Deterministic) -> Guarded Gate 2 (ONLY_ON_DEVICE Nano) -> Gate 3 (6-Vector Firewall).
 * Accepts raw text and/or an inline PNG/JPEG image (raw image NEVER leaves the device).
 */
export async function runLocalAirlock(params: {
  rawText: string;
  imageBase64?: { mimeType: "image/png" | "image/jpeg"; data: string };
  policy: AirlockPolicyConfig;
  prevReceiptSha256: string | null;
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
          gate2Spans.push(...findAllOccurrences(workingText, ent.text, ent.category));
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
        payloadPreview: `Nano local scan skipped (${err instanceof Error ? err.message : "unavailable"}). Protected by Gate 1 + #10635 guard.`,
      });
    }
  } else {
    wireTap.record({
      stage: "GATE2_NANO_ON_DEVICE",
      inferenceSource: "DETERMINISTIC_LOCAL",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: `SDK #10635 Guard Active (Nano status: ${nanoStatus}). Hard-blocked cloud fallback for raw document; running local Gate 1 only.`,
    });
  }

  // Gate 1: Deterministic Regex + Luhn + Shannon Entropy (< 5ms)
  const g1Start = performance.now();
  const rawDoc = asRawDocument(workingText);
  const gate1Spans = scanDeterministicPii(rawDoc);
  wireTap.record({
    stage: "GATE1_REGEX",
    inferenceSource: "DETERMINISTIC_LOCAL",
    latencyMs: Math.max(1, Math.round(performance.now() - g1Start)),
    bytesSent: 0,
    payloadPreview: `Deterministic scanner matched ${gate1Spans.length} structured PII/secret spans locally.`,
  });

  const mergedSpans = resolveOverlappingSpans([...gate1Spans, ...gate2Spans]);
  const candidateSanitized = vault.redactSpans(rawDoc, mergedSpans);

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
  }

  return {
    rawDoc,
    candidateSanitized,
    vault,
    gate1Count: gate1Spans.length,
    gate2Count: gate2Spans.length,
    gate2UsedNano,
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
 * Calls Firebase Server Prompt Templates first, falling back cleanly to ONLY_IN_CLOUD if
 * the user hasn't provisioned the template in Firebase Console yet.
 */
export async function runDeepCloudAudit(params: {
  verified: VerifiedSanitizedPayload;
  vault: AirlockVault;
  policyProfile: PolicyProfile;
  templateIdOverride?: string;
}): Promise<CloudAuditOutput> {
  const handles = getFirebaseHandles();
  if (!handles) {
    throw new Error("Configure Firebase keys in apps/web/.env.local to run Cloud Audit.");
  }

  const templateId = params.templateIdOverride ?? POLICY_TEMPLATES[params.policyProfile];
  const t0 = performance.now();
  let sanitizedMarkdown = "";
  let usedServerTemplate = false;

  try {
    const res = await handles.templateAuditModel.generateContent({
      templateId,
      templateVariables: {
        sanitizedText: params.verified.sanitizedText,
        policyProfile: params.policyProfile,
      },
    });
    sanitizedMarkdown = res.response.text();
    usedServerTemplate = true;
  } catch {
    // Graceful fallback to ONLY_IN_CLOUD if server template hasn't been created in console yet
    const fallbackPrompt =
      `You are AirlockAI's compliance auditor (${params.policyProfile}). ` +
      `Preserve all redacted tokens like [ORG_1] or [CURRENCY_1] verbatim so the client can re-hydrate locally.\n` +
      `Provide:\n1. Overall Risk Level (LOW/MEDIUM/HIGH/CRITICAL)\n2. Top 3 Risk Clauses\n3. Redline Counter-Proposals\n\n` +
      `Sanitized Document:\n${params.verified.sanitizedText}`;
    const res = await handles.cloudAuditFallbackModel.generateContent(fallbackPrompt);
    sanitizedMarkdown = res.response.text();
  }

  const latencyMs = Math.round(performance.now() - t0);
  const rehydratedMarkdown = params.vault.rehydrate(sanitizedMarkdown);

  wireTap.record({
    stage: "CLOUD_TEMPLATE_AUDIT",
    inferenceSource: "IN_CLOUD",
    latencyMs,
    bytesSent: new TextEncoder().encode(params.verified.sanitizedText).byteLength,
    payloadPreview: usedServerTemplate
      ? `Server Prompt Template (${templateId}) audited sanitized skeleton (${params.verified.receipt.redactedCount} redacted tokens).`
      : `ONLY_IN_CLOUD fallback audited sanitized skeleton (${params.verified.receipt.redactedCount} redacted tokens).`,
  });

  // Extract a zero-PII 1-line summary for the Firestore Audit Ledger
  const riskMatch = sanitizedMarkdown.match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i);
  const riskLevel = riskMatch?.[1]?.toUpperCase() ?? "MEDIUM";
  const sanitizedSummary = `Policy ${params.policyProfile} audit: ${params.verified.receipt.redactedCount} entities redacted, 6/6 firewall vectors passed.`;

  let ledgerDocId: string | null = null;
  try {
    ledgerDocId = await writeZeroPiiAuditLedger({
      ...params.verified.receipt,
      inferenceSource: "IN_CLOUD",
      riskLevel,
      sanitizedSummary,
    });
  } catch {
    // Offline or Firestore rules not yet deployed — audit result still succeeds locally
  }

  return {
    sanitizedMarkdown,
    rehydratedMarkdown,
    usedServerTemplate,
    templateId,
    inferenceSource: "IN_CLOUD",
    latencyMs,
    ledgerDocId,
  };
}
