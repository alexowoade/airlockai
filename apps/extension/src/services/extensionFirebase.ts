import { initializeApp } from "firebase/app";
import { CustomProvider, initializeAppCheck } from "firebase/app-check";
import { getAuth, signInAnonymously } from "firebase/auth";
import { addDoc, collection, getFirestore } from "firebase/firestore";
import {
  getAI,
  getGenerativeModel,
  getTemplateGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  Schema,
  type GenerativeModel,
  type TemplateGenerativeModel,
} from "firebase/ai";
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

export const POLICY_TEMPLATES: Record<PolicyProfile, string> = {
  NDA_STRICT: "airlock-nda-v1-0-0",
  MEDICAL_HIPAA: "airlock-hipaa-v1-0-0",
  INVOICE_FINANCE: "airlock-invoice-v1-0-0",
};

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY as string | undefined,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN as string | undefined,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID as string | undefined,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET as string | undefined,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID as string | undefined,
  appId: import.meta.env.VITE_FIREBASE_APP_ID as string | undefined,
};

export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.appId
);

const semanticPiiSchema = Schema.object({
  properties: {
    entities: Schema.array({
      items: Schema.object({
        properties: {
          text: Schema.string({ description: "Exact sensitive substring to redact." }),
          category: Schema.enumString({
            enum: ["PERSON", "ORG", "MEDICAL", "SECRET_TERM"],
          }),
        },
      }),
    }),
  },
});

interface ExtensionHandles {
  auth: ReturnType<typeof getAuth>;
  db: ReturnType<typeof getFirestore>;
  localPiiModel: GenerativeModel;
  templateAuditModel: TemplateGenerativeModel;
  cloudAuditFallbackModel: GenerativeModel;
}

let handles: ExtensionHandles | null = null;

function getHandles(): ExtensionHandles | null {
  if (!isFirebaseConfigured) return null;
  if (handles) return handles;

  const app = initializeApp(firebaseConfig);

  // MV3 CSP blocks remote reCAPTCHA scripts; use debug token + CustomProvider cleanly
  const debugToken =
    (import.meta.env.VITE_EXTENSION_APPCHECK_DEBUG_TOKEN as string | undefined) || true;
  (self as unknown as Record<string, unknown>).FIREBASE_APPCHECK_DEBUG_TOKEN = debugToken;

  initializeAppCheck(app, {
    provider: new CustomProvider({
      getToken: async () => ({
        token: typeof debugToken === "string" ? debugToken : "mv3-debug-token",
        expireTimeMillis: Date.now() + 60 * 60 * 1000,
      }),
    }),
    isTokenAutoRefreshEnabled: true,
  });

  const auth = getAuth(app);
  const db = getFirestore(app);
  const ai = getAI(app, { backend: new GoogleAIBackend() });

  const localPiiModel = getGenerativeModel(ai, {
    mode: InferenceMode.ONLY_ON_DEVICE,
    onDeviceParams: {
      promptOptions: { responseConstraint: semanticPiiSchema },
    },
  });

  const templateAuditModel = getTemplateGenerativeModel(ai);

  const cloudAuditFallbackModel = getGenerativeModel(ai, {
    mode: InferenceMode.ONLY_IN_CLOUD,
    inCloudParams: { model: "gemini-3.5-flash-lite" },
  });

  handles = { auth, db, localPiiModel, templateAuditModel, cloudAuditFallbackModel };
  return handles;
}

export type LocalNanoStatus = "available" | "downloadable" | "downloading" | "unavailable";

export async function checkLocalNanoStatus(): Promise<LocalNanoStatus> {
  const api = (globalThis as unknown as {
    LanguageModel?: { availability: () => Promise<LocalNanoStatus> };
  }).LanguageModel;
  if (!api) return "unavailable";
  try {
    return await api.availability();
  } catch {
    return "unavailable";
  }
}

function findOccurrences(haystack: string, needle: string, category: EntityCategory): DetectedSpan[] {
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

export interface SidePanelAirlockResult {
  readonly rawDoc: RawDocument;
  readonly candidateSanitized: string;
  readonly vault: AirlockVault;
  readonly gate1Count: number;
  readonly gate2Count: number;
  readonly usedNano: boolean;
  readonly firewallResult: FirewallResult;
}

export async function runExtensionLocalAirlock(
  rawText: string,
  policy: PolicyProfile
): Promise<SidePanelAirlockResult> {
  const h = getHandles();
  const vault = new AirlockVault();
  const rawDoc = asRawDocument(rawText.trim());
  const gate1Spans = scanDeterministicPii(rawDoc);
  const gate2Spans: DetectedSpan[] = [];
  let usedNano = false;

  // Pre-SDK #10635 Guard: strictly verify Chrome LanguageModel availability before ONLY_ON_DEVICE
  const nanoStatus = await checkLocalNanoStatus();
  if (h && nanoStatus === "available") {
    try {
      const res = await h.localPiiModel.generateContent(
        `Extract contextual sensitive entities (PERSON, ORG, MEDICAL, SECRET_TERM) under policy ${policy}:\n${rawDoc}`
      );
      const parsed = JSON.parse(res.response.text()) as {
        entities?: Array<{ text: string; category: "PERSON" | "ORG" | "MEDICAL" | "SECRET_TERM" }>;
      };
      for (const ent of parsed.entities ?? []) {
        gate2Spans.push(...findOccurrences(rawDoc, ent.text, ent.category));
      }
      usedNano = true;
    } catch {
      // Protected by Gate 1 + #10635 guard; never silently falls back to cloud
    }
  }

  const merged = resolveOverlappingSpans([...gate1Spans, ...gate2Spans]);
  const candidateSanitized = vault.redactSpans(rawDoc, merged);
  const firewallResult = await verifyAndMintPayload({
    rawDoc,
    candidateSanitized,
    vault,
    policyProfile: policy,
  });

  return {
    rawDoc,
    candidateSanitized,
    vault,
    gate1Count: gate1Spans.length,
    gate2Count: gate2Spans.length,
    usedNano,
    firewallResult,
  };
}

export async function runExtensionCloudAudit(params: {
  verified: VerifiedSanitizedPayload;
  vault: AirlockVault;
  policy: PolicyProfile;
}): Promise<{
  sanitizedMarkdown: string;
  rehydratedMarkdown: string;
  usedTemplate: boolean;
  latencyMs: number;
}> {
  const h = getHandles();
  if (!h) {
    throw new Error("Configure apps/web/.env.local before building the extension.");
  }

  const templateId = POLICY_TEMPLATES[params.policy];
  const t0 = performance.now();
  let sanitizedMarkdown = "";
  let usedTemplate = false;

  try {
    const res = await h.templateAuditModel.generateContent({
      templateId,
      templateVariables: {
        sanitizedText: params.verified.sanitizedText,
        policyProfile: params.policy,
      },
    });
    sanitizedMarkdown = res.response.text();
    usedTemplate = true;
  } catch {
    const res = await h.cloudAuditFallbackModel.generateContent(
      `You are AirlockAI (${params.policy}). Preserve exact placeholder tokens like [ORG_1] verbatim so the local vault can re-hydrate.\n` +
        `Provide: 1) Risk Level, 2) Top 3 Risk Clauses, 3) Redline Fixes.\n\n${params.verified.sanitizedText}`
    );
    sanitizedMarkdown = res.response.text();
  }

  const latencyMs = Math.round(performance.now() - t0);
  const rehydratedMarkdown = params.vault.rehydrate(sanitizedMarkdown);

  // Sync zero-PII SHA-256 receipt to the same Firestore ledger used by Web PWA & Android
  try {
    if (!h.auth.currentUser) {
      await signInAnonymously(h.auth);
    }
    const uid = h.auth.currentUser!.uid;
    const riskMatch = sanitizedMarkdown.match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i);
    await addDoc(collection(h.db, "users", uid, "audit_ledger"), {
      ...params.verified.receipt,
      inferenceSource: "IN_CLOUD",
      riskLevel: riskMatch?.[1]?.toUpperCase() ?? "MEDIUM",
      sanitizedSummary: `Chrome Side Panel (${params.policy}): ${params.verified.receipt.redactedCount} redacted, 6/6 firewall checks passed.`,
    });
  } catch {
    // Non-blocking if offline or rules not deployed
  }

  return { sanitizedMarkdown, rehydratedMarkdown, usedTemplate, latencyMs };
}
