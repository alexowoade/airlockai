import { initializeApp, type FirebaseApp } from "firebase/app";
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "firebase/app-check";
import { getAuth, signInAnonymously, type Auth } from "firebase/auth";
import {
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDocs,
  getFirestore,
  limit,
  orderBy,
  query,
  updateDoc,
  type Firestore,
} from "firebase/firestore";
import { fetchAndActivate, getRemoteConfig, getValue, type RemoteConfig } from "firebase/remote-config";
import {
  getAI,
  getGenerativeModel,
  getTemplateGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  Schema,
  type AI,
  type GenerativeModel,
  type TemplateGenerativeModel,
} from "firebase/ai";
import type { AirlockReceipt, PolicyProfile } from "@airlock/core";
import { ZK_ORACLE_FUNCTION_DECLARATIONS } from "../utils/zkOracleTools.js";

export interface AirlockPolicyConfig {
  readonly profile: PolicyProfile;
  readonly templateId: string;
  readonly blockOnMediumConfidence: boolean;
  readonly maxCloudTokens: number;
}

export const DEFAULT_POLICY: AirlockPolicyConfig = {
  profile: "NDA_STRICT",
  templateId: "airlock-nda-v1-0-0",
  blockOnMediumConfidence: true,
  maxCloudTokens: 1200,
};

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

export const activeProjectId = firebaseConfig.projectId ?? "local-demo";

export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.appId
);

/**
 * Structured schema shared for Gate 2 semantic + multimodal on-device PII extraction.
 */
const semanticPiiSchema = Schema.object({
  properties: {
    extractedText: Schema.string({
      description: "Full plain-text transcription if an image was supplied; otherwise empty string.",
    }),
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

/**
 * Structured schema shared between on-device Nano and cloud fallback for offline triage.
 */
const triageSchema = Schema.object({
  properties: {
    documentType: Schema.enumString({ enum: ["NDA", "MEDICAL_BILL", "INVOICE", "CONTRACT", "OTHER"] }),
    quickRiskLevel: Schema.enumString({ enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }),
    oneLineSummary: Schema.string({
      description: "One-sentence summary using ONLY the redacted placeholder tokens.",
    }),
  },
});

/**
 * Structured JSON schema for interactive Deep Cloud Audit redline cards.
 * Preserves redacted placeholders like [ORG_1] or [CURRENCY_1] verbatim for local re-hydration.
 */
const structuredAuditSchema = Schema.object({
  properties: {
    overallRiskLevel: Schema.enumString({ enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }),
    executiveSummary: Schema.string({
      description: "2-sentence executive compliance summary preserving placeholder tokens verbatim.",
    }),
    clauses: Schema.array({
      items: Schema.object({
        properties: {
          clauseTitle: Schema.string({ description: "Short clause title (3-6 words)." }),
          severity: Schema.enumString({ enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }),
          issue: Schema.string({
            description: "Concise legal/compliance risk explanation using placeholder tokens verbatim.",
          }),
          quotedExcerpt: Schema.string({
            description: "Short sanitized excerpt from the document referencing the risky term.",
          }),
          redlineCounterProposal: Schema.string({
            description: "Drop-in replacement clause wording preserving all placeholder tokens verbatim.",
          }),
        },
      }),
    }),
  },
});

export interface FirebaseHandles {
  app: FirebaseApp;
  auth: Auth;
  db: Firestore;
  remoteConfig: RemoteConfig;
  ai: AI;
  localPiiModel: GenerativeModel;
  hybridTriageModel: GenerativeModel;
  templateAuditModel: TemplateGenerativeModel;
  cloudAuditFallbackModel: GenerativeModel;
  structuredAuditModel: GenerativeModel;
  zkOracleModel: GenerativeModel;
}

let cachedHandles: FirebaseHandles | null = null;

export function getFirebaseHandles(): FirebaseHandles | null {
  if (!isFirebaseConfigured) return null;
  if (cachedHandles) return cachedHandles;

  const app = initializeApp(firebaseConfig);

  if (import.meta.env.DEV) {
    (self as unknown as Record<string, unknown>).FIREBASE_APPCHECK_DEBUG_TOKEN = true;
  }

  initializeAppCheck(app, {
    provider: new ReCaptchaEnterpriseProvider(
      (import.meta.env.VITE_RECAPTCHA_SITE_KEY as string | undefined) || "dev-placeholder"
    ),
    isTokenAutoRefreshEnabled: true,
  });

  const auth = getAuth(app);
  const db = getFirestore(app);
  const remoteConfig = getRemoteConfig(app);
  remoteConfig.settings.minimumFetchIntervalMillis = import.meta.env.DEV ? 10_000 : 300_000;
  remoteConfig.defaultConfig = {
    airlock_policy: JSON.stringify(DEFAULT_POLICY),
  };

  const ai = getAI(app, { backend: new GoogleAIBackend() });

  // 1. Gate 2: STRICTLY ON-DEVICE (Guarded additionally by #10635 runtime check below)
  const localPiiModel = getGenerativeModel(ai, {
    mode: InferenceMode.ONLY_ON_DEVICE,
    onDeviceParams: {
      promptOptions: { responseConstraint: semanticPiiSchema },
    },
  });

  // 2. Offline Triage: PREFER_ON_DEVICE with structured output on BOTH paths
  const hybridTriageModel = getGenerativeModel(ai, {
    mode: InferenceMode.PREFER_ON_DEVICE,
    onDeviceParams: {
      promptOptions: { responseConstraint: triageSchema },
    },
    inCloudParams: {
      model: "gemini-3.5-flash-lite",
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: triageSchema,
      },
    },
  });

  // 3. Deep Cloud Audit via locked Server Prompt Templates
  const templateAuditModel = getTemplateGenerativeModel(ai);

  // 4. Fallback Cloud Audit model (ONLY_IN_CLOUD) if server templates are not yet created
  const cloudAuditFallbackModel = getGenerativeModel(ai, {
    mode: InferenceMode.ONLY_IN_CLOUD,
    inCloudParams: {
      model: "gemini-3.5-flash-lite",
    },
  });

  // 5. Structured JSON Clause Redline model (ONLY_IN_CLOUD with Firebase AI Logic Schema)
  const structuredAuditModel = getGenerativeModel(ai, {
    mode: InferenceMode.ONLY_IN_CLOUD,
    inCloudParams: {
      model: "gemini-3.5-flash-lite",
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: structuredAuditSchema,
        maxOutputTokens: 1400,
      },
    },
  });

  // 6. Zero-Knowledge Local Oracle Model (ONLY_IN_CLOUD + Native Function Calling)
  const zkOracleModel = getGenerativeModel(ai, {
    model: "gemini-3.5-flash-lite",
    tools: [{ functionDeclarations: ZK_ORACLE_FUNCTION_DECLARATIONS }],
    generationConfig: {
      maxOutputTokens: 1400,
    },
  });

  cachedHandles = {
    app,
    auth,
    db,
    remoteConfig,
    ai,
    localPiiModel,
    hybridTriageModel,
    templateAuditModel,
    cloudAuditFallbackModel,
    structuredAuditModel,
    zkOracleModel,
  };
  return cachedHandles;
}

export type LocalNanoStatus = "available" | "downloadable" | "downloading" | "unavailable";

interface BrowserLanguageModelApi {
  availability: () => Promise<LocalNanoStatus>;
  create: (opts?: {
    monitor?: (m: EventTarget) => void;
  }) => Promise<{ destroy?: () => void }>;
}

function getBrowserLanguageModel(): BrowserLanguageModelApi | null {
  const api = (globalThis as unknown as { LanguageModel?: BrowserLanguageModelApi }).LanguageModel;
  return api ?? null;
}

/**
 * Defense against firebase-js-sdk#10635:
 * Verifies Chrome's native LanguageModel is genuinely present and "available"
 * BEFORE invoking Firebase's ONLY_ON_DEVICE mode, preventing accidental cloud fallback.
 */
export async function checkLocalNanoStatus(): Promise<LocalNanoStatus> {
  const api = getBrowserLanguageModel();
  if (!api) return "unavailable";
  try {
    return await api.availability();
  } catch {
    return "unavailable";
  }
}

export async function triggerLocalNanoDownload(
  onProgress: (pct: number) => void
): Promise<LocalNanoStatus> {
  const api = getBrowserLanguageModel();
  if (!api) return "unavailable";
  const session = await api.create({
    monitor(m) {
      m.addEventListener("downloadprogress", (ev: Event) => {
        const loaded = (ev as Event & { loaded?: number }).loaded ?? 0;
        onProgress(Math.round(loaded * 100));
      });
    },
  });
  session.destroy?.();
  return checkLocalNanoStatus();
}

export async function fetchRemotePolicy(): Promise<AirlockPolicyConfig> {
  const handles = getFirebaseHandles();
  if (!handles) return DEFAULT_POLICY;
  try {
    await fetchAndActivate(handles.remoteConfig);
    const raw = getValue(handles.remoteConfig, "airlock_policy").asString();
    return JSON.parse(raw) as AirlockPolicyConfig;
  } catch {
    return DEFAULT_POLICY;
  }
}

export interface LedgerEntry extends AirlockReceipt {
  readonly inferenceSource: "ON_DEVICE" | "IN_CLOUD";
  readonly riskLevel: string;
  readonly sanitizedSummary: string;
}

export interface LedgerRecord extends LedgerEntry {
  readonly docId: string;
}

export async function writeZeroPiiAuditLedger(entry: LedgerEntry): Promise<string | null> {
  const handles = getFirebaseHandles();
  if (!handles) return null;
  if (!handles.auth.currentUser) {
    await signInAnonymously(handles.auth);
  }
  const uid = handles.auth.currentUser!.uid;
  const ref = await addDoc(collection(handles.db, "users", uid, "audit_ledger"), {
    ...entry,
  });
  return ref.id;
}

export async function fetchZeroPiiAuditLedger(): Promise<ReadonlyArray<LedgerRecord>> {
  const handles = getFirebaseHandles();
  if (!handles) return [];
  if (!handles.auth.currentUser) {
    await signInAnonymously(handles.auth);
  }
  const uid = handles.auth.currentUser!.uid;
  const q = query(
    collection(handles.db, "users", uid, "audit_ledger"),
    orderBy("timestampIso", "desc"),
    limit(15)
  );
  const snap = await getDocs(q);
  return snap.docs.map((d) => ({
    ...(d.data() as LedgerEntry),
    docId: d.id,
  }));
}

export type Layer4AttackMode = "RAW_PII_INJECTION" | "LEDGER_OVERWRITE" | "LEDGER_DELETE";

export interface Layer4AttackResult {
  readonly mode: Layer4AttackMode;
  readonly blockedByRules: boolean;
  readonly errorCode: string;
  readonly ruleEnforced: string;
  readonly detail: string;
  readonly latencyMs: number;
}

/**
 * Live Layer-4 Red-Team Proof:
 * Intentionally bypasses all client-side Airlock gates and attacks Cloud Firestore directly
 * to prove server-side firestore.rules (hasNoRawPii + append-only immutability) reject a
 * compromised client with PERMISSION_DENIED.
 */
export async function runLayer4FirestoreAttack(
  mode: Layer4AttackMode,
  targetDocId?: string
): Promise<Layer4AttackResult> {
  const handles = getFirebaseHandles();
  if (!handles) {
    throw new Error("Firebase must be connected to test live Cloud Firestore Security Rules.");
  }
  if (!handles.auth.currentUser) {
    await signInAnonymously(handles.auth);
  }
  const uid = handles.auth.currentUser!.uid;
  const t0 = performance.now();

  const ruleEnforced =
    mode === "RAW_PII_INJECTION"
      ? "firestore.rules :: hasNoRawPii(sanitizedSummary)"
      : "firestore.rules :: allow update, delete: if false (append-only ledger)";

  try {
    if (mode === "RAW_PII_INJECTION") {
      const dummyHash = "a".repeat(64);
      await addDoc(collection(handles.db, "users", uid, "audit_ledger"), {
        receiptVersion: "airlock.v1",
        rawDocSha256: dummyHash,
        sanitizedPayloadSha256: dummyHash,
        prevReceiptSha256: null,
        receiptSha256: dummyHash,
        redactedCount: 0,
        checksPassed: 6,
        firewallPassed: true,
        policyProfile: "NDA_STRICT",
        timestampIso: new Date().toISOString(),
        inferenceSource: "IN_CLOUD",
        riskLevel: "CRITICAL",
        sanitizedSummary:
          "BYPASS ATTACK: Raw SSN 912-45-6789 and email elena.vance@helios-robotics.test",
      });
    } else if (mode === "LEDGER_OVERWRITE") {
      const ref = doc(handles.db, "users", uid, "audit_ledger", targetDocId ?? "append-only-probe");
      await updateDoc(ref, {
        riskLevel: "LOW",
        sanitizedSummary: "TAMPERED_BY_COMPROMISED_CLIENT",
      });
    } else {
      const ref = doc(handles.db, "users", uid, "audit_ledger", targetDocId ?? "append-only-probe");
      await deleteDoc(ref);
    }

    return {
      mode,
      blockedByRules: false,
      errorCode: "UNEXPECTED_ALLOW",
      ruleEnforced,
      detail: "WARNING: Firestore accepted the attack payload. Verify firestore.rules deployment.",
      latencyMs: Math.max(1, Math.round(performance.now() - t0)),
    };
  } catch (err) {
    const code =
      typeof err === "object" && err !== null && "code" in err
        ? String((err as { code?: unknown }).code)
        : "permission-denied";
    const msg = err instanceof Error ? err.message : String(err);
    const isPermissionDenied =
      code.toLowerCase().includes("permission-denied") ||
      msg.toLowerCase().includes("missing or insufficient permissions");

    return {
      mode,
      blockedByRules: isPermissionDenied,
      errorCode: code,
      ruleEnforced,
      detail: isPermissionDenied
        ? `Cloud Firestore server rejected the bypassed request (${code}). Zero PII stored; ledger immutable.`
        : `Firestore request failed with ${code}: ${msg}`,
      latencyMs: Math.max(1, Math.round(performance.now() - t0)),
    };
  }
}
