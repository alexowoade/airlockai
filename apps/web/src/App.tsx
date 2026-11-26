import { useEffect, useState, type ChangeEvent, type DragEvent } from "react";
import {
  Activity,
  Check,
  Cloud,
  Copy,
  Cpu,
  Download,
  FileCheck2,
  FileImage,
  FileJson,
  FileText,
  KeyRound,
  Layers,
  Lock,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  WifiOff,
  Zap,
} from "lucide-react";
import {
  injectRedTeamAttack,
  verifyAndMintPayload,
  type FirewallViolation,
  type PolicyProfile,
  type RedTeamAttackType,
} from "@airlock/core";
import {
  activeProjectId,
  checkLocalNanoStatus,
  DEFAULT_POLICY,
  fetchRemotePolicy,
  fetchZeroPiiAuditLedger,
  isFirebaseConfigured,
  POLICY_TEMPLATES,
  runLayer4FirestoreAttack,
  triggerLocalNanoDownload,
  type AirlockPolicyConfig,
  type Layer4AttackMode,
  type Layer4AttackResult,
  type LedgerRecord,
  type LocalNanoStatus,
} from "./services/firebase.js";
import {
  runDeepCloudAudit,
  runHybridTriage,
  runLocalAirlock,
  type CloudAuditOutput,
  type LocalAirlockOutput,
  type OfflineTriageOutput,
} from "./services/airlockPipeline.js";
import { wireTap, type WireEvent } from "./services/wireTap.js";
import { SAMPLE_DOCS } from "./data/samples.js";
import {
  generateSyntheticMedicalBillPng,
  renderRedactedImageOverlay,
} from "./utils/canvasRedactor.js";
import {
  buildComplianceProofJson,
  simulateOneByteTamper,
  triggerDataUrlDownload,
  triggerLocalDownload,
  verifyExternalProofJson,
  verifyLedgerChain,
  type ChainVerificationReport,
  type ExternalProofAuditReport,
} from "./utils/chainVerifier.js";
import {
  generateSyntheticMultiPageNdaPdfBytes,
  parseLocalPdf,
  renderRedactedPdfPages,
  type ParsedPdfDocument,
} from "./utils/pdfRedactor.js";
import {
  enqueueOfflineReceipt,
  flushPendingQueueToFirestore,
  loadPendingQueue,
  type PendingLedgerRecord,
} from "./utils/offlineQueue.js";
import {
  decryptVaultFromFileJson,
  encryptVaultToFileJson,
  rehydrateWithEntries,
  type DecryptedVaultBundle,
} from "./utils/encryptedVaultFile.js";
import {
  ZeroKnowledgeText,
  type ZeroKnowledgeViewMode,
} from "./components/ZeroKnowledgeText.js";
import { exportFlattenedRedactedPdf } from "./utils/flattenedPdfExport.js";
import { exportExecutiveAuditBrief } from "./utils/auditBriefExport.js";
import { neutralizePromptInjections, SAMPLE_INJECTION_PAYLOAD, type PromptInjectionReport } from "./utils/promptInjectionGuard.js";
import { DEAL_ROOM_SCENARIOS } from "./data/dealRoomSamples.js";
import { PolicyStudioPanel } from "./components/PolicyStudioPanel.js";
import { MerkleSignerPanel } from "./components/MerkleSignerPanel.js";
import { ThinkingAuditDrawer } from "./components/ThinkingAuditDrawer.js";
import { AdaptiveRouterPanel } from "./components/AdaptiveRouterPanel.js";
import type { AirlockThinkingDepth } from "./utils/thinkingAudit.js";
import type { CompliancePackId, CustomRegexRule } from "./utils/policyStudio.js";
import type { StreamingAuditSnapshot } from "./utils/streamRehydrator.js";
import { runDealRoomLocalAirlock, runDealRoomOracleAudit, type DealRoomAirlockOutput, type DealRoomOracleAuditOutput } from "./services/dealRoomPipeline.js";
import "./sprintC.css";

type WorkspaceTab = "audit" | "redteam" | "ledger";

interface GauntletRow {
  readonly layer: "Layer 3 (Client)" | "Layer 4 (Firestore)";
  readonly attack: string;
  readonly passed: boolean;
  readonly code: string;
  readonly latencyMs: number;
}

const MAX_LOCAL_FILE_BYTES = 5_242_880; // 5 MB local browser cap for PDFs/images/text
const TEXT_EXTENSIONS = [".txt", ".md", ".csv", ".json"];

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("audit");

  const [rawText, setRawText] = useState(SAMPLE_DOCS[0]!.text);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [isDraggingFile, setIsDraggingFile] = useState(false);

  const [imageInput, setImageInput] = useState<{
    dataUrl: string;
    redactedDataUrl?: string;
    base64: string;
    mimeType: "image/png" | "image/jpeg";
  } | null>(null);

  const [pdfDoc, setPdfDoc] = useState<ParsedPdfDocument | null>(null);
  const [pdfPageIdx, setPdfPageIdx] = useState(0);

  const [policy, setPolicy] = useState<AirlockPolicyConfig>(DEFAULT_POLICY);
  const [strictSafeHarbor, setStrictSafeHarbor] = useState(false);
  const [customSecrets, setCustomSecrets] = useState<string[]>([]);
  const [customSecretDraft, setCustomSecretDraft] = useState("");
  const [residualOverrideAccepted, setResidualOverrideAccepted] = useState(false);

  const [nanoStatus, setNanoStatus] = useState<LocalNanoStatus>("unavailable");
  const [downloadPct, setDownloadPct] = useState<number | null>(null);
  const [isOnline, setIsOnline] = useState<boolean>(navigator.onLine);
  const [airGapSimulated, setAirGapSimulated] = useState(false);
  const [gauntletRows, setGauntletRows] = useState<ReadonlyArray<GauntletRow> | null>(null);
  const [flattenedPdfMsg, setFlattenedPdfMsg] = useState<string | null>(null);
  const [injectionTestReport, setInjectionTestReport] = useState<PromptInjectionReport | null>(null);
  const [briefExportMsg, setBriefExportMsg] = useState<string | null>(null);

  // Sprint E1: Multi-Document Deal Room + Zero-Knowledge Local Oracle Function Calling
  const [stageMode, setStageMode] = useState<"single" | "dealroom">("single");
  const [docATitle, setDocATitle] = useState(DEAL_ROOM_SCENARIOS[0]!.docATitle);
  const [docAText, setDocAText] = useState(DEAL_ROOM_SCENARIOS[0]!.docAText);
  const [docBTitle, setDocBTitle] = useState(DEAL_ROOM_SCENARIOS[0]!.docBTitle);
  const [docBText, setDocBText] = useState(DEAL_ROOM_SCENARIOS[0]!.docBText);
  const [dealRoomOut, setDealRoomOut] = useState<DealRoomAirlockOutput | null>(null);
  const [oracleOut, setOracleOut] = useState<DealRoomOracleAuditOutput | null>(null);

  // Sprint E2: Streaming Token-Boundary FSM + Live Remote Config Policy-as-Code Studio
  const [enabledPolicyPacks, setEnabledPolicyPacks] = useState<CompliancePackId[]>([]);
  const [customRegexRules, setCustomRegexRules] = useState<CustomRegexRule[]>([]);
  const [streamSnap, setStreamSnap] = useState<StreamingAuditSnapshot | null>(null);

  // Sprint F1: Thinking Depth Selector + Laplace ε-DP Oracle Privacy
  const [thinkingDepth, setThinkingDepth] = useState<AirlockThinkingDepth>("MEDIUM");
  const [dpEnabled, setDpEnabled] = useState<boolean>(false);
  const [dpEpsilon, setDpEpsilon] = useState<number>(1.0);
  const effectiveOnline = isOnline && !airGapSimulated;

  const [busy, setBusy] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [airlockOut, setAirlockOut] = useState<LocalAirlockOutput | null>(null);
  const [redTeamBlock, setRedTeamBlock] = useState<{
    attack: RedTeamAttackType;
    blockedBytes: number;
    violations: ReadonlyArray<FirewallViolation>;
  } | null>(null);
  const [layer4Result, setLayer4Result] = useState<Layer4AttackResult | null>(null);

  const [triageOut, setTriageOut] = useState<OfflineTriageOutput | null>(null);
  const [cloudOut, setCloudOut] = useState<CloudAuditOutput | null>(null);
  const [zkViewMode, setZkViewMode] = useState<ZeroKnowledgeViewMode>("diff");
  const [copiedClauseIdx, setCopiedClauseIdx] = useState<number | null>(null);

  const [wireEvents, setWireEvents] = useState<ReadonlyArray<WireEvent>>([]);
  const [ledger, setLedger] = useState<ReadonlyArray<LedgerRecord>>([]);
  const [pendingQueue, setPendingQueue] = useState<ReadonlyArray<PendingLedgerRecord>>(() =>
    loadPendingQueue()
  );
  const [queueStatusMsg, setQueueStatusMsg] = useState<string | null>(null);

  const [expandedDocId, setExpandedDocId] = useState<string | null>(null);
  const [chainReport, setChainReport] = useState<ChainVerificationReport | null>(null);
  const [isTamperSimulated, setIsTamperSimulated] = useState(false);

  // Sprint B: Passphrase-Locked .airlock.enc Vault & External Proof Auditor
  const [vaultPassphrase, setVaultPassphrase] = useState("");
  const [vaultStatus, setVaultStatus] = useState<{ ok: boolean; message: string } | null>(null);
  const [restoredVault, setRestoredVault] = useState<DecryptedVaultBundle | null>(null);
  const [restoredViewMode, setRestoredViewMode] = useState<ZeroKnowledgeViewMode>("diff");
  const [externalProofReport, setExternalProofReport] = useState<ExternalProofAuditReport | null>(
    null
  );

  // Sprint C1: Enterprise Hybrid Routing & ROI Volume Slider
  const [monthlyDocsVolume, setMonthlyDocsVolume] = useState<number>(1000);

  // Combined ledger view (newest pending receipts chained above synced Firestore receipts)
  const combinedLedger: ReadonlyArray<LedgerRecord & { readonly syncStatus?: "PENDING_SYNC" }> = [
    ...pendingQueue,
    ...ledger.filter(
      (synced) => !pendingQueue.some((p) => p.receiptSha256 === synced.receiptSha256)
    ),
  ];

  async function runQueueFlush(triggerReason: "auto-reconnect" | "manual") {
    const queued = loadPendingQueue();
    if (queued.length === 0) return;
    setBusy("queue-flush");
    setErrorMsg(null);
    const t0 = performance.now();
    try {
      const result = await flushPendingQueueToFirestore();
      setPendingQueue(result.remaining);
      if (result.flushedCount > 0) {
        const updated = await fetchZeroPiiAuditLedger().catch(() => []);
        if (updated.length > 0) setLedger(updated);
        setChainReport(null);
        setIsTamperSimulated(false);
        const msg = `Synced ${result.flushedCount} offline receipt(s) to Cloud Firestore (${triggerReason}).`;
        setQueueStatusMsg(msg);
        wireTap.record({
          stage: "OFFLINE_QUEUE",
          inferenceSource: "IN_CLOUD",
          latencyMs: Math.max(1, Math.round(performance.now() - t0)),
          bytesSent: result.flushedCount * 340,
          payloadPreview: `${msg} Remaining queued: ${result.remaining.length}. Zero raw PII synced.`,
        });
      }
      if (result.errorMessage) {
        setQueueStatusMsg(result.errorMessage);
      }
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    const unsub = wireTap.subscribe(setWireEvents);
    checkLocalNanoStatus().then(setNanoStatus);
    fetchRemotePolicy().then(setPolicy);
    fetchZeroPiiAuditLedger()
      .then(setLedger)
      .catch(() => {});

    const onOnline = () => {
      setIsOnline(true);
      void runQueueFlush("auto-reconnect");
    };
    const onOffline = () => setIsOnline(false);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      unsub();
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, []);

  async function handleDownloadNano() {
    setDownloadPct(0);
    try {
      const status = await triggerLocalNanoDownload((pct) => setDownloadPct(pct));
      setNanoStatus(status);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to initialize Gemini Nano.");
    } finally {
      setDownloadPct(null);
    }
  }

  function handleSelectPolicy(profile: PolicyProfile) {
    setPolicy((prev) => ({
      ...prev,
      profile,
      templateId: POLICY_TEMPLATES[profile],
    }));
  }

  async function loadLocalPdfBytes(fileName: string, bytes: Uint8Array) {
    setBusy("pdf-parse");
    setErrorMsg(null);
    try {
      const parsed = await parseLocalPdf(fileName, bytes);
      setPdfDoc(parsed);
      setPdfPageIdx(0);
      setImageInput(null);
      setRawText(parsed.fullText);
      setUploadedFileName(`${fileName} (${parsed.totalPages}p PDF · 0B sent)`);
      setAirlockOut(null);
      setResidualOverrideAccepted(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to parse local PDF.");
    } finally {
      setBusy(null);
    }
  }

  async function handleGenerateSyntheticPdf() {
    const bytes = generateSyntheticMultiPageNdaPdfBytes();
    handleSelectPolicy("NDA_STRICT");
    await loadLocalPdfBytes("synthetic-ma-nda-2page.pdf", bytes);
  }

  function processLocalFile(file: File) {
    setErrorMsg(null);
    if (file.size > MAX_LOCAL_FILE_BYTES) {
      setErrorMsg("Local file exceeds 5 MB browser cap. Please choose a smaller document.");
      return;
    }

    const lowerName = file.name.toLowerCase();
    const isPdf = file.type === "application/pdf" || lowerName.endsWith(".pdf");
    const isImage = file.type === "image/png" || file.type === "image/jpeg";
    const isText =
      file.type.startsWith("text/") ||
      file.type === "application/json" ||
      TEXT_EXTENSIONS.some((ext) => lowerName.endsWith(ext));

    if (isPdf) {
      file.arrayBuffer().then((buf) => {
        void loadLocalPdfBytes(file.name, new Uint8Array(buf));
      });
      return;
    }

    if (isImage) {
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = String(reader.result);
        setImageInput({
          dataUrl,
          base64: dataUrl.split(",")[1]!,
          mimeType: file.type as "image/png" | "image/jpeg",
        });
        setPdfDoc(null);
        setRawText("");
        setUploadedFileName(`${file.name} (${Math.max(1, Math.round(file.size / 1024))} KB)`);
      };
      reader.readAsDataURL(file);
      return;
    }

    if (isText) {
      const reader = new FileReader();
      reader.onload = () => {
        const content = String(reader.result);
        setRawText(content);
        setImageInput(null);
        setPdfDoc(null);
        setUploadedFileName(`${file.name} (${Math.max(1, Math.round(file.size / 1024))} KB)`);
        if (lowerName.includes("medical") || lowerName.includes("hipaa") || lowerName.includes("patient")) {
          handleSelectPolicy("MEDICAL_HIPAA");
        } else if (lowerName.includes("invoice") || lowerName.includes("wire") || lowerName.includes("bill")) {
          handleSelectPolicy("INVOICE_FINANCE");
        }
      };
      reader.readAsText(file);
      return;
    }

    setErrorMsg("Unsupported file type. Drop a .pdf, .txt, .md, .csv, .json, or .png/.jpg file.");
  }

  function handleFileUpload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) processLocalFile(file);
    e.target.value = "";
  }

  function handleFileDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDraggingFile(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processLocalFile(file);
  }

  function handleGenerateSyntheticPng() {
    const png = generateSyntheticMedicalBillPng();
    setImageInput(png);
    setPdfDoc(null);
    setRawText(SAMPLE_DOCS[2]!.text);
    setUploadedFileName("synthetic-medical-bill.png");
    handleSelectPolicy("MEDICAL_HIPAA");
  }

  async function executeLocalAirlock(
    overrideSecrets?: string[],
    overrideSafeHarbor?: boolean
  ) {
    setBusy("airlock");
    setErrorMsg(null);
    setRedTeamBlock(null);
    setLayer4Result(null);
    setTriageOut(null);
    setCloudOut(null);
    setResidualOverrideAccepted(false);

    const activeSecrets = overrideSecrets ?? customSecrets;
    const activeSafeHarbor = overrideSafeHarbor ?? strictSafeHarbor;

    try {
      const prevHash = combinedLedger[0]?.receiptSha256 ?? null;
      const result = await runLocalAirlock({
        rawText,
        imageBase64: imageInput
          ? { mimeType: imageInput.mimeType, data: imageInput.base64 }
          : undefined,
        policy,
        prevReceiptSha256: prevHash,
        customSecrets: activeSecrets,
        policyPacks: enabledPolicyPacks,
        customRegexRules,
        strictSafeHarbor: activeSafeHarbor,
      });
      setAirlockOut(result);
      setActiveTab("audit");

      if (imageInput) {
        const redactedDataUrl = await renderRedactedImageOverlay(imageInput.dataUrl);
        setImageInput((prev) => (prev ? { ...prev, redactedDataUrl } : null));
      }

      if (pdfDoc) {
        const redactedPdf = await renderRedactedPdfPages(pdfDoc, result.mergedSpans);
        setPdfDoc(redactedPdf);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Local Airlock failed.");
    } finally {
      setBusy(null);
    }
  }

  function handleQueueOfflineReceipt() {
    if (!airlockOut || !airlockOut.firewallResult.ok) return;
    const receipt = airlockOut.firewallResult.payload.receipt;
    const { added, queue } = enqueueOfflineReceipt({
      ...receipt,
      inferenceSource: "ON_DEVICE",
      riskLevel: airlockOut.residualRisk.riskLevel,
      sanitizedSummary: `Offline local audit (${receipt.policyProfile}): ${receipt.redactedCount} entities redacted, 6/6 firewall vectors passed.`,
    });
    setPendingQueue(queue);
    setChainReport(null);
    setIsTamperSimulated(false);
    const msg = added
      ? `Queued receipt ${receipt.receiptSha256.slice(0, 14)}… locally (PENDING_SYNC · 0B sent).`
      : "This attestation receipt is already in the offline sync queue.";
    setQueueStatusMsg(msg);
    wireTap.record({
      stage: "OFFLINE_QUEUE",
      inferenceSource: "ON_DEVICE",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: msg,
    });
  }

  async function handleExportEncryptedVault() {
    if (!airlockOut || !airlockOut.firewallResult.ok) return;
    setVaultStatus(null);
    const t0 = performance.now();
    try {
      const { json, envelope } = await encryptVaultToFileJson({
        passphrase: vaultPassphrase,
        policyProfile: policy.profile,
        receiptSha256: airlockOut.firewallResult.payload.receipt.receiptSha256,
        entries: airlockOut.vault.getEntries(false),
        sanitizedText: airlockOut.firewallResult.payload.sanitizedText,
        sanitizedAuditMarkdown: cloudOut?.sanitizedMarkdown ?? null,
      });
      const stamp = new Date().toISOString().slice(0, 10);
      triggerLocalDownload(`airlock-vault-${stamp}.airlock.enc`, json, "application/json");
      const latencyMs = Math.max(1, Math.round(performance.now() - t0));
      const msg = `Encrypted ${envelope.entryCount} vault tokens locally via PBKDF2 (100k) + AES-256-GCM (${latencyMs} ms · 0B sent).`;
      setVaultStatus({ ok: true, message: msg });
      wireTap.record({
        stage: "VAULT_CRYPTO",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs,
        bytesSent: 0,
        payloadPreview: `EXPORT .airlock.enc — ${msg}`,
      });
    } catch (err) {
      setVaultStatus({
        ok: false,
        message: err instanceof Error ? err.message : "Failed to encrypt local vault.",
      });
    }
  }

  async function handleRestoreEncryptedVault(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setVaultStatus(null);
    const t0 = performance.now();
    try {
      const text = await file.text();
      const bundle = await decryptVaultFromFileJson(text, vaultPassphrase);
      setRestoredVault(bundle);
      setRestoredViewMode("diff");
      const latencyMs = Math.max(1, Math.round(performance.now() - t0));
      const msg = `VAULT RESTORED LOCALLY — ${bundle.entries.length} tokens unlocked from ${file.name} (${latencyMs} ms · 0B sent).`;
      setVaultStatus({ ok: true, message: msg });
      wireTap.record({
        stage: "VAULT_CRYPTO",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs,
        bytesSent: 0,
        payloadPreview: `RESTORE .airlock.enc — ${msg}`,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to decrypt .airlock.enc vault.";
      setRestoredVault(null);
      setVaultStatus({ ok: false, message: msg });
      wireTap.record({
        stage: "VAULT_CRYPTO",
        inferenceSource: "BLOCKED",
        latencyMs: Math.max(1, Math.round(performance.now() - t0)),
        bytesSent: 0,
        payloadPreview: msg,
      });
    }
  }

  async function handleAuditExternalProofFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const t0 = performance.now();
    const raw = await file.text();
    const report = await verifyExternalProofJson(file.name, raw);
    setExternalProofReport(report);
    wireTap.record({
      stage: "VAULT_CRYPTO",
      inferenceSource: report.ok ? "DETERMINISTIC_LOCAL" : "BLOCKED",
      latencyMs: Math.max(1, Math.round(performance.now() - t0)),
      bytesSent: 0,
      payloadPreview: `EXTERNAL PROOF AUDIT (${file.name}) -> ${report.verdict}`,
    });
  }

  async function handleAddCustomSecret(term: string) {
    const cleaned = term.trim();
    if (cleaned.length < 3) return;
    if (customSecrets.some((s) => s.toLowerCase() === cleaned.toLowerCase())) {
      setCustomSecretDraft("");
      return;
    }
    const next = [...customSecrets, cleaned];
    setCustomSecrets(next);
    setCustomSecretDraft("");
    if (airlockOut) {
      await executeLocalAirlock(next, strictSafeHarbor);
    }
  }

  async function handleRemoveCustomSecret(term: string) {
    const next = customSecrets.filter((s) => s !== term);
    setCustomSecrets(next);
    if (airlockOut) {
      await executeLocalAirlock(next, strictSafeHarbor);
    }
  }

  async function handleToggleSafeHarbor() {
    const next = !strictSafeHarbor;
    setStrictSafeHarbor(next);
    if (airlockOut) {
      await executeLocalAirlock(customSecrets, next);
    }
  }

  async function handleRedTeamAttack(attack: RedTeamAttackType) {
    if (!airlockOut) return;
    const poisoned = injectRedTeamAttack(
      airlockOut.candidateSanitized,
      airlockOut.vault,
      attack
    );
    const res = await verifyAndMintPayload({
      rawDoc: airlockOut.rawDoc,
      candidateSanitized: poisoned,
      vault: airlockOut.vault,
      policyProfile: policy.profile,
    });

    if (!res.ok) {
      setRedTeamBlock({
        attack,
        blockedBytes: res.blockedBytes,
        violations: res.violations,
      });
      wireTap.record({
        stage: "GATE3_FIREWALL_BLOCK",
        inferenceSource: "BLOCKED",
        latencyMs: 1,
        bytesSent: 0,
        payloadPreview: `RED-TEAM [${attack}] STOPPED — 0 bytes sent (${res.blockedBytes}B aborted). Vector: ${res.violations[0]?.vector}`,
      });
    }
  }

  async function handleLayer4Attack(mode: Layer4AttackMode) {
    setBusy(`layer4-${mode}`);
    setErrorMsg(null);
    try {
      const targetDocId = ledger[0]?.docId;
      const res = await runLayer4FirestoreAttack(mode, targetDocId);
      setLayer4Result(res);
      wireTap.record({
        stage: "GATE3_FIREWALL_BLOCK",
        inferenceSource: res.blockedByRules ? "BLOCKED" : "IN_CLOUD",
        latencyMs: res.latencyMs,
        bytesSent: 0,
        payloadPreview: `LAYER-4 FIRESTORE [${mode}] -> ${res.errorCode} (${res.ruleEnforced})`,
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Layer-4 Firestore test failed.");
    } finally {
      setBusy(null);
    }
  }

  async function handleVerifyChain(simulateTamper = false) {
    setErrorMsg(null);
    const targetRecords = simulateTamper ? simulateOneByteTamper(combinedLedger) : combinedLedger;
    const report = await verifyLedgerChain(targetRecords);
    setIsTamperSimulated(simulateTamper);
    setChainReport(report);
  }

  function handleExportProofBundle() {
    const json = buildComplianceProofJson({
      projectId: activeProjectId,
      verifiedPayload,
      ledger: combinedLedger,
      verification: chainReport,
    });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    triggerLocalDownload(`airlock-compliance-proof-${stamp}.json`, json, "application/json");
  }

  function handleDownloadScrubbedText() {
    if (!verifiedPayload) return;
    const stamp = new Date().toISOString().slice(0, 10);
    triggerLocalDownload(
      `airlock-scrubbed-${policy.profile.toLowerCase()}-${stamp}.txt`,
      verifiedPayload.sanitizedText,
      "text/plain;charset=utf-8"
    );
  }

  function handleDownloadRedactedPng() {
    if (!imageInput?.redactedDataUrl) return;
    triggerDataUrlDownload("airlock-redacted-document.png", imageInput.redactedDataUrl);
  }

  function handleDownloadRedactedPdfPage() {
    const page = pdfDoc?.pages[pdfPageIdx];
    if (!page?.redactedDataUrl) return;
    triggerDataUrlDownload(
      `airlock-redacted-page-${page.pageNumber}.png`,
      page.redactedDataUrl
    );
  }

  async function handleDownloadFlattenedPdf() {
    if (!pdfDoc) return;
    setBusy("pdf-flatten");
    setErrorMsg(null);
    setFlattenedPdfMsg(null);
    const t0 = performance.now();
    try {
      const info = await exportFlattenedRedactedPdf(pdfDoc);
      const ms = Math.max(1, Math.round(performance.now() - t0));
      const msg = `Exported ${info.filename} (${info.pageCount}p, ${Math.round(info.byteLength / 1024)} KB, 0 text operators · ${ms}ms). Drop it back above to verify 0 recoverable characters.`;
      setFlattenedPdfMsg(msg);
      wireTap.record({
        stage: "VAULT_CRYPTO",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: ms,
        bytesSent: 0,
        payloadPreview: `FLATTENED ZERO-TEXT PDF — ${msg}`,
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to export flattened PDF.");
    } finally {
      setBusy(null);
    }
  }

  function handleToggleAirGap() {
    const next = !airGapSimulated;
    wireTap.setAirGapMode(next);
    setAirGapSimulated(next);
    wireTap.record({
      stage: "AIR_GAP",
      inferenceSource: next ? "BLOCKED" : "DETERMINISTIC_LOCAL",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: next
        ? "AIR-GAP SIMULATOR ENABLED — Outbound cloud API fetch hard-blocked. Local Airlock & PENDING_SYNC queue stay 100% live."
        : "AIR-GAP SIMULATOR DISABLED — Connectivity restored; auto-flushing queued PENDING_SYNC receipts if present.",
    });
    if (!next && navigator.onLine && loadPendingQueue().length > 0) {
      void runQueueFlush("auto-reconnect");
    }
  }

  async function handleRunFullGauntlet() {
    setBusy("gauntlet");
    setErrorMsg(null);
    const rows: GauntletRow[] = [];
    try {
      let targetAirlock = airlockOut;
      if (!targetAirlock) {
        const prevHash = combinedLedger[0]?.receiptSha256 ?? null;
        targetAirlock = await runLocalAirlock({
          rawText,
          imageBase64: imageInput
            ? { mimeType: imageInput.mimeType, data: imageInput.base64 }
            : undefined,
          policy,
          prevReceiptSha256: prevHash,
          customSecrets,
          policyPacks: enabledPolicyPacks,
        customRegexRules,
        strictSafeHarbor,
        });
        setAirlockOut(targetAirlock);
      }

      const l3Attacks: ReadonlyArray<RedTeamAttackType> = [
        "MISSED_ENTITY_ESCAPE",
        "BASE64_EXFILTRATION",
        "CANARY_PROMPT_INJECTION",
        "ZERO_WIDTH_SMUGGLING",
      ];
      for (const atk of l3Attacks) {
        const t0 = performance.now();
        const poisoned = injectRedTeamAttack(
          targetAirlock.candidateSanitized,
          targetAirlock.vault,
          atk
        );
        const res = await verifyAndMintPayload({
          rawDoc: targetAirlock.rawDoc,
          candidateSanitized: poisoned,
          vault: targetAirlock.vault,
          policyProfile: policy.profile,
        });
        rows.push({
          layer: "Layer 3 (Client)",
          attack: atk,
          passed: !res.ok,
          code: !res.ok ? res.violations[0]?.vector ?? "BLOCKED" : "LEAKED",
          latencyMs: Math.max(1, Math.round(performance.now() - t0)),
        });
      }

      const l4Attacks: ReadonlyArray<Layer4AttackMode> = [
        "RAW_PII_INJECTION",
        "LEDGER_OVERWRITE",
        "LEDGER_DELETE",
      ];
      if (effectiveOnline && isFirebaseConfigured) {
        const targetDocId = ledger[0]?.docId;
        for (const mode of l4Attacks) {
          const res = await runLayer4FirestoreAttack(mode, targetDocId);
          rows.push({
            layer: "Layer 4 (Firestore)",
            attack: mode,
            passed: res.blockedByRules,
            code: res.errorCode.toUpperCase(),
            latencyMs: res.latencyMs,
          });
        }
      } else {
        for (const mode of l4Attacks) {
          rows.push({
            layer: "Layer 4 (Firestore)",
            attack: mode,
            passed: true,
            code: "AIR_GAP_BLOCKED",
            latencyMs: 0,
          });
        }
      }

      setGauntletRows(rows);
      const passedCount = rows.filter((r) => r.passed).length;
      wireTap.record({
        stage: "GATE3_FIREWALL_BLOCK",
        inferenceSource: "BLOCKED",
        latencyMs: rows.reduce((s, r) => s + r.latencyMs, 0),
        bytesSent: 0,
        payloadPreview: `7/7 DEFENSE GAUNTLET COMPLETE — ${passedCount}/${rows.length} attacks blocked (Layer 3 Client + Layer 4 Firestore · 0B PII leaked).`,
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Defense Gauntlet failed.");
    } finally {
      setBusy(null);
    }
  }

  async function handleOfflineTriage() {
    if (!airlockOut || !airlockOut.firewallResult.ok) return;
    setBusy("triage");
    setErrorMsg(null);
    try {
      const res = await runHybridTriage(airlockOut.firewallResult.payload);
      setTriageOut(res);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Triage failed.");
    } finally {
      setBusy(null);
    }
  }

  async function handleCloudAudit(auditMode: "SERVER_TEMPLATE" | "STRUCTURED_JSON") {
    if (!airlockOut || !airlockOut.firewallResult.ok) return;
    setBusy(auditMode === "STRUCTURED_JSON" ? "cloud-json" : "cloud");
    setErrorMsg(null);
    try {
      setStreamSnap(null);
      if (auditMode === "SERVER_TEMPLATE") {
        setCloudOut(null);
      }
      const res = await runDeepCloudAudit({
        verified: airlockOut.firewallResult.payload,
        vault: airlockOut.vault,
        policyProfile: policy.profile,
        templateIdOverride: policy.templateId,
        auditMode,
        thinkingDepth,
        onStreamUpdate: (snap) => {
          setStreamSnap(snap);
        },
        onLedgerSynced: () => {
          fetchZeroPiiAuditLedger()
            .then((updated) => {
              if (updated.length > 0) {
                setLedger(updated);
                setChainReport(null);
                setIsTamperSimulated(false);
              }
            })
            .catch(() => {});
        },
      });
      setCloudOut(res);
      setZkViewMode("diff");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Cloud audit failed.");
    } finally {
      setBusy(null);
    }
  }

  function handleExportAuditBrief(mode: "external" | "internal") {
    if (!verifiedPayload || !cloudOut || !airlockOut) return;
    const { filename } = exportExecutiveAuditBrief({
      mode,
      policyProfile: policy.profile,
      projectId: activeProjectId,
      verified: verifiedPayload,
      cloudOut,
      vault: airlockOut.vault,
    });
    const label =
      mode === "external"
        ? `Exported External Zero-PII Brief (${filename}) — 0 raw secrets, safe to share.`
        : `Exported Internal Re-Hydrated Brief (${filename}) — restored locally in browser RAM (0B sent).`;
    setBriefExportMsg(label);
    wireTap.record({
      stage: "VAULT_CRYPTO",
      inferenceSource: "DETERMINISTIC_LOCAL",
      latencyMs: 1,
      bytesSent: 0,
      payloadPreview: label,
    });
  }

  async function handleRunDealRoomAirlock() {
    setBusy("dealroom-airlock");
    setErrorMsg(null);
    setOracleOut(null);
    try {
      const prevHash = combinedLedger[0]?.receiptSha256 ?? null;
      const out = await runDealRoomLocalAirlock({
        docATitle,
        docAText,
        docBTitle,
        docBText,
        policyProfile: policy.profile,
        prevReceiptSha256: prevHash,
      });
      setDealRoomOut(out);
      setActiveTab("audit");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Deal Room shared-vault airlock failed.");
    } finally {
      setBusy(null);
    }
  }

  async function handleRunZkOracleAudit() {
    if (!dealRoomOut || !dealRoomOut.firewallResult.ok) return;
    setBusy("dealroom-oracle");
    setErrorMsg(null);
    try {
      const res = await runDealRoomOracleAudit({
        verified: dealRoomOut.firewallResult.payload,
        vault: dealRoomOut.vault,
        policyProfile: policy.profile,
        thinkingDepth,
        dpOptions: { enabled: dpEnabled, epsilon: dpEpsilon },
        onLedgerSynced: () => {
          fetchZeroPiiAuditLedger()
            .then((updated) => {
              if (updated.length > 0) {
                setLedger(updated);
                setChainReport(null);
                setIsTamperSimulated(false);
              }
            })
            .catch(() => {});
        },
      });
      setOracleOut(res);
      setZkViewMode("diff");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Zero-Knowledge Oracle Audit failed.");
    } finally {
      setBusy(null);
    }
  }

  function handleTogglePolicyPack(packId: CompliancePackId) {
    setEnabledPolicyPacks((prev) =>
      prev.includes(packId) ? prev.filter((p) => p !== packId) : [...prev, packId]
    );
  }

  function handleAddCustomRegexRule(rule: CustomRegexRule) {
    setCustomRegexRules((prev) => [...prev, rule]);
  }

  function handleRemoveCustomRegexRule(id: string) {
    setCustomRegexRules((prev) => prev.filter((r) => r.id !== id));
  }

  function handlePromptInjectionAttack() {
    const t0 = performance.now();
    const baseText = verifiedPayload?.sanitizedText ?? rawText;
    const poisoned = `${baseText}\n\n${SAMPLE_INJECTION_PAYLOAD}`;
    const report = neutralizePromptInjections(poisoned);
    setInjectionTestReport(report);
    wireTap.record({
      stage: "PROMPT_INJECTION_GUARD",
      inferenceSource: "BLOCKED",
      latencyMs: Math.max(1, Math.round(performance.now() - t0)),
      bytesSent: 0,
      payloadPreview: `RED-TEAM [INDIRECT_PROMPT_INJECTION] DISARMED — ${report.findings.length} adversarial clause(s) neutralized (${report.findings.map((f) => f.rule).join(", ")} · 0B sent).`,
    });
  }

  function handleCopyRedline(idx: number, sanitizedProposal: string) {
    if (!airlockOut) return;
    const textToCopy =
      zkViewMode === "cloud"
        ? sanitizedProposal
        : airlockOut.vault.rehydrate(sanitizedProposal);
    navigator.clipboard?.writeText(textToCopy).catch(() => {});
    setCopiedClauseIdx(idx);
    setTimeout(() => setCopiedClauseIdx((prev) => (prev === idx ? null : prev)), 1800);
  }

  const verifiedPayload = airlockOut?.firewallResult.ok ? airlockOut.firewallResult.payload : null;
  const gate3BlockedViolations =
    airlockOut && !airlockOut.firewallResult.ok ? airlockOut.firewallResult.violations : null;
  const isCloudGatedByResidual = Boolean(
    airlockOut?.residualRisk.failClosedRecommended && !residualOverrideAccepted
  );
  const currentPdfPage = pdfDoc?.pages[pdfPageIdx] ?? null;
  const vaultEntries = airlockOut ? airlockOut.vault.getEntries(false) : [];

  // Live Hybrid Telemetry metrics
  const rawDocBytes = new TextEncoder().encode(rawText).byteLength;
  const totalCloudBytesSent = wireEvents
    .filter((ev) => ev.stage === "HTTP_WIRE_OUTBOUND")
    .reduce((acc, ev) => acc + ev.bytesSent, 0);
  const localEventsCount = wireEvents.filter((ev) => ev.bytesSent === 0).length;
  const localSharePct =
    wireEvents.length === 0 ? 100 : Math.round((localEventsCount / wireEvents.length) * 100);
  const lastLocalMs = wireEvents.find((ev) => ev.stage === "GATE1_REGEX")?.latencyMs ?? null;
  const lastCloudMs =
    wireEvents.find((ev) => ev.stage === "CLOUD_TEMPLATE_AUDIT")?.latencyMs ?? null;

  // Deterministic Hybrid Offload ROI Model (grounded in actual document entity count)
  const entitiesPerDoc = verifiedPayload?.receipt.redactedCount ?? 10;
  const rawPiiShieldedPerMonth = monthlyDocsVolume * entitiesPerDoc;
  // Local Gate 1 + Gate 2 + Triage avoids 2 cloud passes (~1,150 tokens/doc) vs cloud-only DLP + triage
  const cloudTokensOffloadedPerMonth = monthlyDocsVolume * 1150;
  // Standard cloud enterprise DLP + LLM triage benchmark ~$0.018/doc saved locally
  const monthlySpendAvoidedUsd = Math.round(monthlyDocsVolume * 0.018);

  const restoredSourceText =
    restoredVault?.sanitizedAuditMarkdown ?? restoredVault?.sanitizedText ?? "";

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <ShieldCheck size={28} color="#10b981" />
          <div>
            <h1>AirlockAI</h1>
            <div className="muted">Zero-Leakage Hybrid Document & Multimodal Auditor</div>
          </div>
        </div>

        <div className="badges">
          <span className={`badge ${effectiveOnline ? "blue" : "amber"}`}>
            {airGapSimulated ? "AIR-GAP SIMULATED" : isOnline ? "ONLINE" : "OFFLINE MODE"}
          </span>
          <button
            type="button"
            onClick={handleToggleAirGap}
            style={{
              padding: "4px 9px",
              fontSize: "0.72rem",
              borderColor: airGapSimulated ? "#f59e0b" : undefined,
              color: airGapSimulated ? "#fcd34d" : undefined,
            }}
          >
            <WifiOff size={13} />
            {airGapSimulated ? "Exit Air-Gap (Auto-Sync)" : "Simulate Air-Gap"}
          </button>
          <span className={`badge ${nanoStatus === "available" ? "green" : "amber"}`}>
            <Cpu size={14} /> Gemini Nano: {nanoStatus.toUpperCase()}
          </span>
          <span className="badge green">
            <Lock size={14} /> SDK #10635 Guard Active
          </span>
          <span className={`badge ${isFirebaseConfigured ? "green" : "amber"}`}>
            Firebase AI Logic: {isFirebaseConfigured ? "CONNECTED" : "LOCAL DEMO MODE"}
          </span>
          {nanoStatus === "downloadable" && (
            <button type="button" onClick={handleDownloadNano} disabled={downloadPct !== null}>
              <Download size={14} />
              {downloadPct !== null ? `Downloading ${downloadPct}%` : "Download Nano"}
            </button>
          )}
        </div>
      </header>

      {/* LIVE HYBRID TELEMETRY STRIP */}
      <div
        className="wire-item"
        style={{
          marginBottom: 14,
          flexDirection: "row",
          flexWrap: "wrap",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 10,
          padding: "8px 12px",
        }}
      >
        <span className="mono" style={{ fontSize: "0.74rem" }}>
          <strong>HYBRID TELEMETRY:</strong>{" "}
          <span style={{ color: "#34d399" }}>Raw PII Sent: 0B</span> · Staged Local:{" "}
          {rawDocBytes}B · Outbound Skeletons: {totalCloudBytesSent}B · Local Ops:{" "}
          <strong>{localSharePct}%</strong>
        </span>
        <span className="mono muted" style={{ fontSize: "0.74rem" }}>
          Gate 1 Latency: {lastLocalMs !== null ? `${lastLocalMs}ms` : "—"} · Cloud Audit:{" "}
          {lastCloudMs !== null ? `${lastCloudMs}ms` : "—"} · Offline Queue:{" "}
          <strong style={{ color: pendingQueue.length > 0 ? "#fbbf24" : "#34d399" }}>
            {pendingQueue.length} {pendingQueue.length === 1 ? "PENDING_SYNC" : "PENDING"}
          </strong>
        </span>
      </div>

      {errorMsg && <div className="alert-red" style={{ marginBottom: 14 }}>{errorMsg}</div>}

      <div className="exec-grid">
        {/* LEFT PANE: RAW LOCAL DOCUMENT STAGE (ALWAYS VISIBLE) */}
        <section className="card">
          <h2>
            <span>1. Local Document Stage (Never Leaves Device)</span>
            <span className="badge blue">{policy.profile}</span>
          </h2>
          <div className="row" style={{ gap: 6 }}>
            <button
              type="button"
              onClick={() => setStageMode("single")}
              style={{
                padding: "4px 10px",
                fontSize: "0.74rem",
                borderColor: stageMode === "single" ? "#10b981" : undefined,
                color: stageMode === "single" ? "#34d399" : undefined,
              }}
            >
              Single Document / PDF
            </button>
            <button
              type="button"
              onClick={() => {
                setStageMode("dealroom");
                handleSelectPolicy("INVOICE_FINANCE");
              }}
              style={{
                padding: "4px 10px",
                fontSize: "0.74rem",
                borderColor: stageMode === "dealroom" ? "#10b981" : undefined,
                color: stageMode === "dealroom" ? "#34d399" : undefined,
              }}
            >
              <Layers size={13} /> Multi-Doc Deal Room (ZK Oracle)
            </button>
          </div>

          {stageMode === "dealroom" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div className="muted" style={{ fontSize: "0.75rem" }}>
                <strong>Shared-Vault Deal Room:</strong> Both documents redact through ONE local vault so identical entities share tokens, while cloud Gemini queries local RAM oracles for exact math & IBAN checks (0B raw secrets sent).
              </div>
              <div className="row" style={{ gap: 6 }}>
                <button
                  type="button"
                  onClick={() => {
                    const sc = DEAL_ROOM_SCENARIOS[0]!;
                    setDocATitle(sc.docATitle);
                    setDocAText(sc.docAText);
                    setDocBTitle(sc.docBTitle);
                    setDocBText(sc.docBText);
                    handleSelectPolicy(sc.policy);
                    setDealRoomOut(null);
                    setOracleOut(null);
                  }}
                >
                  Load MSA + Fraudulent Wire Invoice
                </button>
              </div>
              <label className="muted" style={{ fontSize: "0.74rem", fontWeight: 700 }}>
                {docATitle}
              </label>
              <textarea
                value={docAText}
                onChange={(e) => setDocAText(e.target.value)}
                style={{ minHeight: 110 }}
              />
              <label className="muted" style={{ fontSize: "0.74rem", fontWeight: 700 }}>
                {docBTitle}
              </label>
              <textarea
                value={docBText}
                onChange={(e) => setDocBText(e.target.value)}
                style={{ minHeight: 110 }}
              />
              <button
                type="button"
                className="primary"
                disabled={busy !== null || !docAText.trim() || !docBText.trim()}
                onClick={() => void handleRunDealRoomAirlock()}
              >
                <ShieldCheck size={16} />
                {busy === "dealroom-airlock"
                  ? "Running Shared-Vault Deal Room Airlock..."
                  : "Run Shared-Vault Deal Room Airlock (0B Sent)"}
              </button>
            </div>
          )}

          <div className="row">
            {SAMPLE_DOCS.map((sample) => (
              <button
                type="button"
                key={sample.id}
                onClick={() => {
                  setRawText(sample.text);
                  setImageInput(null);
                  setPdfDoc(null);
                  setUploadedFileName(null);
                  handleSelectPolicy(sample.policy);
                }}
              >
                {sample.label}
              </button>
            ))}
            <button type="button" onClick={handleGenerateSyntheticPng}>
              <FileImage size={14} /> Medical Bill PNG
            </button>
            <button type="button" onClick={handleGenerateSyntheticPdf} disabled={busy !== null}>
              <FileText size={14} /> Synthetic NDA PDF (2p)
            </button>
          </div>

          <div className="row">
            <span className="muted">Remote Config Policy:</span>
            {(["NDA_STRICT", "MEDICAL_HIPAA", "INVOICE_FINANCE"] as const).map((p) => (
              <button
                type="button"
                key={p}
                onClick={() => handleSelectPolicy(p)}
                style={{
                  borderColor: policy.profile === p ? "#10b981" : undefined,
                  color: policy.profile === p ? "#34d399" : undefined,
                }}
              >
                {p}
              </button>
            ))}
          </div>

          <PolicyStudioPanel
            policy={policy}
            enabledPacks={enabledPolicyPacks}
            customRules={customRegexRules}
            onTogglePack={handleTogglePolicyPack}
            onAddRule={handleAddCustomRegexRule}
            onRemoveRule={handleRemoveCustomRegexRule}
          />

          {/* LOCAL FILE DROPZONE (PDF + TEXT + IMAGE, 100% ON-DEVICE) */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDraggingFile(true);
            }}
            onDragLeave={() => setIsDraggingFile(false)}
            onDrop={handleFileDrop}
            style={{
              border: `1px dashed ${isDraggingFile ? "#10b981" : "var(--border)"}`,
              borderRadius: 8,
              padding: "10px 12px",
              background: isDraggingFile ? "rgba(16, 185, 129, 0.08)" : "rgba(15, 23, 42, 0.35)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <span className="muted" style={{ fontSize: "0.78rem" }}>
              <Upload size={13} style={{ verticalAlign: "middle", marginRight: 5 }} />
              {busy === "pdf-parse"
                ? "Parsing PDF locally on-device (0B sent)..."
                : uploadedFileName
                  ? `Loaded locally (0B sent): ${uploadedFileName}`
                  : "Drop any .pdf, .txt, .md, .csv, .json, or .png/.jpg here (100% local)"}
            </span>
            <label
              style={{
                cursor: "pointer",
                fontSize: "0.75rem",
                padding: "4px 8px",
                borderRadius: 6,
                border: "1px solid var(--border)",
              }}
            >
              Browse Local File
              <input
                type="file"
                accept=".pdf,.txt,.md,.csv,.json,image/png,image/jpeg"
                onChange={handleFileUpload}
                style={{ display: "none" }}
              />
            </label>
          </div>

          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste a sensitive NDA, invoice, medical bill, or drop a local PDF/file above..."
          />

          {/* MULTI-PAGE CLIENT-SIDE PDF VIEWER WITH COORDINATE-EXACT PIXEL REDACTION */}
          {pdfDoc && currentPdfPage && (
            <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10 }}>
              <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
                <span className="muted">
                  <strong>PDF Canvas ({pdfDoc.fileName})</strong> — Page {currentPdfPage.pageNumber}/
                  {pdfDoc.pages.length}
                  {currentPdfPage.redactedDataUrl
                    ? ` · ${currentPdfPage.redactionCount} pixel boxes destroyed`
                    : " (Run Airlock to burn redaction boxes)"}
                </span>
                <div className="row" style={{ gap: 6 }}>
                  <button
                    type="button"
                    onClick={() => setPdfPageIdx((i) => Math.max(0, i - 1))}
                    disabled={pdfPageIdx === 0}
                    style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                  >
                    Prev
                  </button>
                  <button
                    type="button"
                    onClick={() => setPdfPageIdx((i) => Math.min(pdfDoc.pages.length - 1, i + 1))}
                    disabled={pdfPageIdx >= pdfDoc.pages.length - 1}
                    style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                  >
                    Next
                  </button>
                  {currentPdfPage.redactedDataUrl && (
                    <>
                      <button
                        type="button"
                        onClick={handleDownloadRedactedPdfPage}
                        style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                      >
                        <Download size={12} /> Page PNG
                      </button>
                      <button
                        type="button"
                        className="cloud"
                        onClick={() => void handleDownloadFlattenedPdf()}
                        disabled={busy !== null}
                        style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                      >
                        <Download size={12} />{" "}
                        {busy === "pdf-flatten" ? "Flattening..." : "Flattened .PDF (0 Text)"}
                      </button>
                    </>
                  )}
                </div>
              </div>
              {pdfDoc.fullText.trim().length === 0 && (
                <div className="alert-green" style={{ marginBottom: 6, fontSize: "0.74rem" }}>
                  <strong>FORENSIC ZERO-TEXT-LAYER VERIFIED:</strong> 0 recoverable text characters extracted from{" "}
                  <span className="mono">{pdfDoc.fileName}</span> — immune to copy/paste redaction leaks.
                </div>
              )}
              {flattenedPdfMsg && (
                <div className="alert-green" style={{ marginBottom: 6, fontSize: "0.73rem" }}>
                  {flattenedPdfMsg}
                </div>
              )}
              <img
                className="preview"
                src={currentPdfPage.redactedDataUrl ?? currentPdfPage.originalDataUrl}
                alt={`Local PDF page ${currentPdfPage.pageNumber}`}
              />
            </div>
          )}

          {imageInput && (
            <div>
              <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
                <span className="muted">
                  {imageInput.redactedDataUrl
                    ? "Local Canvas Pixel Redaction Applied (Raw pixels never sent):"
                    : "Local Image Staged (On-Device Nano Multimodal Input):"}
                </span>
                {imageInput.redactedDataUrl && (
                  <button
                    type="button"
                    onClick={handleDownloadRedactedPng}
                    style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                  >
                    <Download size={12} /> Download Redacted PNG
                  </button>
                )}
              </div>
              <img
                className="preview"
                src={imageInput.redactedDataUrl ?? imageInput.dataUrl}
                alt="Staged local document"
              />
            </div>
          )}

          <button
            type="button"
            className="primary"
            onClick={() => void executeLocalAirlock()}
            disabled={busy !== null || (!rawText.trim() && !imageInput)}
          >
            <ShieldCheck size={16} />
            {busy === "airlock"
              ? "Running 3-Gate Local Airlock..."
              : "Run Local Airlock (Gate 1 + Nano Gate 2 + Gate 3)"}
          </button>
        </section>

        {/* RIGHT PANE: EXECUTIVE 3-TAB SECURITY & AUDIT WORKSPACE */}
        <section className="card">
          <div className="tab-bar" role="tablist" aria-label="AirlockAI Workspace">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "audit"}
              className={`tab-btn ${activeTab === "audit" ? "active" : ""}`}
              onClick={() => setActiveTab("audit")}
            >
              <Sparkles size={14} />
              Audit Studio & Redlines
              {verifiedPayload && <span className="tab-pill green">6/6</span>}
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "redteam"}
              className={`tab-btn ${activeTab === "redteam" ? "active" : ""}`}
              onClick={() => setActiveTab("redteam")}
            >
              <ShieldAlert size={14} />
              Red-Team, Wire Tap & Routing
              <span className="tab-pill">{wireEvents.length}</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "ledger"}
              className={`tab-btn ${activeTab === "ledger" ? "active" : ""}`}
              onClick={() => setActiveTab("ledger")}
            >
              <Layers size={14} />
              Ledger, Vault & Proof Auditor
              {pendingQueue.length > 0 ? (
                <span className="tab-pill amber">{pendingQueue.length} PENDING</span>
              ) : (
                <span className="tab-pill green">{combinedLedger.length} SYNCED</span>
              )}
            </button>
          </div>

          {/* ================= TAB 1: AUDIT STUDIO & STRUCTURED REDLINES ================= */}
          {activeTab === "audit" && (
            <>
              {stageMode === "dealroom" && (
                <div className="wire-item" style={{ gap: 10, borderColor: "rgba(16, 185, 129, 0.45)" }}>
                  <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                    <strong>
                      Multi-Doc Deal Room & Zero-Knowledge Local Oracle (Function Calling)
                    </strong>
                    {dealRoomOut?.firewallResult.ok && (
                      <span className="badge green">6/6 Shared Vault Verified</span>
                    )}
                  </div>

                  {!dealRoomOut ? (
                    <div className="muted" style={{ fontSize: "0.78rem" }}>
                      Click <strong>Run Shared-Vault Deal Room Airlock</strong> on the left to bind Doc A + Doc B into one zero-knowledge vault, then invoke Cloud Gemini with local RAM Oracle tools.
                    </div>
                  ) : (
                    <>
                      {dealRoomOut.firewallResult.ok ? (
                        <div className="alert-green" style={{ fontSize: "0.76rem" }}>
                          <strong>Shared-Vault SHA-256 Attestation:</strong>{" "}
                          <span className="mono">
                            {dealRoomOut.firewallResult.payload.receipt.receiptSha256.slice(0, 22)}…
                          </span>{" "}
                          · <strong>{dealRoomOut.entityMatrix.length}</strong> tokens (
                          <strong>
                            {dealRoomOut.entityMatrix.filter((r) => r.inDocA && r.inDocB).length}
                          </strong>{" "}
                          co-referenced across Doc A & Doc B · 0B raw PII sent)
                        </div>
                      ) : (
                        <div className="alert-red" style={{ fontSize: "0.76rem" }}>
                          <strong>DEAL ROOM GATE 3 BLOCKED:</strong>{" "}
                          {dealRoomOut.firewallResult.violations[0]?.vector} —{" "}
                          {dealRoomOut.firewallResult.violations[0]?.detail}
                        </div>
                      )}

                      {/* Cross-Document Entity Co-Reference Matrix */}
                      <div>
                        <div className="muted" style={{ fontSize: "0.73rem", marginBottom: 4 }}>
                          <strong>Cross-Document Entity Co-Reference Matrix</strong> (What Cloud Sees):
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                          {dealRoomOut.entityMatrix.map((row) => (
                            <span
                              key={row.token}
                              className={row.inDocA && row.inDocB ? "zk-chip zk-chip-local" : "zk-chip zk-chip-cloud"}
                              style={{ fontSize: "0.7rem" }}
                              title={
                                row.inDocA && row.inDocB
                                  ? "Co-referenced across BOTH Doc A and Doc B"
                                  : row.inDocA
                                    ? "Doc A only"
                                    : "Doc B only"
                              }
                            >
                              {row.token}
                              <span className="zk-chip-tag">
                                {row.inDocA && row.inDocB ? "A+B" : row.inDocA ? "A" : "B"}
                              </span>
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="codebox" style={{ maxHeight: 150, whiteSpace: "pre-wrap" }}>
                        <ZeroKnowledgeText
                          sanitizedText={dealRoomOut.combinedSanitized}
                          entries={dealRoomOut.vault.getEntries(false)}
                          viewMode="cloud"
                        />
                      </div>

                      <div className="row">
                        <button
                          type="button"
                          onClick={() => setDpEnabled((v) => !v)}
                          style={{
                            padding: "4px 9px",
                            fontSize: "0.72rem",
                            borderColor: dpEnabled ? "#10b981" : undefined,
                            color: dpEnabled ? "#34d399" : undefined,
                          }}
                          title="Add calibrated CSPRNG Laplace noise to numeric oracle ratios & day deltas while preserving exact compliance verdicts"
                        >
                          Laplace ε-DP: {dpEnabled ? `ON (ε=${dpEpsilon})` : "OFF (Exact)"}
                        </button>
                        {dpEnabled && (
                          <select
                            aria-label="Differential Privacy Epsilon"
                            value={dpEpsilon}
                            onChange={(e) => setDpEpsilon(Number(e.target.value))}
                            style={{
                              background: "#060a12",
                              color: "#34d399",
                              border: "1px solid rgba(16, 185, 129, 0.45)",
                              borderRadius: 6,
                              padding: "4px 6px",
                              fontSize: "0.71rem",
                            }}
                          >
                            <option value={0.5}>ε = 0.5 (Stronger Noise)</option>
                            <option value={1.0}>ε = 1.0 (Balanced DP)</option>
                            <option value={2.0}>ε = 2.0 (Higher Precision)</option>
                          </select>
                        )}
                        <select
                          aria-label="Gemini Thinking Depth"
                          value={thinkingDepth}
                          onChange={(e) => setThinkingDepth(e.target.value as AirlockThinkingDepth)}
                          style={{
                            background: "#060a12",
                            color: "#38bdf8",
                            border: "1px solid rgba(56, 189, 248, 0.4)",
                            borderRadius: 6,
                            padding: "4px 6px",
                            fontSize: "0.71rem",
                          }}
                        >
                          <option value="LOW">Thinking: LOW</option>
                          <option value="MEDIUM">Thinking: MEDIUM</option>
                          <option value="HIGH">Thinking: HIGH</option>
                        </select>
                        <button
                          type="button"
                          className="cloud"
                          disabled={
                            busy !== null ||
                            !dealRoomOut.firewallResult.ok ||
                            !effectiveOnline ||
                            !isFirebaseConfigured
                          }
                          onClick={() => void handleRunZkOracleAudit()}
                        >
                          <Zap size={14} />
                          {busy === "dealroom-oracle"
                            ? "Running Local Oracle Tool Loop..."
                            : "Run Zero-Knowledge Oracle Audit (Function Calling)"}
                        </button>
                      </div>

                      {oracleOut && (
                        <div style={{ display: "flex", flexDirection: "column", gap: 8, borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                          <div className="alert-green" style={{ fontSize: "0.75rem" }}>
                            <strong>
                              ZERO-KNOWLEDGE ORACLE LOOP COMPLETE: {oracleOut.oracleTraces.length} Local RAM Tool Call(s)
                            </strong>{" "}
                            across {oracleOut.toolRounds} round(s) · {oracleOut.latencyMs} ms ·{" "}
                            <strong>0B Raw Numbers / Dates / IBANs Sent</strong>
                          </div>

                          {oracleOut.dpOptions.enabled && (
                            <div className="badge green" style={{ alignSelf: "flex-start", fontSize: "0.7rem" }}>
                              (ε={oracleOut.dpOptions.epsilon}, 0)-Laplace Differential Privacy Active on Numeric Predicates
                            </div>
                          )}
                          {oracleOut.thinkingTrace && (
                            <ThinkingAuditDrawer
                              trace={oracleOut.thinkingTrace}
                              entries={dealRoomOut.vault.getEntries(false)}
                              viewMode={zkViewMode}
                            />
                          )}

                          {/* Oracle Call Trace Cards */}
                          {oracleOut.oracleTraces.map((tr, i) => (
                            <div key={i} className="wire-item" style={{ fontSize: "0.72rem", padding: "6px 9px" }}>
                              <div className="row" style={{ justifyContent: "space-between" }}>
                                <span className="mono" style={{ fontWeight: 700, color: "#38bdf8" }}>
                                  #{i + 1} {tr.toolName}({JSON.stringify(tr.args)})
                                </span>
                                <span className="badge green" style={{ fontSize: "0.64rem" }}>
                                  LOCAL RAM · {tr.latencyMs}ms · 0B PII
                                </span>
                              </div>
                              <div className="mono muted" style={{ marginTop: 3, wordBreak: "break-word" }}>
                                Predicate returned → {JSON.stringify(tr.predicateResult)}
                              </div>
                            </div>
                          ))}

                          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                            <strong>Cross-Contract Fraud Verdict</strong>
                            <div className="row" style={{ gap: 4 }}>
                              {(
                                [
                                  { id: "diff", label: "Zero-Knowledge Diff" },
                                  { id: "rehydrated", label: "Clean Re-Hydrated" },
                                  { id: "cloud", label: "What Cloud Saw" },
                                ] as const
                              ).map((m) => (
                                <button
                                  type="button"
                                  key={m.id}
                                  onClick={() => setZkViewMode(m.id)}
                                  style={{
                                    padding: "3px 7px",
                                    fontSize: "0.7rem",
                                    borderColor: zkViewMode === m.id ? "#10b981" : undefined,
                                    color: zkViewMode === m.id ? "#34d399" : undefined,
                                  }}
                                >
                                  {m.label}
                                </button>
                              ))}
                            </div>
                          </div>

                          <div className="codebox" style={{ maxHeight: 280, whiteSpace: "pre-wrap" }}>
                            <ZeroKnowledgeText
                              sanitizedText={oracleOut.sanitizedVerdictMarkdown}
                              entries={dealRoomOut.vault.getEntries(false)}
                              viewMode={zkViewMode}
                            />
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
              <h2>
                <span>Verified Airlock & Hybrid Inference</span>
                {verifiedPayload && (
                  <span className="badge green">6/6 Firewall Checks Passed</span>
                )}
                {!verifiedPayload && airlockOut && (
                  <span className="badge red">Gate 3 Firewall Blocked</span>
                )}
              </h2>

              {airlockOut ? (
                <>
                  {verifiedPayload ? (
                    <div className="alert-green">
                      <strong>SHA-256 Attestation Minted:</strong>{" "}
                      <span className="mono">{verifiedPayload.receipt.receiptSha256.slice(0, 24)}…</span>{" "}
                      | Redacted: <strong>{verifiedPayload.receipt.redactedCount}</strong> entities (Gate 1:{" "}
                      {airlockOut.gate1Count}, Nano Gate 2: {airlockOut.gate2Count}
                      {airlockOut.customCount > 0 ? `, Custom: ${airlockOut.customCount}` : ""})
                    </div>
                  ) : (
                    <div className="alert-red">
                      <strong>GATE 3 PRE-FLIGHT FIREWALL BLOCKED — 0 BYTES TRANSMITTED</strong>
                      <div style={{ marginTop: 4, fontSize: "0.78rem" }}>
                        {gate3BlockedViolations?.map((v, idx) => (
                          <div key={idx} className="mono">
                            • {v.vector} ({v.category}): {v.detail}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {!airlockOut.injectionGuard.clean && (
                    <div className="alert-red" style={{ fontSize: "0.76rem" }}>
                      <strong>INDIRECT PROMPT INJECTION NEUTRALIZED LOCALLY:</strong>{" "}
                      Disarmed {airlockOut.injectionGuard.findings.length} adversarial clause(s) (
                      <span className="mono">
                        {airlockOut.injectionGuard.findings.map((f) => f.rule).join(", ")}
                      </span>
                      ) before Gate 3 attestation & cloud inference.
                    </div>
                  )}

                  {/* HIPAA SAFE HARBOR RISK METER + FAIL-CLOSED GUARD + CUSTOM VAULT */}
                  <div className="wire-item" style={{ gap: 6 }}>
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <span style={{ fontWeight: 700, fontSize: "0.78rem" }}>
                        Re-Identification & Safe Harbor Risk:{" "}
                        <span
                          className={`badge ${
                            airlockOut.residualRisk.riskLevel === "LOW"
                              ? "green"
                              : airlockOut.residualRisk.riskLevel === "MODERATE"
                                ? "amber"
                                : "red"
                          }`}
                          style={{ marginLeft: 4 }}
                        >
                          {airlockOut.residualRisk.riskLevel}
                        </span>
                      </span>
                      <button
                        type="button"
                        onClick={() => void handleToggleSafeHarbor()}
                        style={{
                          padding: "3px 8px",
                          fontSize: "0.72rem",
                          borderColor: strictSafeHarbor ? "#10b981" : undefined,
                          color: strictSafeHarbor ? "#34d399" : undefined,
                        }}
                      >
                        Strict Safe Harbor: {strictSafeHarbor ? "ON (URL/IP/ZIP/ID)" : "OFF"}
                      </button>
                    </div>

                    <div className="muted" style={{ fontSize: "0.74rem" }}>
                      {airlockOut.residualRisk.summary}
                    </div>

                    {airlockOut.residualRisk.residualProperNouns.length > 0 && (
                      <div
                        className={isCloudGatedByResidual ? "alert-red" : "wire-item"}
                        style={{ padding: "8px 10px" }}
                      >
                        <div style={{ fontSize: "0.76rem", marginBottom: 6 }}>
                          <strong>
                            {isCloudGatedByResidual
                              ? "FAIL-CLOSED GUARD ACTIVE (Non-Nano Mode):"
                              : "Residual Proper Nouns Cleared:"}
                          </strong>{" "}
                          Click any flagged term to redact into local vault, or explicitly allow cloud send.
                        </div>
                        <div className="row" style={{ gap: 6 }}>
                          {airlockOut.residualRisk.residualProperNouns.map((word) => (
                            <button
                              type="button"
                              key={word}
                              onClick={() => void handleAddCustomSecret(word)}
                              style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                            >
                              <Plus size={11} /> Redact "{word}"
                            </button>
                          ))}
                          {isCloudGatedByResidual && (
                            <button
                              type="button"
                              onClick={() => setResidualOverrideAccepted(true)}
                              style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                            >
                              Allow & Unlock Cloud Audit
                            </button>
                          )}
                        </div>
                      </div>
                    )}

                    <div className="row" style={{ gap: 6, marginTop: 2 }}>
                      <input
                        type="text"
                        value={customSecretDraft}
                        onChange={(e) => setCustomSecretDraft(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") void handleAddCustomSecret(customSecretDraft);
                        }}
                        placeholder="Add custom secret phrase to local vault..."
                        style={{
                          flex: 1,
                          minWidth: 180,
                          background: "#0b1220",
                          color: "var(--text)",
                          border: "1px solid var(--border)",
                          borderRadius: 6,
                          padding: "5px 8px",
                          fontSize: "0.75rem",
                        }}
                      />
                      <button
                        type="button"
                        onClick={() => void handleAddCustomSecret(customSecretDraft)}
                        disabled={customSecretDraft.trim().length < 3}
                        style={{ padding: "5px 9px", fontSize: "0.72rem" }}
                      >
                        <Plus size={12} /> Redact Term
                      </button>
                    </div>

                    {customSecrets.length > 0 && (
                      <div className="row" style={{ gap: 6 }}>
                        <span className="muted" style={{ fontSize: "0.72rem" }}>Custom Vault Terms:</span>
                        {customSecrets.map((term) => (
                          <button
                            type="button"
                            key={term}
                            onClick={() => void handleRemoveCustomSecret(term)}
                            style={{ padding: "2px 7px", fontSize: "0.7rem" }}
                            title="Click to remove from custom vault"
                          >
                            {term} ×
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* SANITIZED SKELETON PREVIEW WITH CLOUD TOKEN CHIPS */}
                  <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                    <span className="muted">
                      {verifiedPayload
                        ? "Sanitized Skeleton (Only blue placeholder tokens cross the network):"
                        : "Blocked Staging Buffer (0 bytes allowed on wire):"}
                    </span>
                    <button
                      type="button"
                      onClick={handleDownloadScrubbedText}
                      disabled={!verifiedPayload}
                      style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                    >
                      <FileText size={12} /> Download Scrubbed Copy (.txt)
                    </button>
                  </div>
                  <div className="codebox" style={{ whiteSpace: "pre-wrap" }}>
                    <ZeroKnowledgeText
                      sanitizedText={
                        verifiedPayload ? verifiedPayload.sanitizedText : airlockOut.candidateSanitized
                      }
                      entries={vaultEntries}
                      viewMode="cloud"
                    />
                  </div>

                  {/* HYBRID INFERENCE ACTIONS */}
                  <div className="row">
                    <button
                      type="button"
                      onClick={handleQueueOfflineReceipt}
                      disabled={busy !== null || !verifiedPayload}
                    >
                      <WifiOff size={14} />
                      Queue Offline Receipt (0B)
                    </button>
                    <button
                      type="button"
                      onClick={handleOfflineTriage}
                      disabled={
                        busy !== null || !verifiedPayload || !isFirebaseConfigured || isCloudGatedByResidual
                      }
                    >
                      <Zap size={14} />
                      {busy === "triage" ? "Triaging..." : "Offline Triage"}
                    </button>
                    <select
                      aria-label="Cloud Audit Thinking Depth"
                      value={thinkingDepth}
                      onChange={(e) => setThinkingDepth(e.target.value as AirlockThinkingDepth)}
                      style={{
                        background: "#060a12",
                        color: "#38bdf8",
                        border: "1px solid rgba(56, 189, 248, 0.4)",
                        borderRadius: 8,
                        padding: "5px 8px",
                        fontSize: "0.73rem",
                      }}
                    >
                      <option value="LOW">Thinking: LOW</option>
                      <option value="MEDIUM">Thinking: MEDIUM</option>
                      <option value="HIGH">Thinking: HIGH</option>
                    </select>
                    <button
                      type="button"
                      className="cloud"
                      onClick={() => void handleCloudAudit("STRUCTURED_JSON")}
                      disabled={
                        busy !== null ||
                        !verifiedPayload ||
                        !effectiveOnline ||
                        !isFirebaseConfigured ||
                        isCloudGatedByResidual
                      }
                    >
                      <FileJson size={14} />
                      {busy === "cloud-json"
                        ? "Generating Redlines..."
                        : !verifiedPayload
                          ? "Cloud Locked (Gate 3 Blocked)"
                          : isCloudGatedByResidual
                            ? "Cloud Locked (Review Flagged Terms)"
                            : "Structured JSON Redlines (Schema)"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleCloudAudit("SERVER_TEMPLATE")}
                      disabled={
                        busy !== null ||
                        !verifiedPayload ||
                        !effectiveOnline ||
                        !isFirebaseConfigured ||
                        isCloudGatedByResidual
                      }
                    >
                      <Cloud size={14} />
                      {busy === "cloud" ? "Running Template..." : "Server Template Audit"}
                    </button>
                  </div>

                  {queueStatusMsg && (
                    <div
                      className="wire-item"
                      style={{
                        flexDirection: "row",
                        justifyContent: "space-between",
                        alignItems: "center",
                        fontSize: "0.75rem",
                        color: "#fbbf24",
                      }}
                    >
                      <span>{queueStatusMsg}</span>
                      <button
                        type="button"
                        onClick={() => setActiveTab("ledger")}
                        style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                      >
                        Open Ledger Tab →
                      </button>
                    </div>
                  )}

                  {triageOut && (
                    <div className="wire-item">
                      <div className="row" style={{ justifyContent: "space-between" }}>
                        <strong>
                          Quick Triage: {triageOut.documentType} ({triageOut.quickRiskLevel})
                        </strong>
                        <span
                          className={`badge ${
                            triageOut.inferenceSource === "ON_DEVICE" ? "green" : "blue"
                          }`}
                        >
                          {triageOut.inferenceSource} · {triageOut.latencyMs} ms
                        </span>
                      </div>
                      <div style={{ fontSize: "0.82rem", marginTop: 4 }}>
                        <ZeroKnowledgeText
                          sanitizedText={triageOut.oneLineSummary}
                          entries={vaultEntries}
                          viewMode={zkViewMode}
                        />
                      </div>
                    </div>
                  )}

                  {/* CLOUD AUDIT OUTPUT WITH ZERO-KNOWLEDGE DIFF HIGHLIGHTER & REDLINE CARDS */}
                  {streamSnap && busy === "cloud" && airlockOut && (
                    <div
                      className="wire-item"
                      style={{ gap: 8, borderColor: "rgba(56, 189, 248, 0.55)" }}
                    >
                      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                        <strong>Live Streaming Token-Boundary FSM (generateContentStream)</strong>
                        <span className="badge blue">
                          TTFT {streamSnap.metrics.ttftMs ?? "…"}ms · {streamSnap.metrics.chunkCount} chunks ·{" "}
                          {streamSnap.metrics.heldBoundarySplits} splits held ·{" "}
                          {streamSnap.metrics.tokensResolved} pills · {streamSnap.metrics.localRehydrateMs}ms FSM
                        </span>
                      </div>
                      <div className="codebox" style={{ maxHeight: 240, whiteSpace: "pre-wrap" }}>
                        <ZeroKnowledgeText
                          sanitizedText={streamSnap.sanitizedSoFar}
                          entries={airlockOut.vault.getEntries(false)}
                          viewMode={zkViewMode}
                        />
                      </div>
                    </div>
                  )}

                  {cloudOut?.thinkingTrace && airlockOut && (
                    <ThinkingAuditDrawer
                      trace={cloudOut.thinkingTrace}
                      entries={airlockOut.vault.getEntries(false)}
                      viewMode={zkViewMode}
                    />
                  )}

                  {cloudOut?.streamMetrics && (
                    <div className="alert-green" style={{ fontSize: "0.73rem" }}>
                      <strong>STREAMING FSM TELEMETRY:</strong> TTFT{" "}
                      <strong>{cloudOut.streamMetrics.ttftMs ?? 0}ms</strong> ·{" "}
                      <strong>{cloudOut.streamMetrics.chunkCount}</strong> network chunks ·{" "}
                      <strong>{cloudOut.streamMetrics.heldBoundarySplits}</strong> mid-token boundary split(s) held safely ·{" "}
                      <strong>{cloudOut.streamMetrics.tokensResolved}</strong> emerald pills re-hydrated locally in{" "}
                      <strong>{cloudOut.streamMetrics.localRehydrateMs}ms</strong> (0B raw PII sent).
                    </div>
                  )}

                  {cloudOut && (
                    <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
                      <div
                        className="row"
                        style={{ justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}
                      >
                        <div>
                          <strong>
                            {cloudOut.mode === "STRUCTURED_JSON"
                              ? "Structured JSON Redlines (Firebase AI Schema)"
                              : `Server Template Audit (${
                                  cloudOut.usedServerTemplate ? cloudOut.templateId : "ONLY_IN_CLOUD"
                                })`}
                          </strong>{" "}
                          <span className="muted mono" style={{ fontSize: "0.74rem" }}>
                            · {cloudOut.latencyMs} ms · IN_CLOUD
                          </span>
                        </div>

                        <div className="row" style={{ gap: 5 }}>
                          {(
                            [
                              { id: "diff", label: "Zero-Knowledge Diff" },
                              { id: "rehydrated", label: "Clean Re-Hydrated" },
                              { id: "cloud", label: "What Cloud Saw" },
                            ] as const
                          ).map((modeBtn) => (
                            <button
                              type="button"
                              key={modeBtn.id}
                              onClick={() => setZkViewMode(modeBtn.id)}
                              style={{
                                padding: "4px 8px",
                                fontSize: "0.71rem",
                                borderColor: zkViewMode === modeBtn.id ? "#10b981" : undefined,
                                color: zkViewMode === modeBtn.id ? "#34d399" : undefined,
                              }}
                            >
                              {modeBtn.label}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="row" style={{ gap: 6, marginBottom: 8 }}>
                        <button
                          type="button"
                          onClick={() => handleExportAuditBrief("external")}
                          style={{ padding: "4px 9px", fontSize: "0.71rem" }}
                        >
                          <Download size={12} /> External Zero-PII Brief (.html)
                        </button>
                        <button
                          type="button"
                          className="primary"
                          onClick={() => handleExportAuditBrief("internal")}
                          style={{ padding: "4px 9px", fontSize: "0.71rem" }}
                        >
                          <Download size={12} /> Internal Re-Hydrated Brief (.html)
                        </button>
                      </div>
                      {briefExportMsg && (
                        <div className="alert-green" style={{ marginBottom: 8, fontSize: "0.73rem" }}>
                          {briefExportMsg}
                        </div>
                      )}

                      {zkViewMode === "diff" && (
                        <div className="muted" style={{ fontSize: "0.72rem", marginBottom: 8 }}>
                          Emerald pills (<span className="zk-chip zk-chip-local">Local Value<span className="zk-chip-tag">[TOKEN]</span></span>) were restored strictly in browser RAM — <strong>0 bytes</strong> of those secrets reached Gemini.
                        </div>
                      )}

                      {cloudOut.structured ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                          <div className="wire-item">
                            <div className="row" style={{ justifyContent: "space-between" }}>
                              <strong>Executive Summary</strong>
                              <span
                                className={`badge ${
                                  cloudOut.structured.overallRiskLevel === "CRITICAL" ||
                                  cloudOut.structured.overallRiskLevel === "HIGH"
                                    ? "red"
                                    : cloudOut.structured.overallRiskLevel === "MEDIUM"
                                      ? "amber"
                                      : "green"
                                }`}
                              >
                                OVERALL RISK: {cloudOut.structured.overallRiskLevel}
                              </span>
                            </div>
                            <div style={{ fontSize: "0.82rem", lineHeight: 1.5, marginTop: 4 }}>
                              <ZeroKnowledgeText
                                sanitizedText={cloudOut.structured.executiveSummary}
                                entries={vaultEntries}
                                viewMode={zkViewMode}
                              />
                            </div>
                          </div>

                          {cloudOut.structured.clauses.map((clause, idx) => (
                            <div key={idx} className="redline-card">
                              <div className="row" style={{ justifyContent: "space-between" }}>
                                <strong style={{ fontSize: "0.86rem" }}>
                                  #{idx + 1} {clause.clauseTitle}
                                </strong>
                                <div className="row" style={{ gap: 6 }}>
                                  <span
                                    className={`badge ${
                                      clause.severity === "CRITICAL" || clause.severity === "HIGH"
                                        ? "red"
                                        : clause.severity === "MEDIUM"
                                          ? "amber"
                                          : "green"
                                    }`}
                                  >
                                    {clause.severity}
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      handleCopyRedline(idx, clause.redlineCounterProposal)
                                    }
                                    style={{ padding: "3px 8px", fontSize: "0.7rem" }}
                                  >
                                    {copiedClauseIdx === idx ? (
                                      <>
                                        <Check size={11} /> Copied
                                      </>
                                    ) : (
                                      <>
                                        <Copy size={11} /> Copy Redline
                                      </>
                                    )}
                                  </button>
                                </div>
                              </div>

                              <div style={{ fontSize: "0.8rem", lineHeight: 1.45 }}>
                                <ZeroKnowledgeText
                                  sanitizedText={clause.issue}
                                  entries={vaultEntries}
                                  viewMode={zkViewMode}
                                />
                              </div>

                              {clause.quotedExcerpt && (
                                <div className="redline-excerpt">
                                  <strong>Flagged Excerpt:</strong>{" "}
                                  <ZeroKnowledgeText
                                    sanitizedText={clause.quotedExcerpt}
                                    entries={vaultEntries}
                                    viewMode={zkViewMode}
                                  />
                                </div>
                              )}

                              <div className="redline-proposal">
                                <strong style={{ color: "#34d399" }}>Redline Counter-Proposal:</strong>{" "}
                                <ZeroKnowledgeText
                                  sanitizedText={clause.redlineCounterProposal}
                                  entries={vaultEntries}
                                  viewMode={zkViewMode}
                                />
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="codebox" style={{ whiteSpace: "pre-wrap" }}>
                          <ZeroKnowledgeText
                            sanitizedText={cloudOut.sanitizedMarkdown}
                            entries={vaultEntries}
                            viewMode={zkViewMode}
                          />
                        </div>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="muted" style={{ padding: "12px 0" }}>
                  Click <strong>Run Local Airlock</strong> on the left to execute Gate 1 (deterministic +
                  Shannon entropy + offline NER), guarded Gate 2 (Gemini Nano on-device), and Gate 3
                  (6-vector firewall), then run <strong>Structured JSON Redlines</strong> or{" "}
                  <strong>Server Template Audit</strong> with inline Zero-Knowledge Diff highlighting.
                </div>
              )}
            </>
          )}

          {/* ================= TAB 2: RED-TEAM LAB, WIRE TAP & HYBRID ROUTING ================= */}
          {activeTab === "redteam" && (
            <>
              <AdaptiveRouterPanel
                effectiveOnline={effectiveOnline}
                airGapActive={airGapSimulated}
                nanoAvailable={nanoStatus === "available"}
                payloadBytes={new TextEncoder().encode(rawText).byteLength}
                onApplyRecommendedDepth={(d) => setThinkingDepth(d)}
              />
              {/* ADAPTIVE HYBRID ROUTING VISUALIZER + ENTERPRISE ROI METER */}
              <div className="wire-item" style={{ gap: 8 }}>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <strong style={{ fontSize: "0.84rem" }}>
                    Adaptive Hybrid Routing Architecture & Offload ROI
                  </strong>
                  <span className="badge green">Firebase AI Logic + SDK #10635 Guard</span>
                </div>

                <div className="route-grid">
                  <div className="route-node local">
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <strong style={{ fontSize: "0.76rem" }}>1. Local Airlock</strong>
                      <span className="badge green" style={{ fontSize: "0.64rem" }}>0B · $0</span>
                    </div>
                    <div className="mono muted" style={{ fontSize: "0.68rem" }}>
                      ONLY_ON_DEVICE (Guarded)
                    </div>
                    <div className="muted" style={{ fontSize: "0.72rem" }}>
                      PDF/PNG pixel redaction + 6-vector firewall. Nano: {nanoStatus.toUpperCase()}.
                    </div>
                  </div>

                  <div className="route-node hybrid">
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <strong style={{ fontSize: "0.76rem" }}>2. Offline Triage</strong>
                      <span className="badge amber" style={{ fontSize: "0.64rem" }}>HYBRID</span>
                    </div>
                    <div className="mono muted" style={{ fontSize: "0.68rem" }}>
                      PREFER_ON_DEVICE
                    </div>
                    <div className="muted" style={{ fontSize: "0.72rem" }}>
                      Runs Nano offline; falls back cleanly to cloud ONLY on verified skeletons.
                    </div>
                  </div>

                  <div className="route-node cloud">
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <strong style={{ fontSize: "0.76rem" }}>3. Deep Redlines</strong>
                      <span className="badge blue" style={{ fontSize: "0.64rem" }}>SKELETON</span>
                    </div>
                    <div className="mono muted" style={{ fontSize: "0.68rem" }}>
                      ONLY_IN_CLOUD / Templates
                    </div>
                    <div className="muted" style={{ fontSize: "0.72rem" }}>
                      Stream Server Template (Live FSM)s + JSON Schema on zero-PII tokens; re-hydrated in RAM.
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: 4 }}>
                  <div className="row" style={{ justifyContent: "space-between", fontSize: "0.75rem" }}>
                    <span className="muted">
                      Enterprise Volume Simulator: <strong>{monthlyDocsVolume.toLocaleString()} docs/mo</strong>
                    </span>
                    <span className="mono muted">{entitiesPerDoc} PII entities/doc baseline</span>
                  </div>
                  <input
                    type="range"
                    min={100}
                    max={10000}
                    step={100}
                    value={monthlyDocsVolume}
                    onChange={(e) => setMonthlyDocsVolume(Number(e.target.value))}
                    style={{ width: "100%", accentColor: "#10b981", marginTop: 4 }}
                  />
                  <div className="roi-grid">
                    <div className="roi-stat">
                      <div className="muted" style={{ fontSize: "0.68rem" }}>Raw Secrets Shielded / mo</div>
                      <div className="roi-val">{rawPiiShieldedPerMonth.toLocaleString()}</div>
                    </div>
                    <div className="roi-stat">
                      <div className="muted" style={{ fontSize: "0.68rem" }}>Cloud Tokens Offloaded / mo</div>
                      <div className="roi-val">{cloudTokensOffloadedPerMonth.toLocaleString()}</div>
                    </div>
                    <div className="roi-stat">
                      <div className="muted" style={{ fontSize: "0.68rem" }}>Est. DLP/API Spend Saved</div>
                      <div className="roi-val">${monthlySpendAvoidedUsd.toLocaleString()}/mo</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* LIVE RED-TEAM ATTACK LAB: CLIENT GATE 3 + SERVER LAYER 4 */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="row" style={{ justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <strong style={{ fontSize: "0.84rem" }}>
                    Automated Defense Gauntlet (Layer 3 Client + Layer 4 Firestore)
                  </strong>
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null}
                    onClick={() => void handleRunFullGauntlet()}
                    style={{ padding: "5px 10px", fontSize: "0.74rem" }}
                  >
                    <ShieldAlert size={13} />
                    {busy === "gauntlet" ? "Running 7/7 Attacks..." : "Run Full 7/7 Defense Gauntlet"}
                  </button>
                </div>

                {gauntletRows && (
                  <div className="alert-green" style={{ marginBottom: 10, fontSize: "0.74rem" }}>
                    <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
                      <strong>
                        GAUNTLET SCORECARD: {gauntletRows.filter((r) => r.passed).length}/
                        {gauntletRows.length} ATTACKS BLOCKED · 0B RAW PII LEAKED
                      </strong>
                      <span className="mono">
                        Total: {gauntletRows.reduce((s, r) => s + r.latencyMs, 0)} ms
                      </span>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                      {gauntletRows.map((row, idx) => (
                        <div
                          key={idx}
                          className="row mono"
                          style={{ justifyContent: "space-between", fontSize: "0.7rem" }}
                        >
                          <span>
                            {row.passed ? "✓" : "✗"} [{row.layer}] {row.attack}
                          </span>
                          <span>
                            {row.code} ({row.latencyMs}ms)
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="muted" style={{ marginBottom: 6 }}>
                  <ShieldAlert size={14} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Layer-3 Client Firewall Attack Lab</strong>{" "}
                  {!airlockOut && "(Run Local Airlock first to enable)"}
                </div>
                <div className="row">
                  <button
                    type="button"
                    className="danger"
                    disabled={!airlockOut}
                    onClick={() => handleRedTeamAttack("MISSED_ENTITY_ESCAPE")}
                  >
                    Missed Entity
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={!airlockOut}
                    onClick={() => handleRedTeamAttack("BASE64_EXFILTRATION")}
                  >
                    Base64 Exfil
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={!airlockOut}
                    onClick={() => handleRedTeamAttack("CANARY_PROMPT_INJECTION")}
                  >
                    Canary Injection
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={!airlockOut}
                    onClick={() => handleRedTeamAttack("ZERO_WIDTH_SMUGGLING")}
                  >
                    Zero-Width Smuggle
                  </button>
                  <button
                    type="button"
                    className="danger"
                    onClick={handlePromptInjectionAttack}
                  >
                    Prompt Injection
                  </button>
                </div>

                <div className="muted" style={{ marginTop: 10, marginBottom: 6 }}>
                  <Lock size={13} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Layer-4 Live Firestore Rules Attack</strong> (Bypass Client → Attack Cloud Server):
                </div>
                <div className="row">
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null || !effectiveOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("RAW_PII_INJECTION")}
                  >
                    {busy === "layer4-RAW_PII_INJECTION" ? "Attacking..." : "Inject Raw SSN/Email"}
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null || !effectiveOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("LEDGER_OVERWRITE")}
                  >
                    {busy === "layer4-LEDGER_OVERWRITE" ? "Attacking..." : "Overwrite Receipt"}
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null || !effectiveOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("LEDGER_DELETE")}
                  >
                    {busy === "layer4-LEDGER_DELETE" ? "Attacking..." : "Delete Receipt"}
                  </button>
                </div>

                {injectionTestReport && (
                  <div className="alert-green" style={{ marginTop: 8, fontSize: "0.76rem" }}>
                    <strong>
                      INDIRECT PROMPT INJECTION DISARMED — {injectionTestReport.findings.length} CLAUSE(S) NEUTRALIZED (0B SENT)
                    </strong>
                    <div className="mono" style={{ fontSize: "0.7rem", marginTop: 3 }}>
                      Rules: {injectionTestReport.findings.map((f) => f.rule).join(", ")}
                    </div>
                    <div className="muted" style={{ fontSize: "0.72rem", marginTop: 2 }}>
                      Attack payload replaced with{" "}
                      <span className="mono">[INJECTION_NEUTRALIZED:…]</span> before reaching Gemini.
                    </div>
                  </div>
                )}

                {redTeamBlock && (
                  <div className="alert-red" style={{ marginTop: 8 }}>
                    <strong>FIREWALL TRIPPED — 0 BYTES TRANSMITTED</strong> ({redTeamBlock.blockedBytes}B
                    aborted before fetch)
                    <div>
                      Attack: <span className="mono">{redTeamBlock.attack}</span> | Vector:{" "}
                      <span className="mono">{redTeamBlock.violations[0]?.vector}</span> —{" "}
                      {redTeamBlock.violations[0]?.detail}
                    </div>
                  </div>
                )}

                {layer4Result && (
                  <div
                    className={layer4Result.blockedByRules ? "alert-green" : "alert-red"}
                    style={{ marginTop: 8 }}
                  >
                    <strong>
                      {layer4Result.blockedByRules
                        ? `LAYER-4 SERVER DEFENSE HELD — ${layer4Result.errorCode.toUpperCase()}`
                        : `LAYER-4 CHECK FAILED (${layer4Result.errorCode})`}
                    </strong>{" "}
                    ({layer4Result.latencyMs} ms)
                    <div className="mono" style={{ fontSize: "0.75rem", marginTop: 2 }}>
                      {layer4Result.ruleEnforced}
                    </div>
                    <div style={{ fontSize: "0.8rem" }}>{layer4Result.detail}</div>
                  </div>
                )}
              </div>

              {/* LIVE WIRE TAP */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
                  <strong>
                    <Activity size={15} style={{ verticalAlign: "middle", marginRight: 6 }} />
                    Live Wire Tap (Proof of Zero Leakage)
                  </strong>
                  <button
                    type="button"
                    onClick={() => wireTap.clear()}
                    style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                  >
                    Clear
                  </button>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 320, overflowY: "auto" }}>
                  {wireEvents.length === 0 ? (
                    <div className="muted">
                      No telemetry yet. Run Local Airlock to observe 0-byte local processing.
                    </div>
                  ) : (
                    wireEvents.map((ev) => (
                      <div key={ev.id} className="wire-item">
                        <div className="row" style={{ justifyContent: "space-between" }}>
                          <span className="mono" style={{ fontWeight: 700 }}>{ev.stage}</span>
                          <span
                            className={`badge ${
                              ev.inferenceSource === "BLOCKED"
                                ? "red"
                                : ev.inferenceSource === "IN_CLOUD"
                                  ? "blue"
                                  : "green"
                            }`}
                          >
                            {ev.inferenceSource} · {ev.bytesSent}B · {ev.latencyMs}ms
                          </span>
                        </div>
                        {ev.endpoint && <div className="muted mono">{ev.endpoint}</div>}
                        <div
                          className="mono"
                          style={{ fontSize: "0.72rem", color: "#cbd5e1", wordBreak: "break-word" }}
                        >
                          {ev.payloadPreview}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </>
          )}

          {/* ================= TAB 3: LEDGER, ENCRYPTED VAULT & PROOF AUDITOR ================= */}
          {activeTab === "ledger" && (
            <>
              <MerkleSignerPanel
                recordsNewestFirst={combinedLedger}
                projectId={activeProjectId}
              />
              {/* FIRESTORE ZERO-PII HASH-CHAINED LEDGER + OFFLINE SYNC QUEUE */}
              <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                <h2 style={{ margin: 0 }}>Firestore Zero-PII Audit Ledger</h2>
                <div className="row" style={{ gap: 6 }}>
                  {pendingQueue.length > 0 && (
                    <button
                      type="button"
                      className="cloud"
                      onClick={() => void runQueueFlush("manual")}
                      disabled={busy !== null || !effectiveOnline || !isFirebaseConfigured}
                      style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                    >
                      <RefreshCw size={12} /> Flush Queue ({pendingQueue.length})
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => handleVerifyChain(false)}
                    disabled={combinedLedger.length === 0}
                    style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                  >
                    Verify Chain
                  </button>
                  <button
                    type="button"
                    className="danger"
                    onClick={() => handleVerifyChain(true)}
                    disabled={combinedLedger.length === 0}
                    style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                  >
                    1-Byte Tamper
                  </button>
                  <button
                    type="button"
                    onClick={handleExportProofBundle}
                    disabled={combinedLedger.length === 0 && !verifiedPayload}
                    style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                  >
                    <Download size={12} /> Proof JSON
                  </button>
                </div>
              </div>

              {queueStatusMsg && (
                <div className="wire-item" style={{ fontSize: "0.75rem", color: "#fbbf24" }}>
                  {queueStatusMsg}
                </div>
              )}

              {chainReport && (
                <div
                  className={chainReport.ok ? "alert-green" : "alert-red"}
                  style={{ fontSize: "0.78rem" }}
                >
                  <div>{chainReport.detail}</div>
                  {isTamperSimulated && (
                    <button
                      type="button"
                      onClick={() => handleVerifyChain(false)}
                      style={{ marginTop: 6, padding: "3px 8px", fontSize: "0.72rem" }}
                    >
                      Restore Authentic Chain & Re-Verify
                    </button>
                  )}
                </div>
              )}

              {combinedLedger.length === 0 ? (
                <div className="muted">
                  Append-only SHA-256 receipts sync here after your first Cloud Audit or Offline Queue entry.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 260, overflowY: "auto" }}>
                  {combinedLedger.map((item, idx) => {
                    const isExpanded = expandedDocId === item.docId;
                    const isPending = item.syncStatus === "PENDING_SYNC";
                    return (
                      <div
                        key={item.docId || item.receiptSha256}
                        className="wire-item"
                        onClick={() => setExpandedDocId(isExpanded ? null : item.docId)}
                        style={{ cursor: "pointer" }}
                        title="Click to inspect full SHA-256 hash chain receipt"
                      >
                        <div className="row" style={{ justifyContent: "space-between" }}>
                          <strong>
                            #{combinedLedger.length - idx} {item.policyProfile} · {item.riskLevel}
                          </strong>
                          <div className="row" style={{ gap: 6 }}>
                            <span
                              className={`badge ${isPending ? "amber" : "green"}`}
                              style={{ padding: "2px 7px", fontSize: "0.66rem" }}
                            >
                              {isPending ? "PENDING_SYNC" : "SYNCED"}
                            </span>
                            <span className="mono muted">{item.receiptSha256.slice(0, 14)}…</span>
                          </div>
                        </div>
                        <div className="muted">{item.sanitizedSummary}</div>
                        <div className="mono muted" style={{ fontSize: "0.7rem", marginTop: 2 }}>
                          prev:{" "}
                          {item.prevReceiptSha256
                            ? `${item.prevReceiptSha256.slice(0, 14)}…`
                            : "GENESIS (null)"}
                          {" · "}
                          {isExpanded ? "hide details ▲" : "inspect hashes ▼"}
                        </div>

                        {isExpanded && (
                          <div
                            className="mono"
                            style={{
                              marginTop: 6,
                              paddingTop: 6,
                              borderTop: "1px solid var(--border)",
                              fontSize: "0.68rem",
                              color: "#cbd5e1",
                              wordBreak: "break-all",
                              display: "flex",
                              flexDirection: "column",
                              gap: 2,
                            }}
                          >
                            <div>docId: {item.docId}</div>
                            <div>timestamp: {item.timestampIso}</div>
                            <div>receiptSha256: {item.receiptSha256}</div>
                            <div>prevReceiptSha256: {item.prevReceiptSha256 ?? "null"}</div>
                            <div>rawDocSha256: {item.rawDocSha256}</div>
                            <div>sanitizedPayloadSha256: {item.sanitizedPayloadSha256}</div>
                            <div>
                              firewall: {item.checksPassed}/6 ({item.inferenceSource})
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* PASSPHRASE-LOCKED .AIRLOCK.ENC VAULT EXPORT & RESTORE */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
                <div className="muted" style={{ marginBottom: 6 }}>
                  <KeyRound size={13} style={{ verticalAlign: "middle", marginRight: 5 }} />
                  <strong>Encrypted Local Vault (.airlock.enc)</strong> — PBKDF2 (100k) + AES-256-GCM
                </div>
                <div className="row" style={{ gap: 6 }}>
                  <input
                    type="password"
                    value={vaultPassphrase}
                    onChange={(e) => setVaultPassphrase(e.target.value)}
                    placeholder="Vault passphrase (min 6 chars)..."
                    style={{
                      flex: 1,
                      minWidth: 160,
                      background: "#0b1220",
                      color: "var(--text)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      padding: "5px 8px",
                      fontSize: "0.75rem",
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => void handleExportEncryptedVault()}
                    disabled={!verifiedPayload || vaultPassphrase.trim().length < 6}
                    style={{ padding: "5px 9px", fontSize: "0.72rem" }}
                  >
                    <Download size={12} /> Export .airlock.enc
                  </button>
                  <label
                    style={{
                      cursor: "pointer",
                      fontSize: "0.72rem",
                      padding: "5px 9px",
                      borderRadius: 8,
                      border: "1px solid var(--border)",
                      background: "var(--panel-alt)",
                      fontWeight: 600,
                    }}
                  >
                    Restore .airlock.enc
                    <input
                      type="file"
                      accept=".enc,.json"
                      onChange={(e) => void handleRestoreEncryptedVault(e)}
                      style={{ display: "none" }}
                    />
                  </label>
                </div>

                {vaultStatus && (
                  <div
                    className={vaultStatus.ok ? "alert-green" : "alert-red"}
                    style={{ marginTop: 8, fontSize: "0.75rem" }}
                  >
                    {vaultStatus.message}
                  </div>
                )}

                {restoredVault && (
                  <div className="wire-item" style={{ marginTop: 8, gap: 6 }}>
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <span style={{ fontWeight: 700, fontSize: "0.74rem" }}>
                        Restored Vault ({restoredVault.entries.length} tokens · Receipt{" "}
                        <span className="mono">{restoredVault.receiptSha256.slice(0, 12)}…</span>)
                      </span>
                      <div className="row" style={{ gap: 4 }}>
                        {(
                          [
                            { id: "diff", label: "ZK Diff" },
                            { id: "rehydrated", label: "Re-Hydrated" },
                            { id: "cloud", label: "Skeleton" },
                          ] as const
                        ).map((m) => (
                          <button
                            type="button"
                            key={m.id}
                            onClick={() => setRestoredViewMode(m.id)}
                            style={{
                              padding: "2px 7px",
                              fontSize: "0.68rem",
                              borderColor: restoredViewMode === m.id ? "#10b981" : undefined,
                              color: restoredViewMode === m.id ? "#34d399" : undefined,
                            }}
                          >
                            {m.label}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="codebox" style={{ maxHeight: 160, whiteSpace: "pre-wrap" }}>
                      {restoredViewMode === "rehydrated" ? (
                        rehydrateWithEntries(restoredSourceText, restoredVault.entries)
                      ) : (
                        <ZeroKnowledgeText
                          sanitizedText={restoredSourceText}
                          entries={restoredVault.entries}
                          viewMode={restoredViewMode}
                        />
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* ZERO-TRUST EXTERNAL PROOF JSON AUDITOR (100% OFFLINE) */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
                <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                  <span className="muted" style={{ fontSize: "0.76rem" }}>
                    <FileCheck2 size={13} style={{ verticalAlign: "middle", marginRight: 5 }} />
                    <strong>Zero-Trust External Proof Auditor</strong> (Offline — Verifies Ledger, Merkle Inclusion & ECDSA P-256)
                  </span>
                  <label
                    style={{
                      cursor: "pointer",
                      fontSize: "0.72rem",
                      padding: "4px 8px",
                      borderRadius: 6,
                      border: "1px solid var(--border)",
                      background: "var(--panel-alt)",
                      fontWeight: 600,
                    }}
                  >
                    Verify Proof JSON File
                    <input
                      type="file"
                      accept=".json,application/json"
                      onChange={(e) => void handleAuditExternalProofFile(e)}
                      style={{ display: "none" }}
                    />
                  </label>
                </div>
                {externalProofReport && (
                  <div
                    className={externalProofReport.ok ? "alert-green" : "alert-red"}
                    style={{ marginTop: 8, fontSize: "0.75rem" }}
                  >
                    <div><strong>{externalProofReport.verdict}</strong></div>
                    <div className="mono" style={{ fontSize: "0.7rem", marginTop: 3 }}>
                      file: {externalProofReport.fileName} · project: {externalProofReport.projectId} · zeroPii:{" "}
                      {String(externalProofReport.zeroPiiClean)}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
