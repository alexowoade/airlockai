import { useEffect, useState, type ChangeEvent, type DragEvent } from "react";
import {
  Activity,
  Cloud,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileCheck2,
  FileImage,
  FileText,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
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

const MAX_LOCAL_FILE_BYTES = 5_242_880; // 5 MB local browser cap for PDFs/images/text
const TEXT_EXTENSIONS = [".txt", ".md", ".csv", ".json"];

export default function App() {
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
  const [showRehydrated, setShowRehydrated] = useState(true);

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
  const [showRestoredRehydrated, setShowRestoredRehydrated] = useState(true);
  const [externalProofReport, setExternalProofReport] = useState<ExternalProofAuditReport | null>(
    null
  );

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
        strictSafeHarbor: activeSafeHarbor,
      });
      setAirlockOut(result);

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
      setShowRestoredRehydrated(true);
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

  async function handleCloudAudit() {
    if (!airlockOut || !airlockOut.firewallResult.ok) return;
    setBusy("cloud");
    setErrorMsg(null);
    try {
      const res = await runDeepCloudAudit({
        verified: airlockOut.firewallResult.payload,
        vault: airlockOut.vault,
        policyProfile: policy.profile,
        templateIdOverride: policy.templateId,
      });
      setCloudOut(res);
      const updated = await fetchZeroPiiAuditLedger().catch(() => []);
      if (updated.length > 0) {
        setLedger(updated);
        setChainReport(null);
        setIsTamperSimulated(false);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Cloud audit failed.");
    } finally {
      setBusy(null);
    }
  }

  const verifiedPayload = airlockOut?.firewallResult.ok ? airlockOut.firewallResult.payload : null;
  const gate3BlockedViolations =
    airlockOut && !airlockOut.firewallResult.ok ? airlockOut.firewallResult.violations : null;
  const isCloudGatedByResidual = Boolean(
    airlockOut?.residualRisk.failClosedRecommended && !residualOverrideAccepted
  );
  const currentPdfPage = pdfDoc?.pages[pdfPageIdx] ?? null;

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
          <span className={`badge ${isOnline ? "blue" : "amber"}`}>
            {isOnline ? "ONLINE" : "OFFLINE MODE"}
          </span>
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

      <div className="grid">
        {/* LEFT COLUMN: RAW LOCAL INPUT STAGE */}
        <section className="card">
          <h2>
            <span>1. Local Document Stage (Never Leaves Device)</span>
            <span className="badge blue">{policy.profile}</span>
          </h2>

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
                    <button
                      type="button"
                      onClick={handleDownloadRedactedPdfPage}
                      style={{ padding: "3px 8px", fontSize: "0.72rem" }}
                    >
                      <Download size={12} /> Redacted Page PNG
                    </button>
                  )}
                </div>
              </div>
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

          {/* PASSPHRASE-LOCKED .AIRLOCK.ENC VAULT EXPORT & RESTORE */}
          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
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
                  <button
                    type="button"
                    onClick={() => setShowRestoredRehydrated((v) => !v)}
                    style={{ padding: "3px 8px", fontSize: "0.7rem" }}
                  >
                    {showRestoredRehydrated ? <Eye size={12} /> : <EyeOff size={12} />}
                    {showRestoredRehydrated ? "Restored Re-Hydrated" : "Sanitized Skeleton"}
                  </button>
                </div>
                <div className="codebox" style={{ maxHeight: 140 }}>
                  {showRestoredRehydrated
                    ? rehydrateWithEntries(restoredSourceText, restoredVault.entries)
                    : restoredSourceText}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* CENTER COLUMN: SANITIZED AIRLOCK, RESIDUAL GUARD, RED-TEAM LAB & RE-HYDRATED AUDIT */}
        <section className="card">
          <h2>
            <span>2. Verified Airlock & Hybrid Inference</span>
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
                  <div className="muted" style={{ marginTop: 6, fontSize: "0.75rem", color: "#fecaca" }}>
                    Tip: Enable <strong>Strict Safe Harbor</strong> (to scrub URLs/IPs/ZIPs/IDs) or add the leaking phrase to your <strong>Custom Secret Vault</strong> below to re-verify.
                  </div>
                </div>
              )}

              {/* HIPAA SAFE HARBOR RISK METER + FAIL-CLOSED RESIDUAL PROPER-NOUN GUARD + CUSTOM VAULT */}
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

                {/* CUSTOM SECRET VAULT */}
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

              <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                <span className="muted">
                  {verifiedPayload
                    ? "Sanitized Skeleton (Only this crosses the network):"
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
              <div className="codebox">
                {verifiedPayload ? verifiedPayload.sanitizedText : airlockOut.candidateSanitized}
              </div>

              <div className="row">
                <button
                  type="button"
                  onClick={handleQueueOfflineReceipt}
                  disabled={busy !== null || !verifiedPayload}
                >
                  <WifiOff size={15} />
                  Queue Offline Receipt (0B Cloud)
                </button>
                <button
                  type="button"
                  onClick={handleOfflineTriage}
                  disabled={busy !== null || !verifiedPayload || !isFirebaseConfigured || isCloudGatedByResidual}
                >
                  <Zap size={15} />
                  {busy === "triage" ? "Triaging..." : "Offline Triage (PREFER_ON_DEVICE)"}
                </button>
                <button
                  type="button"
                  className="cloud"
                  onClick={handleCloudAudit}
                  disabled={
                    busy !== null ||
                    !verifiedPayload ||
                    !isOnline ||
                    !isFirebaseConfigured ||
                    isCloudGatedByResidual
                  }
                >
                  <Cloud size={15} />
                  {busy === "cloud"
                    ? "Auditing in Cloud..."
                    : !verifiedPayload
                      ? "Cloud Locked (Gate 3 Firewall Blocked)"
                      : isCloudGatedByResidual
                        ? "Cloud Locked (Review Flagged Terms)"
                        : "Deep Cloud Audit (Server Template)"}
                </button>
              </div>

              {/* RED-TEAM ATTACK LAB: CLIENT GATE 3 + SERVER LAYER 4 */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="muted" style={{ marginBottom: 6 }}>
                  <ShieldAlert size={14} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Live Red-Team Attack Lab</strong> (Layer 3 Client Firewall):
                </div>
                <div className="row">
                  <button type="button" className="danger" onClick={() => handleRedTeamAttack("MISSED_ENTITY_ESCAPE")}>
                    Missed Entity
                  </button>
                  <button type="button" className="danger" onClick={() => handleRedTeamAttack("BASE64_EXFILTRATION")}>
                    Base64 Exfil
                  </button>
                  <button type="button" className="danger" onClick={() => handleRedTeamAttack("CANARY_PROMPT_INJECTION")}>
                    Canary Injection
                  </button>
                  <button type="button" className="danger" onClick={() => handleRedTeamAttack("ZERO_WIDTH_SMUGGLING")}>
                    Zero-Width Smuggle
                  </button>
                </div>

                <div className="muted" style={{ marginTop: 8, marginBottom: 6 }}>
                  <Lock size={13} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Layer-4 Server Attack</strong> (Bypass Client → Attack Live Firestore Rules):
                </div>
                <div className="row">
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null || !isOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("RAW_PII_INJECTION")}
                  >
                    {busy === "layer4-RAW_PII_INJECTION" ? "Attacking..." : "Inject Raw SSN/Email"}
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null || !isOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("LEDGER_OVERWRITE")}
                  >
                    {busy === "layer4-LEDGER_OVERWRITE" ? "Attacking..." : "Overwrite Receipt"}
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={busy !== null || !isOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("LEDGER_DELETE")}
                  >
                    {busy === "layer4-LEDGER_DELETE" ? "Attacking..." : "Delete Receipt"}
                  </button>
                </div>
              </div>

              {redTeamBlock && (
                <div className="alert-red">
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
                <div className={layer4Result.blockedByRules ? "alert-green" : "alert-red"}>
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

              {triageOut && (
                <div className="wire-item">
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <strong>Quick Triage: {triageOut.documentType} ({triageOut.quickRiskLevel})</strong>
                    <span className={`badge ${triageOut.inferenceSource === "ON_DEVICE" ? "green" : "blue"}`}>
                      {triageOut.inferenceSource} · {triageOut.latencyMs} ms
                    </span>
                  </div>
                  <div>{triageOut.oneLineSummary}</div>
                </div>
              )}

              {cloudOut && (
                <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                  <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
                    <strong>
                      Cloud Audit ({cloudOut.usedServerTemplate ? cloudOut.templateId : "ONLY_IN_CLOUD"}) ·{" "}
                      {cloudOut.latencyMs} ms
                    </strong>
                    <button type="button" onClick={() => setShowRehydrated((v) => !v)}>
                      {showRehydrated ? <Eye size={14} /> : <EyeOff size={14} />}
                      {showRehydrated ? "Showing Local Re-Hydrated" : "Showing What Cloud Saw"}
                    </button>
                  </div>
                  <div className="codebox">
                    {showRehydrated ? cloudOut.rehydratedMarkdown : cloudOut.sanitizedMarkdown}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="muted">
              Click <strong>Run Local Airlock</strong> on the left to execute Gate 1 (deterministic +
              Shannon entropy + offline NER), guarded Gate 2 (Gemini Nano on-device), and Gate 3
              (6-vector firewall).
            </div>
          )}
        </section>

        {/* RIGHT COLUMN: LIVE WIRE TAP, OFFLINE-SYNC LEDGER & ZERO-TRUST EXTERNAL PROOF AUDITOR */}
        <section className="card">
          <h2>
            <span>
              <Activity size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />
              3. Live Wire Tap (Proof of Zero Leakage)
            </span>
            <button type="button" onClick={() => wireTap.clear()} style={{ padding: "4px 8px", fontSize: "0.72rem" }}>
              Clear
            </button>
          </h2>

          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 300, overflowY: "auto" }}>
            {wireEvents.length === 0 ? (
              <div className="muted">No telemetry yet. Run Local Airlock to observe 0-byte local processing.</div>
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
                  <div className="mono" style={{ fontSize: "0.72rem", color: "#cbd5e1", wordBreak: "break-word" }}>
                    {ev.payloadPreview}
                  </div>
                </div>
              ))
            )}
          </div>

          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
            <div className="row" style={{ justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <h2 style={{ margin: 0 }}>Firestore Zero-PII Audit Ledger</h2>
              <div className="row" style={{ gap: 6 }}>
                {pendingQueue.length > 0 && (
                  <button
                    type="button"
                    className="cloud"
                    onClick={() => void runQueueFlush("manual")}
                    disabled={busy !== null || !isOnline || !isFirebaseConfigured}
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
              <div className="wire-item" style={{ marginBottom: 8, fontSize: "0.75rem", color: "#fbbf24" }}>
                {queueStatusMsg}
              </div>
            )}

            {chainReport && (
              <div
                className={chainReport.ok ? "alert-green" : "alert-red"}
                style={{ marginBottom: 8, fontSize: "0.78rem" }}
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
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
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
                          <span className={`badge ${isPending ? "amber" : "green"}`} style={{ padding: "2px 7px", fontSize: "0.66rem" }}>
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

            {/* ZERO-TRUST EXTERNAL PROOF JSON AUDITOR (100% OFFLINE) */}
            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10, marginTop: 12 }}>
              <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                <span className="muted" style={{ fontSize: "0.76rem" }}>
                  <FileCheck2 size={13} style={{ verticalAlign: "middle", marginRight: 5 }} />
                  <strong>Zero-Trust External Proof Auditor</strong> (Offline)
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
          </div>
        </section>
      </div>
    </div>
  );
}
