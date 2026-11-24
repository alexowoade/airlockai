import { useEffect, useState, type ChangeEvent, type DragEvent } from "react";
import {
  Activity,
  Cloud,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileImage,
  FileText,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Upload,
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
  verifyLedgerChain,
  type ChainVerificationReport,
} from "./utils/chainVerifier.js";

const MAX_LOCAL_FILE_BYTES = 1_048_576; // 1 MB local browser cap
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

  const [policy, setPolicy] = useState<AirlockPolicyConfig>(DEFAULT_POLICY);
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
  const [expandedDocId, setExpandedDocId] = useState<string | null>(null);
  const [chainReport, setChainReport] = useState<ChainVerificationReport | null>(null);
  const [isTamperSimulated, setIsTamperSimulated] = useState(false);

  useEffect(() => {
    const unsub = wireTap.subscribe(setWireEvents);
    checkLocalNanoStatus().then(setNanoStatus);
    fetchRemotePolicy().then(setPolicy);
    fetchZeroPiiAuditLedger()
      .then(setLedger)
      .catch(() => {});

    const onOnline = () => setIsOnline(true);
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

  function processLocalFile(file: File) {
    setErrorMsg(null);
    if (file.size > MAX_LOCAL_FILE_BYTES) {
      setErrorMsg("Local file exceeds 1 MB demo cap. Please choose a smaller document or screenshot.");
      return;
    }

    const lowerName = file.name.toLowerCase();
    const isImage = file.type === "image/png" || file.type === "image/jpeg";
    const isText =
      file.type.startsWith("text/") ||
      file.type === "application/json" ||
      TEXT_EXTENSIONS.some((ext) => lowerName.endsWith(ext));

    if (isImage) {
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = String(reader.result);
        setImageInput({
          dataUrl,
          base64: dataUrl.split(",")[1]!,
          mimeType: file.type as "image/png" | "image/jpeg",
        });
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

    setErrorMsg("Unsupported file type. Drop a .txt, .md, .csv, .json document or a .png/.jpg image.");
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
    setRawText(SAMPLE_DOCS[2]!.text);
    setUploadedFileName("synthetic-medical-bill.png");
    handleSelectPolicy("MEDICAL_HIPAA");
  }

  async function handleRunLocalAirlock() {
    setBusy("airlock");
    setErrorMsg(null);
    setRedTeamBlock(null);
    setLayer4Result(null);
    setTriageOut(null);
    setCloudOut(null);

    try {
      const prevHash = ledger[0]?.receiptSha256 ?? null;
      const result = await runLocalAirlock({
        rawText,
        imageBase64: imageInput
          ? { mimeType: imageInput.mimeType, data: imageInput.base64 }
          : undefined,
        policy,
        prevReceiptSha256: prevHash,
      });
      setAirlockOut(result);

      if (imageInput) {
        const redactedDataUrl = await renderRedactedImageOverlay(imageInput.dataUrl);
        setImageInput((prev) => (prev ? { ...prev, redactedDataUrl } : null));
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Local Airlock failed.");
    } finally {
      setBusy(null);
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
    const targetRecords = simulateTamper ? simulateOneByteTamper(ledger) : ledger;
    const report = await verifyLedgerChain(targetRecords);
    setIsTamperSimulated(simulateTamper);
    setChainReport(report);
  }

  function handleExportProofBundle() {
    const json = buildComplianceProofJson({
      projectId: activeProjectId,
      verifiedPayload,
      ledger,
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
            <button onClick={handleDownloadNano} disabled={downloadPct !== null}>
              <Download size={14} />
              {downloadPct !== null ? `Downloading ${downloadPct}%` : "Download Nano"}
            </button>
          )}
        </div>
      </header>

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
                key={sample.id}
                onClick={() => {
                  setRawText(sample.text);
                  setImageInput(null);
                  setUploadedFileName(null);
                  handleSelectPolicy(sample.policy);
                }}
              >
                {sample.label}
              </button>
            ))}
            <button onClick={handleGenerateSyntheticPng}>
              <FileImage size={14} /> Medical Bill PNG
            </button>
          </div>

          <div className="row">
            <span className="muted">Remote Config Policy:</span>
            {(["NDA_STRICT", "MEDICAL_HIPAA", "INVOICE_FINANCE"] as const).map((p) => (
              <button
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

          {/* LOCAL FILE DROPZONE (TEXT + IMAGE, 100% ON-DEVICE) */}
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
              marginBottom: 8,
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
              {uploadedFileName
                ? `Loaded locally (0B sent): ${uploadedFileName}`
                : "Drop your own .txt, .md, .csv, .json, or .png/.jpg here (processed 100% locally)"}
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
                accept=".txt,.md,.csv,.json,image/png,image/jpeg"
                onChange={handleFileUpload}
                style={{ display: "none" }}
              />
            </label>
          </div>

          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste a sensitive NDA, invoice, medical bill, or drop a local file above..."
          />

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
            className="primary"
            onClick={handleRunLocalAirlock}
            disabled={busy !== null || (!rawText.trim() && !imageInput)}
          >
            <ShieldCheck size={16} />
            {busy === "airlock"
              ? "Running 3-Gate Local Airlock..."
              : "Run Local Airlock (Gate 1 + Nano Gate 2 + Gate 3)"}
          </button>
        </section>

        {/* CENTER COLUMN: SANITIZED AIRLOCK, RED-TEAM LAB & RE-HYDRATED AUDIT */}
        <section className="card">
          <h2>
            <span>2. Verified Airlock & Hybrid Inference</span>
            {verifiedPayload && (
              <span className="badge green">6/6 Firewall Checks Passed</span>
            )}
          </h2>

          {verifiedPayload ? (
            <>
              <div className="alert-green">
                <strong>SHA-256 Attestation Minted:</strong>{" "}
                <span className="mono">{verifiedPayload.receipt.receiptSha256.slice(0, 24)}…</span>{" "}
                | Redacted: <strong>{verifiedPayload.receipt.redactedCount}</strong> entities (Gate 1:{" "}
                {airlockOut!.gate1Count}, Nano Gate 2: {airlockOut!.gate2Count})
              </div>

              <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                <span className="muted">Sanitized Skeleton (Only this crosses the network):</span>
                <button
                  onClick={handleDownloadScrubbedText}
                  style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                >
                  <FileText size={12} /> Download Scrubbed Copy (.txt)
                </button>
              </div>
              <div className="codebox">{verifiedPayload.sanitizedText}</div>

              <div className="row">
                <button onClick={handleOfflineTriage} disabled={busy !== null || !isFirebaseConfigured}>
                  <Zap size={15} />
                  {busy === "triage" ? "Triaging..." : "Offline Triage (PREFER_ON_DEVICE)"}
                </button>
                <button
                  className="cloud"
                  onClick={handleCloudAudit}
                  disabled={busy !== null || !isOnline || !isFirebaseConfigured}
                >
                  <Cloud size={15} />
                  {busy === "cloud" ? "Auditing in Cloud..." : "Deep Cloud Audit (Server Template)"}
                </button>
              </div>

              {/* RED-TEAM ATTACK LAB: CLIENT GATE 3 + SERVER LAYER 4 */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="muted" style={{ marginBottom: 6 }}>
                  <ShieldAlert size={14} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Live Red-Team Attack Lab</strong> (Layer 3 Client Firewall):
                </div>
                <div className="row">
                  <button className="danger" onClick={() => handleRedTeamAttack("MISSED_ENTITY_ESCAPE")}>
                    Missed Entity
                  </button>
                  <button className="danger" onClick={() => handleRedTeamAttack("BASE64_EXFILTRATION")}>
                    Base64 Exfil
                  </button>
                  <button className="danger" onClick={() => handleRedTeamAttack("CANARY_PROMPT_INJECTION")}>
                    Canary Injection
                  </button>
                  <button className="danger" onClick={() => handleRedTeamAttack("ZERO_WIDTH_SMUGGLING")}>
                    Zero-Width Smuggle
                  </button>
                </div>

                <div className="muted" style={{ marginTop: 8, marginBottom: 6 }}>
                  <Lock size={13} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Layer-4 Server Attack</strong> (Bypass Client → Attack Live Firestore Rules):
                </div>
                <div className="row">
                  <button
                    className="danger"
                    disabled={busy !== null || !isOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("RAW_PII_INJECTION")}
                  >
                    {busy === "layer4-RAW_PII_INJECTION" ? "Attacking..." : "Inject Raw SSN/Email"}
                  </button>
                  <button
                    className="danger"
                    disabled={busy !== null || !isOnline || !isFirebaseConfigured}
                    onClick={() => handleLayer4Attack("LEDGER_OVERWRITE")}
                  >
                    {busy === "layer4-LEDGER_OVERWRITE" ? "Attacking..." : "Overwrite Receipt"}
                  </button>
                  <button
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
                    <button onClick={() => setShowRehydrated((v) => !v)}>
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

        {/* RIGHT COLUMN: LIVE WIRE TAP & FIRESTORE HASH-CHAINED LEDGER */}
        <section className="card">
          <h2>
            <span>
              <Activity size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />
              3. Live Wire Tap (Proof of Zero Leakage)
            </span>
            <button onClick={() => wireTap.clear()} style={{ padding: "4px 8px", fontSize: "0.72rem" }}>
              Clear
            </button>
          </h2>

          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 340, overflowY: "auto" }}>
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
                <button
                  onClick={() => handleVerifyChain(false)}
                  disabled={ledger.length === 0}
                  style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                >
                  Verify Chain
                </button>
                <button
                  className="danger"
                  onClick={() => handleVerifyChain(true)}
                  disabled={ledger.length === 0}
                  style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                >
                  1-Byte Tamper
                </button>
                <button
                  onClick={handleExportProofBundle}
                  disabled={ledger.length === 0 && !verifiedPayload}
                  style={{ padding: "4px 8px", fontSize: "0.72rem" }}
                >
                  <Download size={12} /> Proof JSON
                </button>
              </div>
            </div>

            {chainReport && (
              <div
                className={chainReport.ok ? "alert-green" : "alert-red"}
                style={{ marginBottom: 8, fontSize: "0.78rem" }}
              >
                <div>{chainReport.detail}</div>
                {isTamperSimulated && (
                  <button
                    onClick={() => handleVerifyChain(false)}
                    style={{ marginTop: 6, padding: "3px 8px", fontSize: "0.72rem" }}
                  >
                    Restore Authentic Chain & Re-Verify
                  </button>
                )}
              </div>
            )}

            {ledger.length === 0 ? (
              <div className="muted">
                Append-only SHA-256 receipts sync here after your first Cloud Audit (raw PII is rejected by
                server-side Firestore Security Rules).
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {ledger.map((item, idx) => {
                  const isExpanded = expandedDocId === item.docId;
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
                          #{ledger.length - idx} {item.policyProfile} · {item.riskLevel}
                        </strong>
                        <span className="mono muted">{item.receiptSha256.slice(0, 14)}…</span>
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
          </div>
        </section>
      </div>
    </div>
  );
}
