import { useEffect, useState, type ChangeEvent } from "react";
import {
  Activity,
  Cloud,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileImage,
  Lock,
  ShieldAlert,
  ShieldCheck,
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
  checkLocalNanoStatus,
  DEFAULT_POLICY,
  fetchRemotePolicy,
  fetchZeroPiiAuditLedger,
  isFirebaseConfigured,
  POLICY_TEMPLATES,
  triggerLocalNanoDownload,
  type AirlockPolicyConfig,
  type LedgerEntry,
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

export default function App() {
  const [rawText, setRawText] = useState(SAMPLE_DOCS[0]!.text);
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

  const [triageOut, setTriageOut] = useState<OfflineTriageOutput | null>(null);
  const [cloudOut, setCloudOut] = useState<CloudAuditOutput | null>(null);
  const [showRehydrated, setShowRehydrated] = useState(true);

  const [wireEvents, setWireEvents] = useState<ReadonlyArray<WireEvent>>([]);
  const [ledger, setLedger] = useState<ReadonlyArray<LedgerEntry>>([]);

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

  async function handleImageUpload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.type !== "image/png" && file.type !== "image/jpeg") {
      setErrorMsg("Please upload a PNG or JPEG document photo.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result);
      setImageInput({
        dataUrl,
        base64: dataUrl.split(",")[1]!,
        mimeType: file.type as "image/png" | "image/jpeg",
      });
      setRawText("");
    };
    reader.readAsDataURL(file);
  }

  function handleGenerateSyntheticPng() {
    const png = generateSyntheticMedicalBillPng();
    setImageInput(png);
    setRawText(SAMPLE_DOCS[2]!.text);
    handleSelectPolicy("MEDICAL_HIPAA");
  }

  async function handleRunLocalAirlock() {
    setBusy("airlock");
    setErrorMsg(null);
    setRedTeamBlock(null);
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
      if (updated.length > 0) setLedger(updated);
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

          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste a sensitive NDA, invoice, medical bill, or load a PNG below..."
          />

          <div className="row">
            <label className="muted" style={{ cursor: "pointer" }}>
              Upload PNG/JPEG:{" "}
              <input type="file" accept="image/png,image/jpeg" onChange={handleImageUpload} />
            </label>
          </div>

          {imageInput && (
            <div>
              <div className="muted" style={{ marginBottom: 4 }}>
                {imageInput.redactedDataUrl
                  ? "Local Canvas Pixel Redaction Applied (Raw pixels never sent):"
                  : "Local Image Staged (On-Device Nano Multimodal Input):"}
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

              <div className="muted">Sanitized Skeleton (Only this crosses the network):</div>
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

              {/* RED-TEAM ATTACK LAB */}
              <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="muted" style={{ marginBottom: 6 }}>
                  <ShieldAlert size={14} style={{ verticalAlign: "middle" }} />{" "}
                  <strong>Live Red-Team Attack Lab</strong> (Inject adversarial leaks into staging buffer):
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
              Shannon entropy), guarded Gate 2 (Gemini Nano on-device), and Gate 3 (6-vector firewall).
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

          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 360, overflowY: "auto" }}>
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
            <h2 style={{ marginBottom: 8 }}>Firestore Zero-PII Audit Ledger</h2>
            {ledger.length === 0 ? (
              <div className="muted">
                Append-only SHA-256 receipts sync here after your first Cloud Audit (raw PII is rejected by
                server-side Firestore Security Rules).
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {ledger.map((item) => (
                  <div key={item.receiptSha256} className="wire-item">
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <strong>{item.policyProfile} · {item.riskLevel}</strong>
                      <span className="mono muted">{item.receiptSha256.slice(0, 14)}…</span>
                    </div>
                    <div className="muted">{item.sanitizedSummary}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
