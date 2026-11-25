import { useEffect, useState } from "react";
import {
  Cloud,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  KeyRound,
  Lock,
  MousePointerClick,
  Plus,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  injectRedTeamAttack,
  verifyAndMintPayload,
  type PolicyProfile,
  type RedTeamAttackType,
  type VaultEntry,
} from "@airlock/core";
import {
  checkLocalNanoStatus,
  isFirebaseConfigured,
  runExtensionCloudAudit,
  runExtensionLocalAirlock,
  type LocalNanoStatus,
  type SidePanelAirlockResult,
} from "./services/extensionFirebase.js";
import { exportCrossSurfaceEncryptedVault } from "./utils/extensionSecurity.js";
import "./sprintC2.css";

interface PendingSelection {
  text: string;
  sourceUrl: string;
  capturedAt: number;
}

type DiffViewMode = "diff" | "rehydrated" | "cloud";

const TOKEN_SPLIT_RX = /(\[[A-Z_]+_\d+\])/g;
const LIVE_WEB_PWA_URL = "https://airlockai-2026-alex.web.app";

function ExtensionZkText({
  text,
  entries,
  mode,
}: {
  readonly text: string;
  readonly entries: ReadonlyArray<VaultEntry>;
  readonly mode: DiffViewMode;
}) {
  const map = new Map<string, VaultEntry>();
  for (const e of entries) {
    if (e.category !== "CANARY") map.set(e.token, e);
  }
  return (
    <>
      {text.split(TOKEN_SPLIT_RX).map((seg, i) => {
        const hit = map.get(seg);
        if (!hit) return <span key={i}>{seg}</span>;
        if (mode === "rehydrated") return <span key={i}>{hit.original}</span>;
        if (mode === "cloud") {
          return (
            <span key={i} className="sp-zk-cloud" title={`Redacted ${hit.category} sent to cloud`}>
              {hit.token}
            </span>
          );
        }
        return (
          <span
            key={i}
            className="sp-zk-local"
            title={`Restored locally in browser RAM from ${hit.token} — 0B sent to Gemini`}
          >
            {hit.original}
            <span className="sp-zk-tag">{hit.token}</span>
          </span>
        );
      })}
    </>
  );
}

export default function SidePanelApp() {
  const [rawText, setRawText] = useState("");
  const [sourceUrl, setSourceUrl] = useState<string>("Manual input or active tab");
  const [policy, setPolicy] = useState<PolicyProfile>("NDA_STRICT");
  const [strictSafeHarbor, setStrictSafeHarbor] = useState(false);
  const [customSecrets, setCustomSecrets] = useState<string[]>([]);
  const [residualOverride, setResidualOverride] = useState(false);
  const [nanoStatus, setNanoStatus] = useState<LocalNanoStatus>("unavailable");

  const [busy, setBusy] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [airlock, setAirlock] = useState<SidePanelAirlockResult | null>(null);
  const [redTeamAlert, setRedTeamAlert] = useState<string | null>(null);
  const [cloudAudit, setCloudAudit] = useState<{
    sanitizedMarkdown: string;
    rehydratedMarkdown: string;
    usedTemplate: boolean;
    latencyMs: number;
    syncedToLedger: boolean;
  } | null>(null);
  const [viewMode, setViewMode] = useState<DiffViewMode>("diff");
  const [vaultPassphrase, setVaultPassphrase] = useState("");

  useEffect(() => {
    checkLocalNanoStatus().then(setNanoStatus);

    chrome.storage?.session?.get("pendingSelection", (data) => {
      const sel = data.pendingSelection as PendingSelection | undefined;
      if (sel?.text) {
        setRawText(sel.text);
        setSourceUrl(sel.sourceUrl);
      }
    });

    const onChange = (
      changes: Record<string, chrome.storage.StorageChange>,
      area: string
    ) => {
      if (area === "session" && changes.pendingSelection?.newValue) {
        const sel = changes.pendingSelection.newValue as PendingSelection;
        setRawText(sel.text);
        setSourceUrl(sel.sourceUrl);
        setAirlock(null);
        setCloudAudit(null);
        setRedTeamAlert(null);
        setResidualOverride(false);
      }
    };

    chrome.storage?.onChanged?.addListener(onChange);
    return () => chrome.storage?.onChanged?.removeListener(onChange);
  }, []);

  async function handleGrabActiveTab() {
    setErrorMsg(null);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        setErrorMsg("No active browser tab found.");
        return;
      }
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const sel = window.getSelection()?.toString().trim();
          return sel && sel.length > 0 ? sel : document.body.innerText.slice(0, 4000);
        },
      });
      const captured = String(results[0]?.result ?? "").trim();
      if (!captured) {
        setErrorMsg("No selectable text found on this tab.");
        return;
      }
      setRawText(captured);
      setSourceUrl(tab.url ?? "active-tab");
      setAirlock(null);
      setCloudAudit(null);
      setResidualOverride(false);
    } catch {
      setErrorMsg(
        "Cannot read this tab directly (chrome:// pages are protected). Highlight text on any webpage and right-click 'AirlockAI: Scrub & Audit Selection'."
      );
    }
  }

  async function executeScrub(overrideSecrets?: string[], overrideSafeHarbor?: boolean) {
    if (!rawText.trim()) return;
    setBusy("scrub");
    setErrorMsg(null);
    setRedTeamAlert(null);
    setCloudAudit(null);
    setResidualOverride(false);
    try {
      const res = await runExtensionLocalAirlock({
        rawText,
        policy,
        strictSafeHarbor: overrideSafeHarbor ?? strictSafeHarbor,
        customSecrets: overrideSecrets ?? customSecrets,
      });
      setAirlock(res);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Local scrub failed.");
    } finally {
      setBusy(null);
    }
  }

  async function handleAddCustomTerm(term: string) {
    const cleaned = term.trim();
    if (cleaned.length < 3) return;
    if (customSecrets.some((s) => s.toLowerCase() === cleaned.toLowerCase())) return;
    const next = [...customSecrets, cleaned];
    setCustomSecrets(next);
    await executeScrub(next, strictSafeHarbor);
  }

  async function handleToggleSafeHarbor() {
    const next = !strictSafeHarbor;
    setStrictSafeHarbor(next);
    if (airlock) {
      await executeScrub(customSecrets, next);
    }
  }

  async function handleRedTeam(attack: RedTeamAttackType) {
    if (!airlock) return;
    const poisoned = injectRedTeamAttack(airlock.candidateSanitized, airlock.vault, attack);
    const res = await verifyAndMintPayload({
      rawDoc: airlock.rawDoc,
      candidateSanitized: poisoned,
      vault: airlock.vault,
      policyProfile: policy,
    });
    if (!res.ok) {
      setRedTeamAlert(
        `BLOCKED [${attack}] — 0 bytes sent (${res.blockedBytes}B stopped). Vector: ${res.violations[0]?.vector}`
      );
    }
  }

  async function handleCloudAudit() {
    if (!airlock || !airlock.firewallResult.ok) return;
    setBusy("cloud");
    setErrorMsg(null);
    try {
      const out = await runExtensionCloudAudit({
        verified: airlock.firewallResult.payload,
        vault: airlock.vault,
        policy,
      });
      setCloudAudit(out);
      setViewMode("diff");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Cloud audit failed.");
    } finally {
      setBusy(null);
    }
  }

  async function handleExportVault() {
    if (!airlock || !airlock.firewallResult.ok) return;
    setErrorMsg(null);
    try {
      const { json, entryCount } = await exportCrossSurfaceEncryptedVault({
        passphrase: vaultPassphrase,
        policyProfile: policy,
        receiptSha256: airlock.firewallResult.payload.receipt.receiptSha256,
        entries: airlock.vault.getEntries(false),
        sanitizedText: airlock.firewallResult.payload.sanitizedText,
        sanitizedAuditMarkdown: cloudAudit?.sanitizedMarkdown ?? null,
      });
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `airlock-sidepanel-${new Date().toISOString().slice(0, 10)}.airlock.enc`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setStatusMsg(
        `Exported ${entryCount} tokens to .airlock.enc (PBKDF2 + AES-GCM). Open in Web PWA to restore.`
      );
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to export .airlock.enc vault.");
    }
  }

  async function copyText(label: string, text: string) {
    await navigator.clipboard.writeText(text);
    setStatusMsg(`Copied ${label} to clipboard.`);
    setTimeout(() => setStatusMsg(null), 2200);
  }

  const verified = airlock?.firewallResult.ok ? airlock.firewallResult.payload : null;
  const isCloudGated = Boolean(airlock?.residualRisk.failClosedRecommended && !residualOverride);
  const vaultEntries = airlock ? airlock.vault.getEntries(false) : [];

  return (
    <div className="sp-wrap">
      <div className="sp-header">
        <div className="sp-title">
          <ShieldCheck size={18} color="#10b981" />
          <span>AirlockAI Side Panel</span>
        </div>
        <div className="sp-row" style={{ gap: 5 }}>
          <span className={`sp-badge ${nanoStatus === "available" ? "green" : "amber"}`}>
            <Cpu size={11} /> Nano: {nanoStatus}
          </span>
          <span className="sp-badge green" title="SDK #10635 Guard Active">
            <Lock size={10} /> #10635
          </span>
        </div>
      </div>

      {errorMsg && <div className="sp-alert-red">{errorMsg}</div>}
      {statusMsg && <div className="sp-alert-green">{statusMsg}</div>}

      <div className="sp-card">
        <div className="sp-row" style={{ justifyContent: "space-between" }}>
          <button type="button" onClick={handleGrabActiveTab}>
            <MousePointerClick size={13} /> Grab Active Tab
          </button>
          <select
            value={policy}
            onChange={(e) => setPolicy(e.target.value as PolicyProfile)}
            style={{
              background: "#060a12",
              color: "#e2e8f0",
              border: "1px solid #1e293b",
              borderRadius: 6,
              padding: "4px 6px",
              fontSize: 11,
            }}
          >
            <option value="NDA_STRICT">NDA_STRICT</option>
            <option value="MEDICAL_HIPAA">MEDICAL_HIPAA</option>
            <option value="INVOICE_FINANCE">INVOICE_FINANCE</option>
          </select>
        </div>

        <div className="sp-row" style={{ justifyContent: "space-between" }}>
          <button
            type="button"
            onClick={() => void handleToggleSafeHarbor()}
            style={{
              fontSize: 10,
              padding: "3px 7px",
              borderColor: strictSafeHarbor ? "#10b981" : undefined,
              color: strictSafeHarbor ? "#34d399" : undefined,
            }}
          >
            Safe Harbor (URL/IP/ZIP/ID): {strictSafeHarbor ? "ON" : "OFF"}
          </button>
          <a
            href={LIVE_WEB_PWA_URL}
            target="_blank"
            rel="noreferrer"
            className="muted"
            style={{ fontSize: 10, textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 3 }}
          >
            Open Web PWA <ExternalLink size={10} />
          </a>
        </div>

        <div className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          Source: {sourceUrl}
        </div>

        <textarea
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          placeholder="Highlight any email/contract on a webpage & right-click 'AirlockAI: Scrub & Audit Selection', or paste here..."
        />

        <button
          type="button"
          className="primary"
          onClick={() => void executeScrub()}
          disabled={busy !== null || !rawText.trim()}
        >
          <ShieldCheck size={14} />
          {busy === "scrub" ? "Scrubbing Locally..." : "Run 3-Gate Local Airlock (0B Sent)"}
        </button>
      </div>

      {airlock && (
        <div className="sp-card">
          {airlock.firewallResult.ok ? (
            <div className="sp-alert-green">
              <strong>6/6 Firewall Passed</strong> · {airlock.firewallResult.payload.receipt.redactedCount} redacted · SHA-256{" "}
              {airlock.firewallResult.payload.receipt.receiptSha256.slice(0, 14)}…
            </div>
          ) : (
            <div className="sp-alert-red">
              <strong>GATE 3 BLOCKED (0B Sent):</strong>{" "}
              {airlock.firewallResult.violations[0]?.vector} ({airlock.firewallResult.violations[0]?.category})
            </div>
          )}

          {/* Fail-Closed Residual Proper-Noun Guard */}
          <div className="muted" style={{ fontSize: 11 }}>
            Risk: <strong>{airlock.residualRisk.riskLevel}</strong> — {airlock.residualRisk.summary}
          </div>

          {airlock.residualRisk.residualProperNouns.length > 0 && (
            <div className={isCloudGated ? "sp-alert-red" : "sp-alert-green"}>
              <div style={{ marginBottom: 4 }}>
                <strong>{isCloudGated ? "Fail-Closed Guard:" : "Proper Nouns Cleared:"}</strong> Click to redact:
              </div>
              <div className="sp-row">
                {airlock.residualRisk.residualProperNouns.map((word) => (
                  <button
                    type="button"
                    key={word}
                    onClick={() => void handleAddCustomTerm(word)}
                    style={{ fontSize: 10, padding: "2px 6px" }}
                  >
                    <Plus size={10} /> "{word}"
                  </button>
                ))}
                {isCloudGated && (
                  <button
                    type="button"
                    onClick={() => setResidualOverride(true)}
                    style={{ fontSize: 10, padding: "2px 6px" }}
                  >
                    Unlock Cloud
                  </button>
                )}
              </div>
            </div>
          )}

          <div className="sp-box" style={{ whiteSpace: "pre-wrap" }}>
            <ExtensionZkText
              text={verified ? verified.sanitizedText : airlock.candidateSanitized}
              entries={vaultEntries}
              mode="cloud"
            />
          </div>

          <div className="sp-row">
            <button
              type="button"
              disabled={!verified}
              onClick={() => verified && void copyText("sanitized skeleton", verified.sanitizedText)}
            >
              <Copy size={12} /> Copy Skeleton
            </button>
            <button
              type="button"
              className="cloud"
              onClick={handleCloudAudit}
              disabled={busy !== null || !verified || !isFirebaseConfigured || isCloudGated}
            >
              <Cloud size={12} />{" "}
              {busy === "cloud"
                ? "Auditing..."
                : isCloudGated
                  ? "Locked (Review Terms)"
                  : "Cloud Audit"}
            </button>
          </div>

          {/* Cross-Surface .airlock.enc Vault Export (Web PWA Interoperable) */}
          <div className="sp-row" style={{ marginTop: 4 }}>
            <KeyRound size={12} color="#34d399" />
            <input
              type="password"
              className="sp-input"
              value={vaultPassphrase}
              onChange={(e) => setVaultPassphrase(e.target.value)}
              placeholder="Passphrase to export .airlock.enc..."
            />
            <button
              type="button"
              disabled={!verified || vaultPassphrase.trim().length < 6}
              onClick={() => void handleExportVault()}
              style={{ fontSize: 10, padding: "4px 7px" }}
            >
              <Download size={11} /> .airlock.enc
            </button>
          </div>

          <div className="sp-row" style={{ marginTop: 4 }}>
            <span className="muted">
              <ShieldAlert size={11} style={{ verticalAlign: "middle" }} /> Red-Team:
            </span>
            <button type="button" className="danger" onClick={() => handleRedTeam("MISSED_ENTITY_ESCAPE")}>
              Entity
            </button>
            <button type="button" className="danger" onClick={() => handleRedTeam("BASE64_EXFILTRATION")}>
              Base64
            </button>
            <button type="button" className="danger" onClick={() => handleRedTeam("CANARY_PROMPT_INJECTION")}>
              Canary
            </button>
            <button type="button" className="danger" onClick={() => handleRedTeam("ZERO_WIDTH_SMUGGLING")}>
              Zero-Width
            </button>
          </div>

          {redTeamAlert && <div className="sp-alert-red">{redTeamAlert}</div>}
        </div>
      )}

      {cloudAudit && (
        <div className="sp-card">
          <div className="sp-row" style={{ justifyContent: "space-between" }}>
            <strong>
              Audit ({cloudAudit.usedTemplate ? "Template" : "Cloud"}) · {cloudAudit.latencyMs}ms
              {cloudAudit.syncedToLedger ? " · Chain Synced" : ""}
            </strong>
            <div className="sp-row" style={{ gap: 4 }}>
              {(["diff", "rehydrated", "cloud"] as const).map((m) => (
                <button
                  type="button"
                  key={m}
                  onClick={() => setViewMode(m)}
                  style={{
                    fontSize: 10,
                    padding: "2px 6px",
                    borderColor: viewMode === m ? "#10b981" : undefined,
                    color: viewMode === m ? "#34d399" : undefined,
                  }}
                >
                  {m === "diff" ? "ZK Diff" : m === "rehydrated" ? "Clean" : "Cloud"}
                </button>
              ))}
            </div>
          </div>

          <div className="sp-box" style={{ whiteSpace: "pre-wrap" }}>
            <ExtensionZkText
              text={cloudAudit.sanitizedMarkdown}
              entries={vaultEntries}
              mode={viewMode}
            />
          </div>

          <button
            type="button"
            onClick={() => void copyText("re-hydrated redlines", cloudAudit.rehydratedMarkdown)}
          >
            <Copy size={12} /> Copy Re-Hydrated Redlines
          </button>
        </div>
      )}
    </div>
  );
}
