import { useEffect, useState } from "react";
import {
  Cloud,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  MousePointerClick,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  injectRedTeamAttack,
  verifyAndMintPayload,
  type PolicyProfile,
  type RedTeamAttackType,
} from "@airlock/core";
import {
  checkLocalNanoStatus,
  isFirebaseConfigured,
  runExtensionCloudAudit,
  runExtensionLocalAirlock,
  type LocalNanoStatus,
  type SidePanelAirlockResult,
} from "./services/extensionFirebase.js";

interface PendingSelection {
  text: string;
  sourceUrl: string;
  capturedAt: number;
}

export default function SidePanelApp() {
  const [rawText, setRawText] = useState("");
  const [sourceUrl, setSourceUrl] = useState<string>("Manual input or active tab");
  const [policy, setPolicy] = useState<PolicyProfile>("NDA_STRICT");
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
  } | null>(null);
  const [showRehydrated, setShowRehydrated] = useState(true);

  useEffect(() => {
    checkLocalNanoStatus().then(setNanoStatus);

    // Load any selection passed from the right-click context menu
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
    } catch {
      setErrorMsg(
        "Cannot read this tab directly (chrome:// pages are protected). Highlight text on any webpage and right-click 'AirlockAI: Scrub & Audit Selection'."
      );
    }
  }

  async function handleLocalScrub() {
    if (!rawText.trim()) return;
    setBusy("scrub");
    setErrorMsg(null);
    setRedTeamAlert(null);
    setCloudAudit(null);
    try {
      const res = await runExtensionLocalAirlock(rawText, policy);
      setAirlock(res);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Local scrub failed.");
    } finally {
      setBusy(null);
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
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Cloud audit failed.");
    } finally {
      setBusy(null);
    }
  }

  async function copyText(label: string, text: string) {
    await navigator.clipboard.writeText(text);
    setStatusMsg(`Copied ${label} to clipboard.`);
    setTimeout(() => setStatusMsg(null), 2000);
  }

  const verified = airlock?.firewallResult.ok ? airlock.firewallResult.payload : null;

  return (
    <div className="sp-wrap">
      <div className="sp-header">
        <div className="sp-title">
          <ShieldCheck size={18} color="#10b981" />
          <span>AirlockAI Side Panel</span>
        </div>
        <span className={`sp-badge ${nanoStatus === "available" ? "green" : "amber"}`}>
          <Cpu size={12} /> Nano: {nanoStatus}
        </span>
      </div>

      {errorMsg && <div className="sp-alert-red">{errorMsg}</div>}
      {statusMsg && <div className="sp-alert-green">{statusMsg}</div>}

      <div className="sp-card">
        <div className="sp-row" style={{ justifyContent: "space-between" }}>
          <button onClick={handleGrabActiveTab}>
            <MousePointerClick size={13} /> Grab Active Tab Selection
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

        <div className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          Source: {sourceUrl}
        </div>

        <textarea
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          placeholder="Highlight any email/contract on a webpage & right-click 'AirlockAI: Scrub & Audit Selection', or paste here..."
        />

        <button className="primary" onClick={handleLocalScrub} disabled={busy !== null || !rawText.trim()}>
          <ShieldCheck size={14} />
          {busy === "scrub" ? "Scrubbing Locally..." : "Run 3-Gate Local Airlock (0B Sent)"}
        </button>
      </div>

      {verified && (
        <div className="sp-card">
          <div className="sp-alert-green">
            <strong>6/6 Firewall Passed</strong> · {verified.receipt.redactedCount} redacted · SHA-256{" "}
            {verified.receipt.receiptSha256.slice(0, 14)}…
          </div>

          <div className="sp-box">{verified.sanitizedText}</div>

          <div className="sp-row">
            <button onClick={() => copyText("sanitized skeleton", verified.sanitizedText)}>
              <Copy size={13} /> Copy Safe Skeleton
            </button>
            <button
              className="cloud"
              onClick={handleCloudAudit}
              disabled={busy !== null || !isFirebaseConfigured}
            >
              <Cloud size={13} /> {busy === "cloud" ? "Auditing..." : "Cloud Audit"}
            </button>
          </div>

          <div className="sp-row">
            <span className="muted">
              <ShieldAlert size={12} style={{ verticalAlign: "middle" }} /> Red-Team:
            </span>
            <button className="danger" onClick={() => handleRedTeam("BASE64_EXFILTRATION")}>
              Base64 Exfil
            </button>
            <button className="danger" onClick={() => handleRedTeam("CANARY_PROMPT_INJECTION")}>
              Canary Trap
            </button>
          </div>

          {redTeamAlert && <div className="sp-alert-red">{redTeamAlert}</div>}
        </div>
      )}

      {cloudAudit && (
        <div className="sp-card">
          <div className="sp-row" style={{ justifyContent: "space-between" }}>
            <strong>
              Audit ({cloudAudit.usedTemplate ? "Server Template" : "Cloud"}) · {cloudAudit.latencyMs}ms
            </strong>
            <button onClick={() => setShowRehydrated((v) => !v)}>
              {showRehydrated ? <Eye size={12} /> : <EyeOff size={12} />}
              {showRehydrated ? "Re-Hydrated" : "Cloud View"}
            </button>
          </div>

          <div className="sp-box">
            {showRehydrated ? cloudAudit.rehydratedMarkdown : cloudAudit.sanitizedMarkdown}
          </div>

          <button onClick={() => copyText("re-hydrated redlines", cloudAudit.rehydratedMarkdown)}>
            <Copy size={13} /> Copy Re-Hydrated Redlines
          </button>
        </div>
      )}
    </div>
  );
}
