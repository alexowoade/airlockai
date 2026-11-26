import { useEffect, useState } from "react";
import { Download, Fingerprint, ShieldCheck, Trash2, Upload } from "lucide-react";
import type { AirlockVault, PolicyProfile } from "@airlock/core";
import { wireTap } from "../services/wireTap.js";
import { triggerLocalDownload } from "../utils/chainVerifier.js";
import {
  clearEnrolledPasskeyMeta,
  enrollWebAuthnPrfPasskey,
  loadEnrolledPasskeyMeta,
  probeWebAuthnPrfCapabilities,
  runPrfVaultCryptoSelfTest,
  sealVaultWithHardwarePasskey,
  unsealVaultWithHardwarePasskey,
  type EnrolledPasskeyMeta,
  type PasskeyDecryptedVaultBundle,
  type PrfCryptoSelfTestReport,
  type WebAuthnPrfCapabilities,
} from "../utils/webauthnPrfVault.js";
import { ZeroKnowledgeText } from "./ZeroKnowledgeText.js";

interface Props {
  readonly policyProfile: PolicyProfile;
  readonly receiptSha256: string | null;
  readonly vault: AirlockVault | null;
  readonly sanitizedText: string | null;
  readonly sanitizedAuditMarkdown: string | null;
  readonly zkViewMode: Parameters<typeof ZeroKnowledgeText>[0]["viewMode"];
}

export function PasskeyVaultPanel({
  policyProfile,
  receiptSha256,
  vault,
  sanitizedText,
  sanitizedAuditMarkdown,
  zkViewMode,
}: Props) {
  const [caps, setCaps] = useState<WebAuthnPrfCapabilities | null>(null);
  const [passkey, setPasskey] = useState<EnrolledPasskeyMeta | null>(() => loadEnrolledPasskeyMeta());
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [selfTest, setSelfTest] = useState<PrfCryptoSelfTestReport | null>(null);
  const [restored, setRestored] = useState<PasskeyDecryptedVaultBundle | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void probeWebAuthnPrfCapabilities().then(setCaps);
  }, []);

  async function handleEnrollPasskey() {
    setBusy(true);
    setStatus(null);
    const t0 = performance.now();
    try {
      const meta = await enrollWebAuthnPrfPasskey();
      setPasskey(meta);
      const ms = Math.max(1, Math.round(performance.now() - t0));
      const text = `Enrolled WebAuthn Passkey (${meta.credentialIdBase64Url.slice(0, 14)}… · rpId=${meta.rpId} · prfConfirmed=${meta.prfConfirmed} · ${ms}ms · 0B PII sent).`;
      setStatus({ ok: true, text });
      wireTap.record({
        stage: "WEBAUTHN_PRF",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: ms,
        bytesSent: 0,
        payloadPreview: text,
      });
    } catch (err) {
      const text = err instanceof Error ? err.message : "Passkey enrollment failed.";
      setStatus({ ok: false, text });
    } finally {
      setBusy(false);
    }
  }

  async function handleSealWithHardwarePasskey() {
    if (!passkey || !vault || !receiptSha256 || !sanitizedText) return;
    setBusy(true);
    setStatus(null);
    const t0 = performance.now();
    try {
      const { json, envelope } = await sealVaultWithHardwarePasskey({
        passkey,
        policyProfile,
        receiptSha256,
        entries: vault.getEntries(false),
        sanitizedText,
        sanitizedAuditMarkdown,
      });
      const stamp = new Date().toISOString().slice(0, 10);
      const fname = `airlock-passkey-vault-${stamp}.airlock.enc`;
      triggerLocalDownload(fname, json, "application/json;charset=utf-8");
      const ms = Math.max(1, Math.round(performance.now() - t0));
      const text = `HARDWARE PASSKEY SEALED ${fname} — ${envelope.entryCount} tokens encrypted via WebAuthn PRF -> HKDF-SHA256 -> AES-256-GCM (AAD-bound · ${ms}ms · 0B sent).`;
      setStatus({ ok: true, text });
      wireTap.record({
        stage: "WEBAUTHN_PRF",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: ms,
        bytesSent: 0,
        payloadPreview: text,
      });
    } catch (err) {
      setStatus({ ok: false, text: err instanceof Error ? err.message : "Hardware PRF sealing failed." });
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlockPasskeyFile(file: File) {
    setBusy(true);
    setStatus(null);
    const t0 = performance.now();
    try {
      const textContent = await file.text();
      const bundle = await unsealVaultWithHardwarePasskey(textContent);
      setRestored(bundle);
      const ms = Math.max(1, Math.round(performance.now() - t0));
      const text = `HARDWARE PASSKEY UNSEALED ${file.name} — ${bundle.entries.length} tokens restored locally via WebAuthn PRF -> HKDF-SHA256 -> AES-256-GCM (${ms}ms · 0B sent).`;
      setStatus({ ok: true, text });
      wireTap.record({
        stage: "WEBAUTHN_PRF",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: ms,
        bytesSent: 0,
        payloadPreview: text,
      });
    } catch (err) {
      setRestored(null);
      setStatus({ ok: false, text: err instanceof Error ? err.message : "Passkey unseal failed." });
    } finally {
      setBusy(false);
    }
  }

  async function handleRunSelfTest() {
    setBusy(true);
    setStatus(null);
    try {
      const entries = vault ? vault.getEntries(false) : [];
      const effectiveEntries =
        entries.length > 0
          ? entries
          : [
              {
                token: "[ORG_1]",
                original: "Helios Robotics Corp",
                category: "ORG" as const,
                detectedBy: "GATE1_REGEX" as const,
              },
              {
                token: "[SSN_1]",
                original: "912-45-6789",
                category: "SSN" as const,
                detectedBy: "GATE1_REGEX" as const,
              },
            ];
      const report = await runPrfVaultCryptoSelfTest({
        policyProfile,
        receiptSha256:
          receiptSha256 ?? "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        entries: effectiveEntries,
        sanitizedText: sanitizedText ?? "Agreement for [ORG_1] signer SSN [SSN_1].",
        sanitizedAuditMarkdown,
      });
      setSelfTest(report);
      setStatus({ ok: report.ok, text: report.detail });
      wireTap.record({
        stage: "WEBAUTHN_PRF",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: report.latencyMs,
        bytesSent: 0,
        payloadPreview: `PRF CRYPTO SELF-TEST — ${report.detail}`,
      });
    } finally {
      setBusy(false);
    }
  }

  const hasLiveVault = Boolean(vault && receiptSha256 && sanitizedText);

  return (
    <div
      className="wire-item"
      style={{
        gap: 8,
        marginTop: 10,
        marginBottom: 10,
        borderColor: "rgba(16, 185, 129, 0.45)",
      }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
        <strong style={{ fontSize: "0.84rem" }}>
          <Fingerprint size={14} style={{ verticalAlign: "middle", marginRight: 5 }} />
          Hardware Passkey Vault Sealing (WebAuthn PRF -&gt; HKDF-SHA256 -&gt; AES-256-GCM)
        </strong>
        {caps && (
          <span
            className={caps.platformAuthenticatorAvailable ? "badge green" : "badge blue"}
            style={{ fontSize: "0.66rem" }}
          >
            {caps.platformAuthenticatorAvailable
              ? `Platform Biometric Ready${caps.prfExtensionReported ? " · PRF Supported" : ""}`
              : caps.webAuthnSupported
                ? "WebAuthn Ready (Roaming / Self-Test)"
                : "WebCrypto HKDF Self-Test Mode"}
          </span>
        )}
      </div>

      <div className="mono muted" style={{ fontSize: "0.7rem" }}>
        {passkey ? (
          <span>
            Enrolled Passkey: <strong>{passkey.credentialIdBase64Url.slice(0, 16)}…</strong> (rpId:{" "}
            {passkey.rpId} · PRF confirmed: {String(passkey.prfConfirmed)})
          </span>
        ) : (
          <span>
            No hardware passkey enrolled yet. Enroll Touch ID / Windows Hello / YubiKey, or run the 1-click PRF -&gt; HKDF -&gt; AES-GCM cryptographic self-test below.
          </span>
        )}
      </div>

      <div className="row" style={{ gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <button
          type="button"
          className="primary"
          disabled={busy || !caps?.webAuthnSupported}
          onClick={() => void handleEnrollPasskey()}
          style={{ padding: "4px 9px", fontSize: "0.72rem" }}
        >
          <Fingerprint size={12} /> {passkey ? "Re-Enroll Passkey (PRF)" : "Enroll Hardware Passkey (PRF)"}
        </button>

        {passkey && (
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              clearEnrolledPasskeyMeta();
              setPasskey(null);
              setStatus({ ok: true, text: "Cleared local passkey metadata (0B transmitted)." });
            }}
            style={{ padding: "4px 7px", fontSize: "0.71rem" }}
            title="Forget local passkey credential ID"
          >
            <Trash2 size={11} />
          </button>
        )}

        <button
          type="button"
          className="cloud"
          disabled={busy || !passkey || !hasLiveVault}
          onClick={() => void handleSealWithHardwarePasskey()}
          style={{ padding: "4px 9px", fontSize: "0.72rem" }}
          title={!hasLiveVault ? "Run Local Airlock first to mint a live vault" : "Seal live vault with WebAuthn PRF"}
        >
          <Download size={12} /> Seal Passkey .airlock.enc
        </button>

        <label
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 5,
            padding: "4px 9px",
            fontSize: "0.72rem",
            border: "1px solid var(--border)",
            borderRadius: 8,
            cursor: "pointer",
            background: "rgba(30, 41, 59, 0.7)",
          }}
        >
          <Upload size={12} />
          Unlock Passkey .airlock.enc
          <input
            type="file"
            accept=".enc,.json"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleUnlockPasskeyFile(f);
              e.target.value = "";
            }}
          />
        </label>

        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => void handleRunSelfTest()}
          style={{ padding: "4px 9px", fontSize: "0.72rem" }}
        >
          <ShieldCheck size={12} /> Verify PRF -&gt; HKDF -&gt; AES-GCM (Round-Trip + Tamper Proof)
        </button>
      </div>

      {selfTest && (
        <div className="row mono" style={{ gap: 6, flexWrap: "wrap", fontSize: "0.68rem" }}>
          <span className={selfTest.roundTripVerified ? "badge green" : "badge red"}>
            Round-Trip: {selfTest.roundTripVerified ? "PASS" : "FAIL"}
          </span>
          <span className={selfTest.zeroRawPiiInCiphertext ? "badge green" : "badge red"}>
            0 Raw PII in Ciphertext: {selfTest.zeroRawPiiInCiphertext ? "PASS" : "FAIL"}
          </span>
          <span className={selfTest.wrongPrfRejected ? "badge green" : "badge red"}>
            Wrong PRF Rejected: {selfTest.wrongPrfRejected ? "PASS" : "FAIL"}
          </span>
          <span className={selfTest.ciphertextTamperRejected ? "badge green" : "badge red"}>
            1-Bit CT Tamper Rejected: {selfTest.ciphertextTamperRejected ? "PASS" : "FAIL"}
          </span>
          <span className={selfTest.aadTamperRejected ? "badge green" : "badge red"}>
            AAD Header Tamper Rejected: {selfTest.aadTamperRejected ? "PASS" : "FAIL"}
          </span>
        </div>
      )}

      {status && (
        <div
          className={status.ok ? "alert-green" : "alert-red"}
          style={{ fontSize: "0.73rem", wordBreak: "break-word" }}
        >
          {status.text}
        </div>
      )}

      {restored && (
        <div className="codebox" style={{ maxHeight: 160, whiteSpace: "pre-wrap", fontSize: "0.73rem" }}>
          <ZeroKnowledgeText
            sanitizedText={restored.sanitizedAuditMarkdown ?? restored.sanitizedText}
            entries={restored.entries}
            viewMode={zkViewMode}
          />
        </div>
      )}
    </div>
  );
}
