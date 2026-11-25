import { useEffect, useMemo, useState } from "react";
import { Download, KeyRound, ShieldAlert, ShieldCheck } from "lucide-react";
import type { LedgerRecord } from "../services/firebase.js";
import { wireTap } from "../services/wireTap.js";
import {
  buildMerkleTree,
  generateMerkleInclusionProof,
  type MerkleTreeSnapshot,
} from "../utils/merkleTree.js";
import { getDeviceKeySummary, type DeviceKeySummary } from "../utils/deviceSigner.js";
import {
  buildSignedMerkleSelectiveProof,
  triggerLocalDownload,
  verifyExternalProofJson,
} from "../utils/chainVerifier.js";

interface Props {
  readonly recordsNewestFirst: ReadonlyArray<LedgerRecord>;
  readonly projectId: string;
}

export function MerkleSignerPanel({ recordsNewestFirst, projectId }: Props) {
  const [tree, setTree] = useState<MerkleTreeSnapshot | null>(null);
  const [deviceKey, setDeviceKey] = useState<DeviceKeySummary | null>(null);
  const [selectedLeafIdx, setSelectedLeafIdx] = useState<number>(0);
  const [statusMsg, setStatusMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const chronological = useMemo(() => [...recordsNewestFirst].reverse(), [recordsNewestFirst]);

  useEffect(() => {
    let active = true;
    void getDeviceKeySummary().then((summary) => {
      if (active) setDeviceKey(summary);
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    const hashes = chronological.map((r) => r.receiptSha256);
    void buildMerkleTree(hashes).then((snap) => {
      if (!active) return;
      setTree(snap);
      if (snap.leafCount > 0) {
        setSelectedLeafIdx(snap.leafCount - 1);
      } else {
        setSelectedLeafIdx(0);
      }
    });
    return () => {
      active = false;
    };
  }, [chronological]);

  const activeIndex = Math.min(Math.max(0, selectedLeafIdx), Math.max(0, chronological.length - 1));

  async function handleExportSignedSelectiveProof() {
    if (!tree || chronological.length === 0) return;
    setBusy(true);
    const t0 = performance.now();
    try {
      const record = chronological[activeIndex]!;
      const merkleProof = generateMerkleInclusionProof(tree, activeIndex);
      if (!merkleProof) return;

      const signedBundle = await buildSignedMerkleSelectiveProof({
        projectId,
        record,
        merkleProof,
      });
      const json = JSON.stringify(signedBundle, null, 2);
      const filename = `airlock-merkle-selective-leaf${activeIndex + 1}-of-${tree.leafCount}.json`;
      triggerLocalDownload(filename, json, "application/json;charset=utf-8");

      const ms = Math.max(1, Math.round(performance.now() - t0));
      const msg = `Exported ${filename} — 1 disclosed receipt (${tree.leafCount - 1} siblings hidden), O(log N) path (${merkleProof.proofPath.length} hash(es)), ECDSA P-256 signed (${signedBundle.deviceSignature.kid} · ${ms}ms). Drop it into the Offline Auditor below.`;
      setStatusMsg({ ok: true, text: msg });
      wireTap.record({
        stage: "MERKLE_ECDSA",
        inferenceSource: "DETERMINISTIC_LOCAL",
        latencyMs: ms,
        bytesSent: 0,
        payloadPreview: msg,
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleSelfVerify(tamperMode: boolean) {
    if (!tree || chronological.length === 0) return;
    setBusy(true);
    const t0 = performance.now();
    try {
      const record = chronological[activeIndex]!;
      const merkleProof = generateMerkleInclusionProof(tree, activeIndex);
      if (!merkleProof) return;

      const signedBundle = await buildSignedMerkleSelectiveProof({
        projectId,
        record,
        merkleProof,
      });

      const payloadToAudit = tamperMode
        ? {
            ...signedBundle,
            disclosedReceipt: {
              ...signedBundle.disclosedReceipt,
              riskLevel:
                signedBundle.disclosedReceipt.riskLevel === "LOW" ? "CRITICAL" : "LOW",
            },
          }
        : signedBundle;

      const report = await verifyExternalProofJson(
        tamperMode ? "tampered-selective-proof.json" : "self-verified-selective-proof.json",
        JSON.stringify(payloadToAudit)
      );
      const ms = Math.max(1, Math.round(performance.now() - t0));
      setStatusMsg({
        ok: tamperMode ? !report.ok : report.ok,
        text: tamperMode
          ? `1-BIT TAMPER TEST PASSED (REJECTED AS EXPECTED · ${ms}ms): ${report.verdict}`
          : `${report.verdict} (${ms}ms)`,
      });
      wireTap.record({
        stage: "MERKLE_ECDSA",
        inferenceSource: tamperMode ? "BLOCKED" : "DETERMINISTIC_LOCAL",
        latencyMs: ms,
        bytesSent: 0,
        payloadPreview: tamperMode
          ? `1-BIT TAMPER TEST REJECTED — ${report.verdict}`
          : `SELF-VERIFIED MERKLE + ECDSA — ${report.verdict}`,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="wire-item"
      style={{
        gap: 8,
        marginBottom: 10,
        borderColor: "rgba(56, 189, 248, 0.45)",
      }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <strong style={{ fontSize: "0.84rem" }}>
          <KeyRound size={14} style={{ verticalAlign: "middle", marginRight: 5 }} />
          SHA-256 Merkle Audit Tree & Non-Extractable ECDSA P-256 Signer
        </strong>
        {deviceKey && (
          <span className="badge green" style={{ fontSize: "0.66rem" }}>
            {deviceKey.storage === "INDEXEDDB_NON_EXTRACTABLE"
              ? "IndexedDB Key · extractable=false"
              : "RAM Key · extractable=false"}
          </span>
        )}
      </div>

      <div className="mono muted" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
        <div>
          <strong>Merkle Root:</strong>{" "}
          {tree?.root ? `${tree.root}` : "(Mint at least 1 receipt to compute Merkle Root)"}
        </div>
        <div>
          <strong>Tree Stats:</strong> {tree?.leafCount ?? 0} leaves · Depth{" "}
          {tree?.depth ?? 0} (O(log N) proof steps) ·{" "}
          <strong>Device Key ID:</strong> {deviceKey?.kid ?? "initializing…"}
        </div>
      </div>

      <div className="row" style={{ gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {chronological.length > 0 && (
          <select
            aria-label="Select ledger leaf for selective disclosure proof"
            value={activeIndex}
            onChange={(e) => setSelectedLeafIdx(Number(e.target.value))}
            style={{
              background: "#060a12",
              color: "#e2e8f0",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "4px 7px",
              fontSize: "0.71rem",
            }}
          >
            {chronological.map((r, i) => (
              <option key={r.docId + i} value={i}>
                Leaf #{i + 1} ({r.policyProfile} · {r.receiptSha256.slice(0, 10)}…)
              </option>
            ))}
          </select>
        )}

        <button
          type="button"
          className="cloud"
          disabled={busy || !tree?.root}
          onClick={() => void handleExportSignedSelectiveProof()}
          style={{ padding: "4px 9px", fontSize: "0.72rem" }}
        >
          <Download size={12} /> Export Signed Merkle Selective Proof (.json)
        </button>

        <button
          type="button"
          className="primary"
          disabled={busy || !tree?.root}
          onClick={() => void handleSelfVerify(false)}
          style={{ padding: "4px 9px", fontSize: "0.72rem" }}
        >
          <ShieldCheck size={12} /> Verify Merkle + ECDSA
        </button>

        <button
          type="button"
          className="danger"
          disabled={busy || !tree?.root}
          onClick={() => void handleSelfVerify(true)}
          style={{ padding: "4px 9px", fontSize: "0.72rem" }}
        >
          <ShieldAlert size={12} /> 1-Bit Signature Tamper Test
        </button>
      </div>

      {statusMsg && (
        <div
          className={statusMsg.ok ? "alert-green" : "alert-red"}
          style={{ fontSize: "0.73rem", wordBreak: "break-word" }}
        >
          {statusMsg.text}
        </div>
      )}
    </div>
  );
}
