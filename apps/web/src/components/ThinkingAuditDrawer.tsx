import { useState } from "react";
import { Brain, ChevronDown, ChevronRight, ShieldCheck } from "lucide-react";
import type { VaultEntry } from "@airlock/core";
import type { ThinkingAuditTrace } from "../utils/thinkingAudit.js";
import { ZeroKnowledgeText } from "./ZeroKnowledgeText.js";

interface Props {
  readonly trace: ThinkingAuditTrace;
  readonly entries: ReadonlyArray<VaultEntry>;
  readonly viewMode: Parameters<typeof ZeroKnowledgeText>[0]["viewMode"];
}

export function ThinkingAuditDrawer({ trace, entries, viewMode }: Props) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="wire-item"
      style={{
        gap: 6,
        borderColor: trace.zeroPiiVerified
          ? "rgba(56, 189, 248, 0.45)"
          : "rgba(239, 68, 68, 0.65)",
      }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          style={{ padding: "3px 8px", fontSize: "0.72rem" }}
        >
          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          <Brain size={13} />
          Zero-Knowledge Thinking Inspector ({trace.requestedDepth})
        </button>

        <div className="row" style={{ gap: 5 }}>
          <span
            className={trace.zeroPiiVerified ? "badge green" : "badge red"}
            style={{ fontSize: "0.66rem" }}
          >
            <ShieldCheck size={11} />
            {trace.zeroPiiVerified
              ? `0 Raw Secrets in Thoughts (${trace.placeholderTokenCount} tokens)`
              : `LEAK ALERT: ${trace.leakedSecretCount} secret(s)`}
          </span>
          <span className="badge blue mono" style={{ fontSize: "0.64rem" }}>
            {trace.thoughtSignature
              ? `sig:${trace.thoughtSignature.slice(0, 10)}…`
              : `sha256:${trace.thoughtDigestSha256.slice(0, 10)}…`}
          </span>
        </div>
      </div>

      {expanded && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 4 }}>
          <div className="mono muted" style={{ fontSize: "0.68rem", wordBreak: "break-all" }}>
            <strong>Thought Integrity Digest (SHA-256):</strong> {trace.thoughtDigestSha256}
            {trace.thoughtSignature && (
              <div>
                <strong>Model Thought Signature:</strong> {trace.thoughtSignature}
              </div>
            )}
          </div>
          {trace.summaryAvailable ? (
            <div className="codebox" style={{ maxHeight: 200, whiteSpace: "pre-wrap", fontSize: "0.74rem" }}>
              <ZeroKnowledgeText
                sanitizedText={trace.thoughtSummary}
                entries={entries}
                viewMode={viewMode}
              />
            </div>
          ) : (
            <div className="muted" style={{ fontSize: "0.73rem" }}>
              ThinkingConfig (depth={trace.requestedDepth}, includeThoughts=true) requested. This model turn returned a concise direct verdict without an expanded thought summary block; SHA-256 digest & 0-PII verification remain attested above.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
