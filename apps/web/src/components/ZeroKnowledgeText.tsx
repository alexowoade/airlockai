import type { VaultEntry } from "@airlock/core";

export type ZeroKnowledgeViewMode = "diff" | "rehydrated" | "cloud";

interface ZeroKnowledgeTextProps {
  readonly sanitizedText: string;
  readonly entries: ReadonlyArray<VaultEntry>;
  readonly viewMode: ZeroKnowledgeViewMode;
}

const TOKEN_SPLIT_REGEX = /(\[[A-Z_]+_\d+\])/g;

/**
 * Renders sanitized cloud output with three visual modes:
 * - "diff": Inline emerald pills showing locally restored secrets + source token tooltip
 * - "rehydrated": Clean plain text with secrets re-hydrated in browser RAM
 * - "cloud": Exact sanitized skeleton showing blue token chips (what Gemini saw on wire)
 */
export function ZeroKnowledgeText({
  sanitizedText,
  entries,
  viewMode,
}: ZeroKnowledgeTextProps) {
  const tokenMap = new Map<string, VaultEntry>();
  for (const entry of entries) {
    if (entry.category !== "CANARY") {
      tokenMap.set(entry.token, entry);
    }
  }

  const parts = sanitizedText.split(TOKEN_SPLIT_REGEX);

  return (
    <>
      {parts.map((segment, idx) => {
        const match = tokenMap.get(segment);
        if (!match) {
          return <span key={idx}>{segment}</span>;
        }

        if (viewMode === "rehydrated") {
          return <span key={idx}>{match.original}</span>;
        }

        if (viewMode === "cloud") {
          return (
            <span
              key={idx}
              className="zk-chip zk-chip-cloud"
              title={`Redacted ${match.category} token sent to cloud — raw value stayed on-device`}
            >
              {match.token}
            </span>
          );
        }

        return (
          <span
            key={idx}
            className="zk-chip zk-chip-local"
            title={`Restored locally in browser RAM from ${match.token} (${match.category}) — 0 bytes of raw value sent to Gemini`}
          >
            {match.original}
            <span className="zk-chip-tag">{match.token}</span>
          </span>
        );
      })}
    </>
  );
}
