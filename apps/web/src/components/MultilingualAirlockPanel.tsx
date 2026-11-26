import { useEffect, useState } from "react";
import { Globe, Languages, ShieldCheck } from "lucide-react";
import type { AirlockVault, PolicyProfile } from "@airlock/core";
import { wireTap } from "../services/wireTap.js";
import {
  detectLanguageLocally,
  getChromeMultilingualCapabilities,
  MULTILINGUAL_SAMPLES,
  translateSanitizedSkeletonLocally,
  type LanguageDetectionResult,
  type RedactedTranslationResult,
} from "../utils/multilingualAirlock.js";
import { ZeroKnowledgeText } from "./ZeroKnowledgeText.js";

interface Props {
  readonly currentText: string;
  readonly verifiedSanitizedText: string | null;
  readonly vault: AirlockVault | null;
  readonly zkViewMode: Parameters<typeof ZeroKnowledgeText>[0]["viewMode"];
  readonly onLoadMultilingualSample: (text: string, policy: PolicyProfile, label: string) => void;
}

export function MultilingualAirlockPanel({
  currentText,
  verifiedSanitizedText,
  vault,
  zkViewMode,
  onLoadMultilingualSample,
}: Props) {
  const [open, setOpen] = useState(false);
  const [caps, setCaps] = useState({ languageDetector: "checking…", translatorDeEn: "checking…" });
  const [detected, setDetected] = useState<LanguageDetectionResult | null>(null);
  const [translation, setTranslation] = useState<RedactedTranslationResult | null>(null);

  useEffect(() => {
    void getChromeMultilingualCapabilities().then(setCaps);
  }, []);

  useEffect(() => {
    let active = true;
    void detectLanguageLocally(currentText).then((res) => {
      if (active) setDetected(res);
    });
    return () => {
      active = false;
    };
  }, [currentText]);

  useEffect(() => {
    setTranslation(null);
  }, [verifiedSanitizedText]);

  async function handleTranslateSanitized() {
    if (!verifiedSanitizedText || !vault || !detected) return;
    const res = await translateSanitizedSkeletonLocally({
      sanitizedText: verifiedSanitizedText,
      sourceLang: detected.code,
      vault,
    });
    setTranslation(res);

    wireTap.record({
      stage: "MULTILINGUAL_AIRLOCK",
      inferenceSource:
        res.engine === "CHROME_ON_DEVICE_TRANSLATOR" ? "ON_DEVICE" : "DETERMINISTIC_LOCAL",
      latencyMs: res.latencyMs,
      bytesSent: 0,
      payloadPreview: `REDACT-FIRST TRANSLATE-SECOND (${res.sourceLang.toUpperCase()}->EN via ${res.engine}): ${res.tokenCount} tokens preserved=${res.tokensPreserved}, zeroPii=${res.zeroPiiVerified} (0B raw foreign PII sent).`,
    });
  }

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 10,
        padding: "7px 10px",
        background: "rgba(15, 23, 42, 0.55)",
      }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          style={{ padding: "3px 8px", fontSize: "0.73rem" }}
        >
          <Globe size={12} />
          On-Device Multilingual Airlock (DE / FR / ES -&gt; EN)
        </button>
        {detected && (
          <span className="badge blue mono" style={{ fontSize: "0.66rem" }}>
            Detected: {detected.label} ({Math.round(detected.confidence * 100)}%)
          </span>
        )}
      </div>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 9 }}>
          <div className="mono muted" style={{ fontSize: "0.68rem" }}>
            Chrome Built-in AI — LanguageDetector: <strong>{caps.languageDetector}</strong> · Translator (DE-&gt;EN):{" "}
            <strong>{caps.translatorDeEn}</strong> · Active Engine: <strong>{detected?.engine ?? "LOCAL"}</strong>
          </div>

          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            {MULTILINGUAL_SAMPLES.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => onLoadMultilingualSample(s.text, s.policy, s.label)}
                style={{ padding: "4px 8px", fontSize: "0.71rem" }}
              >
                {s.label}
              </button>
            ))}
          </div>

          {verifiedSanitizedText && vault && detected && detected.code !== "en" && (
            <button
              type="button"
              className="cloud"
              onClick={() => void handleTranslateSanitized()}
              style={{ padding: "5px 10px", fontSize: "0.72rem", alignSelf: "flex-start" }}
            >
              <Languages size={12} /> Translate Redacted Skeleton ({detected.code.toUpperCase()} -&gt; EN · 0B PII)
            </button>
          )}

          {translation && vault && (
            <div className="wire-item" style={{ gap: 6, borderColor: "rgba(16, 185, 129, 0.45)" }}>
              <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap" }}>
                <span className="badge green" style={{ fontSize: "0.66rem" }}>
                  <ShieldCheck size={11} /> Redact-First Verified · {translation.tokenCount} Tokens Intact · 0 Raw PII
                </span>
                <span className="mono muted" style={{ fontSize: "0.66rem" }}>
                  {translation.engine} · {translation.latencyMs}ms
                </span>
              </div>
              <div className="codebox" style={{ maxHeight: 170, whiteSpace: "pre-wrap", fontSize: "0.73rem" }}>
                <ZeroKnowledgeText
                  sanitizedText={translation.translatedSanitizedText}
                  entries={vault.getEntries(false)}
                  viewMode={zkViewMode}
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
