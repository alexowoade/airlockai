import { useEffect, useState } from "react";
import { Cpu, Gauge, Radio } from "lucide-react";
import { wireTap } from "../services/wireTap.js";
import {
  evaluateAdaptiveRoute,
  sampleHardwareNetworkTelemetry,
  type AdaptiveRoutingVerdict,
  type HardwareNetworkSnapshot,
  type SensorSimulationPreset,
} from "../utils/adaptiveRouter.js";

interface Props {
  readonly effectiveOnline: boolean;
  readonly airGapActive: boolean;
  readonly nanoAvailable: boolean;
  readonly payloadBytes: number;
  readonly onApplyRecommendedDepth?: (depth: "LOW" | "MEDIUM" | "HIGH") => void;
}

export function AdaptiveRouterPanel({
  effectiveOnline,
  airGapActive,
  nanoAvailable,
  payloadBytes,
  onApplyRecommendedDepth,
}: Props) {
  const [preset, setPreset] = useState<SensorSimulationPreset>("LIVE");
  const [snapshot, setSnapshot] = useState<HardwareNetworkSnapshot | null>(null);
  const [verdict, setVerdict] = useState<AdaptiveRoutingVerdict | null>(null);

  useEffect(() => {
    let active = true;
    void sampleHardwareNetworkTelemetry({
      effectiveOnline,
      airGapActive,
      nanoAvailable,
      payloadBytes,
      preset,
    }).then((snap) => {
      if (!active) return;
      const v = evaluateAdaptiveRoute(snap);
      setSnapshot(snap);
      setVerdict(v);
    });
    return () => {
      active = false;
    };
  }, [effectiveOnline, airGapActive, nanoAvailable, payloadBytes, preset]);

  function handleSelectPreset(next: SensorSimulationPreset) {
    setPreset(next);
    void sampleHardwareNetworkTelemetry({
      effectiveOnline,
      airGapActive,
      nanoAvailable,
      payloadBytes,
      preset: next,
    }).then((snap) => {
      const v = evaluateAdaptiveRoute(snap);
      setSnapshot(snap);
      setVerdict(v);
      wireTap.record({
        stage: "ADAPTIVE_ROUTING",
        inferenceSource:
          v.decision === "HYBRID_LOCAL_AIRLOCK_CLOUD_THINKING" ? "IN_CLOUD" : "DETERMINISTIC_LOCAL",
        latencyMs: 1,
        bytesSent: 0,
        payloadPreview: `ADAPTIVE ROUTER [${next}] -> ${v.decision} (Score ${v.cloudReadinessScore}/100, RTT ${snap.rttMs}ms, Battery ${snap.batteryPct ?? "AC"}%, Recommended Thinking: ${v.recommendedThinkingDepth})`,
      });
    });
  }

  return (
    <div
      className="wire-item"
      style={{ gap: 8, marginBottom: 10, borderColor: "rgba(56, 189, 248, 0.45)" }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
        <strong style={{ fontSize: "0.84rem" }}>
          <Gauge size={14} style={{ verticalAlign: "middle", marginRight: 5 }} />
          Real-Time Hardware & Network Adaptive Routing Engine
        </strong>
        {verdict && (
          <span
            className={
              verdict.decision === "HYBRID_LOCAL_AIRLOCK_CLOUD_THINKING"
                ? "badge green"
                : verdict.decision === "PREFER_ON_DEVICE_CONSTRAINED"
                  ? "badge amber"
                  : "badge red"
            }
            style={{ fontSize: "0.68rem" }}
          >
            {verdict.decision} · Score {verdict.cloudReadinessScore}/100
          </span>
        )}
      </div>

      <div className="row" style={{ gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <span className="muted" style={{ fontSize: "0.71rem" }}>Telemetry Mode:</span>
        {(
          [
            { id: "LIVE", label: "Live Hardware Sensors" },
            { id: "CONSTRAINED_3G", label: "Simulate 3G (650ms RTT)" },
            { id: "LOW_BATTERY", label: "Simulate Low Battery (12%)" },
          ] as const
        ).map((opt) => (
          <button
            key={opt.id}
            type="button"
            onClick={() => handleSelectPreset(opt.id)}
            style={{
              padding: "3px 8px",
              fontSize: "0.7rem",
              borderColor: preset === opt.id ? "#38bdf8" : undefined,
              color: preset === opt.id ? "#38bdf8" : undefined,
            }}
          >
            {opt.label}
          </button>
        ))}

        {verdict && onApplyRecommendedDepth && (
          <button
            type="button"
            className="primary"
            onClick={() => onApplyRecommendedDepth(verdict.recommendedThinkingDepth)}
            style={{ padding: "3px 8px", fontSize: "0.7rem" }}
          >
            Apply Recommended Depth ({verdict.recommendedThinkingDepth})
          </button>
        )}
      </div>

      {snapshot && verdict && (
        <>
          <div className="row mono muted" style={{ gap: 10, flexWrap: "wrap", fontSize: "0.7rem" }}>
            <span>
              <Radio size={11} style={{ verticalAlign: "middle", marginRight: 3 }} />
              Net: <strong>{snapshot.effectiveType.toUpperCase()}</strong> ({snapshot.rttMs}ms RTT · {snapshot.downlinkMbps} Mbps{snapshot.saveData ? " · Save-Data" : ""})
            </span>
            <span>
              <Cpu size={11} style={{ verticalAlign: "middle", marginRight: 3 }} />
              Compute: <strong>{snapshot.cpuCores} cores</strong>
              {snapshot.deviceMemoryGb ? ` · ${snapshot.deviceMemoryGb}GB RAM` : ""}
            </span>
            <span>
              Battery: <strong>{snapshot.batteryPct !== null ? `${snapshot.batteryPct}%${snapshot.batteryCharging ? " (AC)" : " (DC)"}` : "Desktop/AC"}</strong>
            </span>
            <span>
              Payload: <strong>{snapshot.payloadBytes}B (~{snapshot.estimatedTokens} tok)</strong>
            </span>
          </div>
          <div style={{ fontSize: "0.72rem", color: "#cbd5e1" }}>
            {verdict.rationale.map((r, i) => (
              <div key={i}>• {r}</div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
