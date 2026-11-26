import { useEffect, useState } from "react";
import { Cpu, Gauge, Radio, RotateCcw } from "lucide-react";
import { wireTap } from "../services/wireTap.js";
import {
  evaluateAdaptiveRoute,
  formatSimulationLabel,
  sampleHardwareNetworkTelemetry,
  type AdaptiveRoutingVerdict,
  type HardwareNetworkSnapshot,
  type SensorSimulationFlags,
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
  const [flags, setFlags] = useState<SensorSimulationFlags>({
    simulate3g: false,
    simulateLowBattery: false,
  });
  const [snapshot, setSnapshot] = useState<HardwareNetworkSnapshot | null>(null);
  const [verdict, setVerdict] = useState<AdaptiveRoutingVerdict | null>(null);

  useEffect(() => {
    let active = true;
    void sampleHardwareNetworkTelemetry({
      effectiveOnline,
      airGapActive,
      nanoAvailable,
      payloadBytes,
      flags,
    }).then((snap) => {
      if (!active) return;
      setSnapshot(snap);
      setVerdict(evaluateAdaptiveRoute(snap));
    });
    return () => {
      active = false;
    };
  }, [effectiveOnline, airGapActive, nanoAvailable, payloadBytes, flags]);

  function applyFlags(next: SensorSimulationFlags) {
    setFlags(next);
    const label = formatSimulationLabel(next);
    void sampleHardwareNetworkTelemetry({
      effectiveOnline,
      airGapActive,
      nanoAvailable,
      payloadBytes,
      flags: next,
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
        payloadPreview: `ADAPTIVE ROUTER [${label}] -> ${v.decision} (Score ${v.cloudReadinessScore}/100, RTT ${snap.rttMs}ms, Battery ${snap.batteryPct ?? "AC"}%, Recommended Thinking: ${v.recommendedThinkingDepth})`,
      });
    });
  }

  const chipStyle = (on: boolean) => ({
    display: "inline-flex",
    alignItems: "center",
    gap: 5,
    padding: "3px 8px",
    fontSize: "0.71rem",
    borderRadius: 7,
    border: `1px solid ${on ? "#f59e0b" : "var(--border)"}`,
    color: on ? "#fbbf24" : "#cbd5e1",
    cursor: "pointer",
  });

  return (
    <div className="wire-item" style={{ gap: 8, marginBottom: 10, borderColor: "rgba(56, 189, 248, 0.45)" }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
        <strong style={{ fontSize: "0.84rem" }}>
          <Gauge size={14} style={{ verticalAlign: "middle", marginRight: 5 }} />
          Real-Time Hardware &amp; Network Adaptive Routing Engine
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

      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <span className="muted" style={{ fontSize: "0.71rem" }}>Stackable Stress Toggles:</span>
        <label style={chipStyle(flags.simulate3g)}>
          <input
            type="checkbox"
            checked={flags.simulate3g}
            onChange={(e) => applyFlags({ ...flags, simulate3g: e.target.checked })}
          />
          Simulate 3G (650ms RTT)
        </label>
        <label style={chipStyle(flags.simulateLowBattery)}>
          <input
            type="checkbox"
            checked={flags.simulateLowBattery}
            onChange={(e) => applyFlags({ ...flags, simulateLowBattery: e.target.checked })}
          />
          Simulate Low Battery (12%)
        </label>
        {(flags.simulate3g || flags.simulateLowBattery) && (
          <button
            type="button"
            onClick={() => applyFlags({ simulate3g: false, simulateLowBattery: false })}
            style={{ padding: "3px 8px", fontSize: "0.7rem" }}
          >
            <RotateCcw size={11} /> Reset Live
          </button>
        )}
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
