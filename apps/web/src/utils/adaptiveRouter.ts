export type AdaptiveRouteDecision =
  | "FORCE_ON_DEVICE_AIRGAP"
  | "PREFER_ON_DEVICE_CONSTRAINED"
  | "HYBRID_LOCAL_AIRLOCK_CLOUD_THINKING";

export type SensorSimulationPreset = "LIVE" | "CONSTRAINED_3G" | "LOW_BATTERY";

export interface HardwareNetworkSnapshot {
  readonly online: boolean;
  readonly airGapActive: boolean;
  readonly effectiveType: string;
  readonly rttMs: number;
  readonly downlinkMbps: number;
  readonly saveData: boolean;
  readonly batteryPct: number | null;
  readonly batteryCharging: boolean | null;
  readonly cpuCores: number;
  readonly deviceMemoryGb: number | null;
  readonly nanoAvailable: boolean;
  readonly payloadBytes: number;
  readonly estimatedTokens: number;
  readonly simulatedPreset: SensorSimulationPreset;
}

export interface AdaptiveRoutingVerdict {
  readonly decision: AdaptiveRouteDecision;
  readonly cloudReadinessScore: number; // 0..100
  readonly recommendedThinkingDepth: "LOW" | "MEDIUM" | "HIGH";
  readonly rationale: ReadonlyArray<string>;
}

interface NetworkInformationLike {
  readonly effectiveType?: string;
  readonly rtt?: number;
  readonly downlink?: number;
  readonly saveData?: boolean;
}

interface BatteryManagerLike {
  readonly level: number;
  readonly charging: boolean;
}

interface ExtendedNavigator extends Navigator {
  readonly connection?: NetworkInformationLike;
  readonly deviceMemory?: number;
  readonly getBattery?: () => Promise<BatteryManagerLike>;
}

export async function sampleHardwareNetworkTelemetry(params: {
  effectiveOnline: boolean;
  airGapActive: boolean;
  nanoAvailable: boolean;
  payloadBytes: number;
  preset: SensorSimulationPreset;
}): Promise<HardwareNetworkSnapshot> {
  const nav = (typeof navigator !== "undefined" ? navigator : {}) as ExtendedNavigator;
  const conn = nav.connection;

  let effectiveType = conn?.effectiveType ?? "4g";
  let rttMs = typeof conn?.rtt === "number" && conn.rtt > 0 ? Math.round(conn.rtt) : 45;
  let downlinkMbps = typeof conn?.downlink === "number" && conn.downlink > 0 ? Number(conn.downlink.toFixed(1)) : 10;
  let saveData = Boolean(conn?.saveData);
  let batteryPct: number | null = null;
  let batteryCharging: boolean | null = null;

  if (typeof nav.getBattery === "function") {
    try {
      const bat = await nav.getBattery();
      batteryPct = Math.round(bat.level * 100);
      batteryCharging = Boolean(bat.charging);
    } catch {
      batteryPct = null;
      batteryCharging = null;
    }
  }

  const cpuCores = typeof nav.hardwareConcurrency === "number" ? nav.hardwareConcurrency : 4;
  const deviceMemoryGb = typeof nav.deviceMemory === "number" ? nav.deviceMemory : null;

  if (params.preset === "CONSTRAINED_3G") {
    effectiveType = "3g";
    rttMs = 650;
    downlinkMbps = 0.7;
    saveData = true;
  } else if (params.preset === "LOW_BATTERY") {
    batteryPct = 12;
    batteryCharging = false;
  }

  return {
    online: params.effectiveOnline,
    airGapActive: params.airGapActive,
    effectiveType,
    rttMs,
    downlinkMbps,
    saveData,
    batteryPct,
    batteryCharging,
    cpuCores,
    deviceMemoryGb,
    nanoAvailable: params.nanoAvailable,
    payloadBytes: params.payloadBytes,
    estimatedTokens: Math.max(1, Math.ceil(params.payloadBytes / 4)),
    simulatedPreset: params.preset,
  };
}

/**
 * Deterministic Hybrid Routing Policy Engine based on Google's Hybrid Inference Architecture:
 * evaluates live network RTT/bandwidth, battery health, CPU/RAM budget, and payload complexity.
 */
export function evaluateAdaptiveRoute(snap: HardwareNetworkSnapshot): AdaptiveRoutingVerdict {
  const rationale: string[] = [];

  if (!snap.online || snap.airGapActive) {
    rationale.push(
      snap.airGapActive
        ? "Air-Gap kill switch active — outbound cloud network hard-blocked (0B)."
        : "Browser reports offline — routing 100% to local deterministic gates + offline queue."
    );
    return {
      decision: "FORCE_ON_DEVICE_AIRGAP",
      cloudReadinessScore: 0,
      recommendedThinkingDepth: "LOW",
      rationale,
    };
  }

  let score = 100;

  if (snap.rttMs >= 350) {
    score -= 45;
    rationale.push(`High network RTT (${snap.rttMs}ms on ${snap.effectiveType}) favors local triage to cut latency.`);
  } else if (snap.rttMs >= 150) {
    score -= 15;
    rationale.push(`Moderate network RTT (${snap.rttMs}ms) — streaming FSM recommended.`);
  } else {
    rationale.push(`Low network RTT (${snap.rttMs}ms, ${snap.downlinkMbps} Mbps ${snap.effectiveType}) supports fast cloud streaming.`);
  }

  if (snap.saveData) {
    score -= 25;
    rationale.push("Data-Saver signal enabled — minimize cloud round-trips.");
  }

  if (snap.batteryPct !== null && snap.batteryPct <= 20 && snap.batteryCharging === false) {
    score -= 40;
    rationale.push(`Low unplugged battery (${snap.batteryPct}%) — throttle heavy reasoning & prefer lightweight local gates.`);
  } else if (snap.batteryPct !== null) {
    rationale.push(`Power healthy (${snap.batteryPct}%${snap.batteryCharging ? ", charging" : ""}).`);
  }

  if (snap.cpuCores >= 4) {
    rationale.push(`Local compute healthy (${snap.cpuCores} CPU threads${snap.deviceMemoryGb ? `, ${snap.deviceMemoryGb}GB RAM` : ""}) — Gate 1/3 <5ms.`);
  }

  if (snap.estimatedTokens > 1200) {
    rationale.push(`Complex payload (~${snap.estimatedTokens} tokens) benefits from HIGH cloud thinking depth after local redaction.`);
  }

  const clamped = Math.max(0, Math.min(100, score));
  if (clamped < 60) {
    return {
      decision: "PREFER_ON_DEVICE_CONSTRAINED",
      cloudReadinessScore: clamped,
      recommendedThinkingDepth: "LOW",
      rationale,
    };
  }

  const recommendedThinkingDepth: "LOW" | "MEDIUM" | "HIGH" =
    snap.estimatedTokens > 1200 ? "HIGH" : snap.rttMs > 180 ? "LOW" : "MEDIUM";

  return {
    decision: "HYBRID_LOCAL_AIRLOCK_CLOUD_THINKING",
    cloudReadinessScore: clamped,
    recommendedThinkingDepth,
    rationale,
  };
}
