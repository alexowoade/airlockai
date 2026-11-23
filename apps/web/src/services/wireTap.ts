export interface WireEvent {
  readonly id: string;
  readonly timestampIso: string;
  readonly stage:
    | "GATE1_REGEX"
    | "GATE2_NANO_ON_DEVICE"
    | "GATE3_FIREWALL_BLOCK"
    | "OFFLINE_TRIAGE"
    | "CLOUD_TEMPLATE_AUDIT"
    | "HTTP_WIRE_OUTBOUND";
  readonly inferenceSource: "ON_DEVICE" | "IN_CLOUD" | "DETERMINISTIC_LOCAL" | "BLOCKED";
  readonly latencyMs: number;
  readonly bytesSent: number;
  readonly endpoint?: string;
  readonly payloadPreview: string;
}

type Listener = (events: ReadonlyArray<WireEvent>) => void;

class WireTapRecorder {
  private events: WireEvent[] = [];
  private listeners = new Set<Listener>();
  private fetchInstalled = false;

  public installFetchTap(): void {
    if (this.fetchInstalled || typeof window === "undefined") return;
    this.fetchInstalled = true;

    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const isAiCall =
        url.includes("firebasevertexai.googleapis.com") ||
        url.includes("generativelanguage.googleapis.com");

      const started = performance.now();
      let bodyText = "";
      if (isAiCall && typeof init?.body === "string") {
        bodyText = init.body;
      }

      const response = await nativeFetch(input, init);

      if (isAiCall) {
        const bytes = new TextEncoder().encode(bodyText).byteLength;
        this.record({
          stage: "HTTP_WIRE_OUTBOUND",
          inferenceSource: "IN_CLOUD",
          latencyMs: Math.round(performance.now() - started),
          bytesSent: bytes,
          endpoint: new URL(url).pathname,
          payloadPreview: bodyText.slice(0, 1200) || "(empty body)",
        });
      }
      return response;
    };
  }

  public record(event: Omit<WireEvent, "id" | "timestampIso">): void {
    const entry: WireEvent = {
      ...event,
      id: crypto.randomUUID(),
      timestampIso: new Date().toISOString(),
    };
    this.events = [entry, ...this.events].slice(0, 40);
    this.listeners.forEach((fn) => fn(this.events));
  }

  public clear(): void {
    this.events = [];
    this.listeners.forEach((fn) => fn(this.events));
  }

  public subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    listener(this.events);
    return () => this.listeners.delete(listener);
  }
}

export const wireTap = new WireTapRecorder();
