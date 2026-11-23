import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AirlockVault,
  asRawDocument,
  resolveOverlappingSpans,
  scanDeterministicPii,
  sha256Hex,
  verifyAndMintPayload,
  type DetectedSpan,
  type EntityCategory,
  type FirewallVector,
  type PolicyProfile,
} from "./index.js";

interface SpecFile {
  protocolVersion: string;
  sha256SelfCheck: { input: string; expectedHex: string };
  cleanVectors: Array<{
    id: string;
    policyProfile: PolicyProfile;
    rawDoc: string;
    simulatedGate2Spans: Array<{ text: string; category: EntityCategory }>;
    expectedSanitized: string;
    expectedRedactedCount: number;
  }>;
  adversarialVectors: Array<{
    id: string;
    secret: string;
    category: EntityCategory;
    poisonedSuffix: string;
    expectedVector: FirewallVector;
  }>;
}

const currentDir = dirname(fileURLToPath(import.meta.url));
const specPath = resolve(currentDir, "../../../spec/vectors.json");
const spec = JSON.parse(readFileSync(specPath, "utf-8")) as SpecFile;

describe("Cross-Platform Golden Vector Parity (TypeScript)", () => {
  it("matches canonical SHA-256 self-check", async () => {
    const hex = await sha256Hex(spec.sha256SelfCheck.input);
    expect(hex).toBe(spec.sha256SelfCheck.expectedHex);
  });

  for (const vec of spec.cleanVectors) {
    it(`clean vector [${vec.id}] matches canonical redaction and passes 6/6 checks`, async () => {
      const raw = asRawDocument(vec.rawDoc);
      const vault = new AirlockVault("AIRLOCK-CANARY-FIXED001");
      const gate1 = scanDeterministicPii(raw);
      const gate2: DetectedSpan[] = vec.simulatedGate2Spans.map((s) => {
        const start = raw.indexOf(s.text);
        expect(start).toBeGreaterThanOrEqual(0);
        return {
          start,
          end: start + s.text.length,
          text: s.text,
          category: s.category,
          detectedBy: "GATE2_NANO_ON_DEVICE",
        };
      });

      const merged = resolveOverlappingSpans([...gate1, ...gate2]);
      const sanitized = vault.redactSpans(raw, merged);
      expect(sanitized).toBe(vec.expectedSanitized);

      const res = await verifyAndMintPayload({
        rawDoc: raw,
        candidateSanitized: sanitized,
        vault,
        policyProfile: vec.policyProfile,
      });
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.payload.receipt.redactedCount).toBe(vec.expectedRedactedCount);
        expect(vault.rehydrate(res.payload.sanitizedText)).toBe(vec.rawDoc);
      }
    });
  }

  for (const adv of spec.adversarialVectors) {
    it(`adversarial vector [${adv.id}] trips ${adv.expectedVector}`, async () => {
      const vault = new AirlockVault("AIRLOCK-CANARY-FIXED001");
      if (adv.category !== "CANARY") {
        vault.register(adv.secret, adv.category, "GATE2_NANO_ON_DEVICE");
      }
      const res = await verifyAndMintPayload({
        rawDoc: asRawDocument("Synthetic contract"),
        candidateSanitized: `Sanitized skeleton.${adv.poisonedSuffix}`,
        vault,
        policyProfile: "NDA_STRICT",
      });
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.violations.some((v) => v.vector === adv.expectedVector)).toBe(true);
      }
    });
  }
});
