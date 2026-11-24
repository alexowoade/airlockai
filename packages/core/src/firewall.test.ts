import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  AirlockVault,
  asRawDocument,
  injectRedTeamAttack,
  passesLuhn,
  resolveOverlappingSpans,
  scanDeterministicPii,
  verifyAndMintPayload,
  type DetectedSpan,
} from "./index.js";

/** Deterministically generates a Luhn-valid 16-digit card number from 15 digits */
function makeLuhnCard(prefix15: string): string {
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let digit = Number(prefix15[14 - i]);
    if (i % 2 === 0) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  const full = `${prefix15}${checkDigit}`;
  return `${full.slice(0, 4)}-${full.slice(4, 8)}-${full.slice(8, 12)}-${full.slice(12, 16)}`;
}

describe("AirlockAI 6-Vector Pre-Flight Firewall & Zero-Leak Proofs", () => {
  it("blocks all 4 Red-Team adversarial attacks with zero bytes sent", async () => {
    const raw = asRawDocument(
      "Mutual NDA between Helios Robotics and Elena Vance (elena.vance@helios.test, SSN 912-45-6789, retainer $45,000.00)."
    );
    const vault = new AirlockVault();
    const gate1 = scanDeterministicPii(raw);

    // Simulate Gate 2 on-device Gemini Nano semantic spans for PERSON & ORG
    const orgIdx = raw.indexOf("Helios Robotics");
    const personIdx = raw.indexOf("Elena Vance");
    const gate2: DetectedSpan[] = [
      {
        start: orgIdx,
        end: orgIdx + "Helios Robotics".length,
        text: "Helios Robotics",
        category: "ORG",
        detectedBy: "GATE2_NANO_ON_DEVICE",
      },
      {
        start: personIdx,
        end: personIdx + "Elena Vance".length,
        text: "Elena Vance",
        category: "PERSON",
        detectedBy: "GATE2_NANO_ON_DEVICE",
      },
    ];

    const merged = resolveOverlappingSpans([...gate1, ...gate2]);
    const cleanSanitized = vault.redactSpans(raw, merged);

    // 1. Clean sanitized payload must pass 6/6 checks and mint SHA-256 receipt
    const cleanResult = await verifyAndMintPayload({
      rawDoc: raw,
      candidateSanitized: cleanSanitized,
      vault,
      policyProfile: "NDA_STRICT",
    });
    expect(cleanResult.ok).toBe(true);
    if (cleanResult.ok) {
      expect(cleanResult.payload.receipt.checksPassed).toBe(6);
      expect(cleanResult.payload.receipt.rawDocSha256).toHaveLength(64);
      expect(vault.rehydrate(cleanResult.payload.sanitizedText)).toBe(String(raw));
    }

    // 2. Every Red-Team attack vector MUST be blocked
    const attacks = [
      ["MISSED_ENTITY_ESCAPE", "EXACT_OR_CASE_INSENSITIVE"],
      ["BASE64_EXFILTRATION", "ENCODED_EXFILTRATION"],
      ["CANARY_PROMPT_INJECTION", "CANARY_TRAP"],
      ["ZERO_WIDTH_SMUGGLING", "UNICODE_NFKC_OR_ZERO_WIDTH"],
    ] as const;

    for (const [attack, expectedVector] of attacks) {
      const poisoned = injectRedTeamAttack(cleanSanitized, vault, attack);
      const blocked = await verifyAndMintPayload({
        rawDoc: raw,
        candidateSanitized: poisoned,
        vault,
        policyProfile: "NDA_STRICT",
      });
      expect(blocked.ok).toBe(false);
      if (!blocked.ok) {
        expect(blocked.violations.some((v) => v.vector === expectedVector)).toBe(true);
        expect(blocked.blockedBytes).toBeGreaterThan(0);
      }
    }

    // 3. Partial surname leak ("Vance") MUST also be caught by Vector 3
    const partialLeak = await verifyAndMintPayload({
      rawDoc: raw,
      candidateSanitized: `${cleanSanitized} Note: Vance refused clause 4.`,
      vault,
      policyProfile: "NDA_STRICT",
    });
    expect(partialLeak.ok).toBe(false);
    if (!partialLeak.ok) {
      expect(partialLeak.violations[0]?.vector).toBe("PARTIAL_TOKEN_OR_SURNAME");
    }
  });

  it("redacts PERSON, ORG, SECRET_TERM, and MEDICAL deterministically when Nano is unavailable", async () => {
    const cases = [
      {
        policy: "NDA_STRICT" as const,
        doc: `MUTUAL NON-DISCLOSURE AGREEMENT (Effective 2026-11-15)
Between Helios Robotics Corp ("Discloser", contact: elena.vance@helios-robotics.test, +1-415-890-4421) and Apex Foundry LLC ("Recipient").
1. Confidential Project: All schematics, pricing ($1,450,000.00 licensing floor), and API credentials (sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f) relating to Project Obsidian.
3. Non-Solicit & IP Assignment: Recipient personnel (Lead Engineer Marcus Sterling, SSN 912-45-6789).`,
        mustRedact: [
          "Helios Robotics Corp",
          "Apex Foundry LLC",
          "Project Obsidian",
          "Marcus Sterling",
          "elena.vance@helios-robotics.test",
          "912-45-6789",
        ],
      },
      {
        policy: "INVOICE_FINANCE" as const,
        doc: `Billed To: Meridian Logistics Group (ap@meridian-logistics.test)
Amount Due: $84,750.00. IBAN DE89370400440532013000.
Authorized Signer: David Okonkwo (+1-212-555-0194).`,
        mustRedact: ["Meridian Logistics Group", "David Okonkwo", "DE89370400440532013000"],
      },
      {
        policy: "MEDICAL_HIPAA" as const,
        doc: `Patient: Clara Lindqvist | SSN: 901-33-4482 | Email: clara.lindqvist@mail.test
Facility: Northstar Oncology & Imaging Center
Primary Diagnosis: Stage II Thyroid Carcinoma follow-up panel.`,
        mustRedact: [
          "Clara Lindqvist",
          "Northstar Oncology & Imaging Center",
          "Stage II Thyroid Carcinoma",
        ],
      },
    ];

    for (const tc of cases) {
      const raw = asRawDocument(tc.doc);
      const vault = new AirlockVault();
      const spans = scanDeterministicPii(raw);
      const sanitized = vault.redactSpans(raw, spans);
      const verified = await verifyAndMintPayload({
        rawDoc: raw,
        candidateSanitized: sanitized,
        vault,
        policyProfile: tc.policy,
      });
      expect(verified.ok).toBe(true);
      if (verified.ok) {
        for (const secret of tc.mustRedact) {
          expect(verified.payload.sanitizedText).not.toContain(secret);
        }
        expect(vault.rehydrate(verified.payload.sanitizedText)).toBe(String(raw));
      }
    }
  });

  it("encrypts and decrypts local PII vault cleanly via AES-256-GCM", async () => {
    const vault = new AirlockVault();
    vault.register("elena.vance@helios.test", "EMAIL", "GATE1_REGEX");
    vault.register("Project Obsidian", "SECRET_TERM", "GATE2_NANO_ON_DEVICE");

    const key = await AirlockVault.generateLocalKey();
    const blob = await vault.exportEncrypted(key);
    expect(blob.alg).toBe("AES-256-GCM");
    expect(blob.ciphertextBase64).not.toContain("Obsidian");

    const restored = await AirlockVault.decryptBlob(blob, key);
    expect(restored.some((e) => e.original === "Project Obsidian")).toBe(true);
  });

  it("chains SHA-256 receipts across sequential audits", async () => {
    const vault = new AirlockVault();
    const doc1 = asRawDocument("Invoice for user1@corp.test amount $1,200.00.");
    const s1 = vault.redactSpans(doc1, scanDeterministicPii(doc1));
    const r1 = await verifyAndMintPayload({
      rawDoc: doc1,
      candidateSanitized: s1,
      vault,
      policyProfile: "INVOICE_FINANCE",
    });
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;

    const doc2 = asRawDocument("Follow-up for user2@corp.test amount $2,400.00.");
    const s2 = vault.redactSpans(doc2, scanDeterministicPii(doc2));
    const r2 = await verifyAndMintPayload({
      rawDoc: doc2,
      candidateSanitized: s2,
      vault,
      policyProfile: "INVOICE_FINANCE",
      prevReceiptSha256: r1.payload.receipt.receiptSha256,
    });
    expect(r2.ok).toBe(true);
    if (r2.ok) {
      expect(r2.payload.receipt.prevReceiptSha256).toBe(r1.payload.receipt.receiptSha256);
      expect(r2.payload.receipt.receiptSha256).not.toBe(r1.payload.receipt.receiptSha256);
    }
  });

  it("PROVES ZERO LEAKS across 1,000 randomized synthetic contracts (fast-check)", async () => {
    const digits = (n: number) =>
      fc
        .array(fc.integer({ min: 0, max: 9 }), { minLength: n, maxLength: n })
        .map((arr) => arr.join(""));

    const cardArb = digits(15).map(makeLuhnCard);
    const ssnArb = fc
      .tuple(digits(3), digits(2), digits(4))
      .map(([a, b, c]) => `${a}-${b}-${c}`);
    const emailArb = fc
      .tuple(
        fc.stringMatching(/^[a-z]{4,10}$/),
        fc.stringMatching(/^[a-z]{4,10}$/)
      )
      .map(([u, d]) => `${u}@${d}.test`);
    const phoneArb = fc
      .tuple(digits(3), digits(3), digits(4))
      .map(([a, b, c]) => `+1-${a}-${b}-${c}`);
    const amountArb = fc
      .integer({ min: 100, max: 999999 })
      .map((n) => `$${n.toLocaleString("en-US")}.00`);

    await fc.assert(
      fc.asyncProperty(cardArb, ssnArb, emailArb, phoneArb, amountArb, async (card, ssn, email, phone, amount) => {
        expect(passesLuhn(card)).toBe(true);

        const raw = asRawDocument(
          `AGREEMENT: Party contact ${email}, phone ${phone}, tax id ${ssn}, settlement card ${card}, cap ${amount}.`
        );
        const vault = new AirlockVault();
        const spans = scanDeterministicPii(raw);
        const sanitized = vault.redactSpans(raw, spans);

        const verified = await verifyAndMintPayload({
          rawDoc: raw,
          candidateSanitized: sanitized,
          vault,
          policyProfile: "NDA_STRICT",
        });

        expect(verified.ok).toBe(true);
        if (verified.ok) {
          const out = verified.payload.sanitizedText;
          expect(out).not.toContain(card);
          expect(out).not.toContain(ssn);
          expect(out).not.toContain(email);
          expect(out).not.toContain(phone);
          expect(out).not.toContain(amount);
          expect(vault.rehydrate(out)).toBe(String(raw));
        }
      }),
      { numRuns: 1000 }
    );
  });
});
