import { Schema, type FunctionDeclaration } from "firebase/ai";
import type { AirlockVault, VaultEntry } from "@airlock/core";

export interface OracleCallTrace {
  readonly toolName: string;
  readonly args: Record<string, unknown>;
  readonly predicateResult: Record<string, unknown>;
  readonly latencyMs: number;
  readonly zeroPiiVerified: boolean;
}

/**
 * Firebase AI Logic Function Declarations for Zero-Knowledge Local Oracle reasoning.
 * Cloud Gemini invokes these tools over redacted placeholder tokens; execution happens
 * strictly inside local browser RAM and returns ONLY boolean/ratio predicates (0B raw PII).
 */
export const ZK_ORACLE_FUNCTION_DECLARATIONS: FunctionDeclaration[] = [
  {
    name: "compare_currency_tokens",
    description:
      "Compare two redacted currency placeholder tokens (e.g., [CURRENCY_1] and [CURRENCY_2]) locally in browser RAM without revealing raw dollar amounts. Returns exact relation, ratio, and percentage delta.",
    parameters: Schema.object({
      properties: {
        baselineToken: Schema.string({
          description: "Redacted placeholder token for the authorized cap or baseline amount, e.g. [CURRENCY_1].",
        }),
        challengerToken: Schema.string({
          description: "Redacted placeholder token for the invoiced or challenger amount, e.g. [CURRENCY_2].",
        }),
      },
    }),
  },
  {
    name: "compare_date_tokens",
    description:
      "Compare two redacted date placeholder tokens (e.g., [DATE_1] and [DATE_2]) locally in browser RAM without revealing calendar dates. Returns exact days delta and whether targetToken is past deadlineToken.",
    parameters: Schema.object({
      properties: {
        deadlineToken: Schema.string({
          description: "Redacted placeholder token for the contract expiration or deadline date, e.g. [DATE_1].",
        }),
        targetToken: Schema.string({
          description: "Redacted placeholder token for the invoice or event date, e.g. [DATE_2].",
        }),
      },
    }),
  },
  {
    name: "verify_iban_jurisdiction",
    description:
      "Verify a redacted IBAN token (e.g., [IBAN_2]) locally in browser RAM against an expected 2-letter ISO country code (e.g., DE or US) and validate its MOD-97 checksum without revealing the IBAN.",
    parameters: Schema.object({
      properties: {
        ibanToken: Schema.string({
          description: "Redacted placeholder token for the IBAN, e.g. [IBAN_2].",
        }),
        expectedCountryCode: Schema.string({
          description: "Expected 2-letter ISO country code from contract policy, e.g. DE.",
        }),
      },
    }),
  },
  {
    name: "check_token_identity",
    description:
      "Check whether two redacted placeholder tokens refer to the same underlying value locally in browser RAM without revealing raw values.",
    parameters: Schema.object({
      properties: {
        tokenA: Schema.string({ description: "First placeholder token, e.g. [IBAN_1]." }),
        tokenB: Schema.string({ description: "Second placeholder token, e.g. [IBAN_2]." }),
      },
    }),
  },
];

function lookupEntry(vault: AirlockVault, rawToken: unknown): VaultEntry | undefined {
  const token = String(rawToken ?? "").trim();
  return vault.getEntries(false).find((e) => e.token === token);
}

function parseCurrencyNumber(raw: string): number | null {
  const cleaned = raw.replace(/[^0-9.-]/g, "");
  if (!cleaned) return null;
  const val = Number.parseFloat(cleaned);
  return Number.isFinite(val) ? val : null;
}

function parseDateMs(raw: string): number | null {
  const trimmed = raw.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    const ms = Date.parse(`${trimmed}T00:00:00Z`);
    return Number.isFinite(ms) ? ms : null;
  }
  const ms = Date.parse(trimmed);
  return Number.isFinite(ms) ? ms : null;
}

function verifyIbanMod97(ibanRaw: string): boolean {
  const clean = ibanRaw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(clean)) return false;
  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    const digits = code >= 65 && code <= 90 ? String(code - 55) : rearranged[i]!;
    for (let j = 0; j < digits.length; j++) {
      remainder = (remainder * 10 + Number(digits[j])) % 97;
    }
  }
  return remainder === 1;
}

function assertZeroPiiInOracleReturn(
  payload: Record<string, unknown>,
  vault: AirlockVault
): boolean {
  const serialized = JSON.stringify(payload).toLowerCase();
  for (const entry of vault.getEntries(true)) {
    const orig = entry.original.trim().toLowerCase();
    if (orig.length >= 4 && serialized.includes(orig)) {
      return false;
    }
  }
  return true;
}

/**
 * Executes a single Firebase AI Logic tool call strictly in local browser RAM.
 */
export function executeLocalZkOracle(
  toolName: string,
  args: Record<string, unknown>,
  vault: AirlockVault
): { readonly response: Record<string, unknown>; readonly trace: OracleCallTrace } {
  const t0 = performance.now();
  let response: Record<string, unknown>;

  if (toolName === "compare_currency_tokens") {
    const baseEntry = lookupEntry(vault, args.baselineToken);
    const chalEntry = lookupEntry(vault, args.challengerToken);
    const baseVal = baseEntry ? parseCurrencyNumber(baseEntry.original) : null;
    const chalVal = chalEntry ? parseCurrencyNumber(chalEntry.original) : null;

    if (baseVal === null || chalVal === null || baseVal === 0) {
      response = { ok: false, error: "One or both currency tokens could not be resolved locally." };
    } else {
      const ratio = Number((chalVal / baseVal).toFixed(4));
      const pctDelta = Number((((chalVal - baseVal) / baseVal) * 100).toFixed(2));
      response = {
        ok: true,
        relation: chalVal > baseVal ? "EXCEEDS_BASELINE" : chalVal < baseVal ? "UNDER_BASELINE" : "EQUAL",
        exceedsCap: chalVal > baseVal,
        ratioChallengerToBaseline: ratio,
        percentDelta: `${pctDelta >= 0 ? "+" : ""}${pctDelta}%`,
        privacyGuarantee: "Computed strictly in local browser RAM; 0 raw currency digits returned.",
      };
    }
  } else if (toolName === "compare_date_tokens") {
    const deadEntry = lookupEntry(vault, args.deadlineToken);
    const targEntry = lookupEntry(vault, args.targetToken);
    const deadMs = deadEntry ? parseDateMs(deadEntry.original) : null;
    const targMs = targEntry ? parseDateMs(targEntry.original) : null;

    if (deadMs === null || targMs === null) {
      response = { ok: false, error: "One or both date tokens could not be resolved locally." };
    } else {
      const daysDelta = Math.round((targMs - deadMs) / 86_400_000);
      response = {
        ok: true,
        relation: daysDelta > 0 ? "AFTER_DEADLINE" : daysDelta < 0 ? "BEFORE_DEADLINE" : "ON_DEADLINE",
        isPastDeadline: daysDelta > 0,
        daysDelta,
        privacyGuarantee: "Computed strictly in local browser RAM; 0 raw calendar dates returned.",
      };
    }
  } else if (toolName === "verify_iban_jurisdiction") {
    const ibanEntry = lookupEntry(vault, args.ibanToken);
    const expected = String(args.expectedCountryCode ?? "").trim().toUpperCase().slice(0, 2);
    if (!ibanEntry) {
      response = { ok: false, error: "IBAN token not found in local vault." };
    } else {
      const cleanIban = ibanEntry.original.replace(/\s+/g, "").toUpperCase();
      const actualPrefix = cleanIban.slice(0, 2);
      const matches = Boolean(expected && actualPrefix === expected);
      response = {
        ok: true,
        checksumValid: verifyIbanMod97(cleanIban),
        matchesExpectedCountry: matches,
        riskFlag: matches ? "JURISDICTION_MATCH" : "CROSS_BORDER_JURISDICTION_MISMATCH",
        privacyGuarantee: "IBAN MOD-97 & jurisdiction verified in local RAM; 0 account digits returned.",
      };
    }
  } else if (toolName === "check_token_identity") {
    const eA = lookupEntry(vault, args.tokenA);
    const eB = lookupEntry(vault, args.tokenB);
    if (!eA || !eB) {
      response = { ok: false, error: "One or both tokens not found in local vault." };
    } else {
      const sameEntity = eA.original.trim().toLowerCase() === eB.original.trim().toLowerCase();
      response = {
        ok: true,
        sameEntity,
        sameCategory: eA.category === eB.category,
        categoryA: eA.category,
        categoryB: eB.category,
        privacyGuarantee: "Identity compared strictly in local RAM; 0 raw entity values returned.",
      };
    }
  } else {
    response = { ok: false, error: `Unknown local oracle tool: ${toolName}` };
  }

  const zeroPiiVerified = assertZeroPiiInOracleReturn(response, vault);
  if (!zeroPiiVerified) {
    response = {
      ok: false,
      error: "ORACLE_ZERO_LEAK_GUARD_BLOCKED: Potential raw secret detected in tool output; redacted.",
    };
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - t0));
  return {
    response,
    trace: {
      toolName,
      args,
      predicateResult: response,
      latencyMs,
      zeroPiiVerified,
    },
  };
}
