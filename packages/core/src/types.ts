declare const RawBrand: unique symbol;
declare const VerifiedBrand: unique symbol;

export type RawDocument = string & { readonly [RawBrand]: true };

export type EntityCategory =
  | "CARD_OR_ACCOUNT"
  | "IBAN"
  | "SSN"
  | "EMAIL"
  | "PHONE"
  | "CURRENCY"
  | "DATE"
  | "API_SECRET"
  | "PERSON"
  | "ORG"
  | "MEDICAL"
  | "SECRET_TERM"
  | "CANARY";

export type PolicyProfile = "NDA_STRICT" | "MEDICAL_HIPAA" | "INVOICE_FINANCE";

export interface VaultEntry {
  readonly token: string;
  readonly original: string;
  readonly category: EntityCategory;
  readonly detectedBy: "GATE1_REGEX" | "GATE2_NANO_ON_DEVICE" | "SYSTEM_CANARY";
}

export interface DetectedSpan {
  readonly start: number;
  readonly end: number;
  readonly text: string;
  readonly category: EntityCategory;
  readonly detectedBy: "GATE1_REGEX" | "GATE2_NANO_ON_DEVICE";
}

export type FirewallVector =
  | "EXACT_OR_CASE_INSENSITIVE"
  | "COLLAPSED_ALPHANUMERIC"
  | "PARTIAL_TOKEN_OR_SURNAME"
  | "ENCODED_EXFILTRATION"
  | "UNICODE_NFKC_OR_ZERO_WIDTH"
  | "CANARY_TRAP";

export interface FirewallViolation {
  readonly vector: FirewallVector;
  readonly token: string;
  readonly category: EntityCategory;
  readonly detail: string;
}

export interface AirlockReceipt {
  readonly receiptVersion: "airlock.v1";
  readonly rawDocSha256: string;
  readonly sanitizedPayloadSha256: string;
  readonly prevReceiptSha256: string | null;
  readonly receiptSha256: string;
  readonly redactedCount: number;
  readonly checksPassed: 6;
  readonly firewallPassed: true;
  readonly policyProfile: PolicyProfile;
  readonly timestampIso: string;
}

export interface VerifiedSanitizedPayload {
  readonly [VerifiedBrand]: true;
  readonly sanitizedText: string;
  readonly entitySummary: ReadonlyArray<{
    readonly token: string;
    readonly category: EntityCategory;
  }>;
  readonly receipt: AirlockReceipt;
}

export type FirewallResult =
  | { readonly ok: true; readonly payload: VerifiedSanitizedPayload }
  | {
      readonly ok: false;
      readonly violations: ReadonlyArray<FirewallViolation>;
      readonly blockedBytes: number;
    };

export function asRawDocument(input: string): RawDocument {
  return input as RawDocument;
}
