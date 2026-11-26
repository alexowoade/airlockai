import type { PolicyProfile, VaultEntry } from "@airlock/core";

export interface WebAuthnPrfCapabilities {
  readonly webAuthnSupported: boolean;
  readonly platformAuthenticatorAvailable: boolean;
  readonly prfExtensionReported: boolean | null;
  readonly rpId: string;
}

export interface EnrolledPasskeyMeta {
  readonly credentialIdBase64Url: string;
  readonly rpId: string;
  readonly label: string;
  readonly prfConfirmed: boolean;
  readonly createdAtIso: string;
}

export interface PasskeyEncryptedVaultEnvelope {
  readonly format: "AirlockAI.PasskeyEncryptedVault";
  readonly version: "airlock.prf.v1";
  readonly kdf: "WEBAUTHN_PRF_HKDF_SHA256";
  readonly cipher: "AES-256-GCM";
  readonly aadBound: true;
  readonly containsRawPiiInHeader: false;
  readonly exportedAtIso: string;
  readonly rpId: string;
  readonly credentialIdBase64Url: string;
  readonly policyProfile: PolicyProfile;
  readonly receiptSha256: string;
  readonly entryCount: number;
  readonly prfSaltBase64: string;
  readonly hkdfSaltBase64: string;
  readonly ivBase64: string;
  readonly ciphertextBase64: string;
}

export interface PasskeyDecryptedVaultBundle {
  readonly policyProfile: PolicyProfile;
  readonly receiptSha256: string;
  readonly entries: ReadonlyArray<VaultEntry>;
  readonly sanitizedText: string;
  readonly sanitizedAuditMarkdown: string | null;
  readonly exportedAtIso: string;
  readonly credentialIdBase64Url: string;
}

export interface PrfCryptoSelfTestReport {
  readonly ok: boolean;
  readonly latencyMs: number;
  readonly ciphertextBytes: number;
  readonly entryCount: number;
  readonly roundTripVerified: boolean;
  readonly zeroRawPiiInCiphertext: boolean;
  readonly wrongPrfRejected: boolean;
  readonly ciphertextTamperRejected: boolean;
  readonly aadTamperRejected: boolean;
  readonly detail: string;
}

const PASSKEY_STORAGE_KEY = "airlockai_webauthn_prf_meta_v1";
const HKDF_INFO_DOMAIN = "AirlockAI.WebAuthnPRF.VaultKey.v1";

function toExactBytes(input: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(input);
  const buf = new ArrayBuffer(encoded.byteLength);
  const out = new Uint8Array(buf);
  out.set(encoded);
  return out;
}

function randomExactBytes(length: number): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(length);
  const out = new Uint8Array(buf);
  crypto.getRandomValues(out);
  return out;
}

function copyToExactBytes(src: ArrayBuffer | Uint8Array): Uint8Array<ArrayBuffer> {
  const view = src instanceof Uint8Array ? src : new Uint8Array(src);
  const buf = new ArrayBuffer(view.byteLength);
  const out = new Uint8Array(buf);
  out.set(view);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

function base64ToExactBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToExactBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const padded = b64u.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (b64u.length % 4)) % 4);
  return base64ToExactBytes(padded);
}

function buildVaultAad(credentialIdBase64Url: string, receiptSha256: string, policyProfile: string): Uint8Array<ArrayBuffer> {
  return toExactBytes(`AirlockAI.PasskeyVault.v1|${credentialIdBase64Url}|${receiptSha256}|${policyProfile}`);
}

export function loadEnrolledPasskeyMeta(): EnrolledPasskeyMeta | null {
  try {
    if (typeof localStorage === "undefined") return null;
    const raw = localStorage.getItem(PASSKEY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<EnrolledPasskeyMeta>;
    if (!parsed.credentialIdBase64Url || !parsed.rpId) return null;
    return {
      credentialIdBase64Url: parsed.credentialIdBase64Url,
      rpId: parsed.rpId,
      label: parsed.label ?? "Hardware Passkey",
      prfConfirmed: Boolean(parsed.prfConfirmed),
      createdAtIso: parsed.createdAtIso ?? new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

export function clearEnrolledPasskeyMeta(): void {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(PASSKEY_STORAGE_KEY);
    }
  } catch {
    // ignore storage errors
  }
}

export async function probeWebAuthnPrfCapabilities(): Promise<WebAuthnPrfCapabilities> {
  const rpId = typeof window !== "undefined" ? window.location.hostname || "localhost" : "localhost";
  const webAuthnSupported =
    typeof window !== "undefined" &&
    typeof PublicKeyCredential !== "undefined" &&
    typeof navigator !== "undefined" &&
    Boolean(navigator.credentials?.create) &&
    Boolean(navigator.credentials?.get);

  if (!webAuthnSupported) {
    return {
      webAuthnSupported: false,
      platformAuthenticatorAvailable: false,
      prfExtensionReported: false,
      rpId,
    };
  }

  let platformAuthenticatorAvailable = false;
  try {
    platformAuthenticatorAvailable =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    platformAuthenticatorAvailable = false;
  }

  let prfExtensionReported: boolean | null = null;
  try {
    const pkc = PublicKeyCredential as unknown as {
      getClientCapabilities?: () => Promise<Record<string, boolean>>;
    };
    if (typeof pkc.getClientCapabilities === "function") {
      const caps = await pkc.getClientCapabilities();
      if ("extension:prf" in caps) {
        prfExtensionReported = Boolean(caps["extension:prf"]);
      }
    }
  } catch {
    prfExtensionReported = null;
  }

  return {
    webAuthnSupported,
    platformAuthenticatorAvailable,
    prfExtensionReported,
    rpId,
  };
}

/**
 * Derives a non-extractable AES-256-GCM wrapping key from 32-byte WebAuthn PRF output
 * via HKDF-SHA256 with per-file salt and domain-separated info.
 */
export async function deriveAesGcmKeyFromPrfSecret(
  prfSecretBytes: Uint8Array<ArrayBuffer>,
  hkdfSalt: Uint8Array<ArrayBuffer>
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    "raw",
    prfSecretBytes,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: hkdfSalt,
      info: toExactBytes(HKDF_INFO_DOMAIN),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Seals a local AirlockVault into an AAD-bound AES-256-GCM envelope using 32-byte PRF output.
 */
export async function sealVaultWithPrfBytes(params: {
  prfSecretBytes: Uint8Array<ArrayBuffer>;
  prfSaltBytes: Uint8Array<ArrayBuffer>;
  credentialIdBase64Url: string;
  rpId: string;
  policyProfile: PolicyProfile;
  receiptSha256: string;
  entries: ReadonlyArray<VaultEntry>;
  sanitizedText: string;
  sanitizedAuditMarkdown: string | null;
}): Promise<{ readonly json: string; readonly envelope: PasskeyEncryptedVaultEnvelope }> {
  const hkdfSalt = randomExactBytes(32);
  const iv = randomExactBytes(12);
  const aesKey = await deriveAesGcmKeyFromPrfSecret(params.prfSecretBytes, hkdfSalt);
  const aad = buildVaultAad(params.credentialIdBase64Url, params.receiptSha256, params.policyProfile);

  const plaintextPayload = JSON.stringify({
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entries: params.entries,
    sanitizedText: params.sanitizedText,
    sanitizedAuditMarkdown: params.sanitizedAuditMarkdown,
  });

  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    aesKey,
    toExactBytes(plaintextPayload)
  );

  const envelope: PasskeyEncryptedVaultEnvelope = {
    format: "AirlockAI.PasskeyEncryptedVault",
    version: "airlock.prf.v1",
    kdf: "WEBAUTHN_PRF_HKDF_SHA256",
    cipher: "AES-256-GCM",
    aadBound: true,
    containsRawPiiInHeader: false,
    exportedAtIso: new Date().toISOString(),
    rpId: params.rpId,
    credentialIdBase64Url: params.credentialIdBase64Url,
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entryCount: params.entries.length,
    prfSaltBase64: bytesToBase64(params.prfSaltBytes),
    hkdfSaltBase64: bytesToBase64(hkdfSalt),
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(cipherBuf)),
  };

  return {
    json: JSON.stringify(envelope, null, 2),
    envelope,
  };
}

/**
 * Unseals a Passkey-sealed .airlock.enc envelope using the 32-byte PRF output.
 * Any wrong PRF secret, ciphertext tamper, or AAD header swap fails AES-GCM auth immediately.
 */
export async function unsealVaultWithPrfBytes(
  envelope: PasskeyEncryptedVaultEnvelope,
  prfSecretBytes: Uint8Array<ArrayBuffer>
): Promise<PasskeyDecryptedVaultBundle> {
  if (
    envelope.format !== "AirlockAI.PasskeyEncryptedVault" ||
    envelope.kdf !== "WEBAUTHN_PRF_HKDF_SHA256" ||
    envelope.cipher !== "AES-256-GCM"
  ) {
    throw new Error("Invalid Passkey-sealed .airlock.enc envelope schema.");
  }

  const hkdfSalt = base64ToExactBytes(envelope.hkdfSaltBase64);
  const iv = base64ToExactBytes(envelope.ivBase64);
  const ciphertext = base64ToExactBytes(envelope.ciphertextBase64);
  const aad = buildVaultAad(
    envelope.credentialIdBase64Url,
    envelope.receiptSha256,
    envelope.policyProfile
  );
  const aesKey = await deriveAesGcmKeyFromPrfSecret(prfSecretBytes, hkdfSalt);

  let plainBuf: ArrayBuffer;
  try {
    plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      aesKey,
      ciphertext
    );
  } catch {
    throw new Error(
      "PASSKEY UNSEAL FAILED — Wrong hardware passkey PRF output or tampered AAD/ciphertext (AES-GCM tag mismatch)."
    );
  }

  const decoded = JSON.parse(new TextDecoder().decode(plainBuf)) as {
    policyProfile: PolicyProfile;
    receiptSha256: string;
    entries: ReadonlyArray<VaultEntry>;
    sanitizedText: string;
    sanitizedAuditMarkdown: string | null;
  };

  return {
    ...decoded,
    exportedAtIso: envelope.exportedAtIso,
    credentialIdBase64Url: envelope.credentialIdBase64Url,
  };
}

/**
 * Enrolls a real W3C WebAuthn Level 3 Passkey requesting the PRF extension.
 */
export async function enrollWebAuthnPrfPasskey(label = "AirlockAI Local Enclave Passkey"): Promise<EnrolledPasskeyMeta> {
  const caps = await probeWebAuthnPrfCapabilities();
  if (!caps.webAuthnSupported) {
    throw new Error("WebAuthn is not available in this browser context.");
  }

  const userId = randomExactBytes(16);
  const challenge = randomExactBytes(32);
  const probeSalt = randomExactBytes(32);

  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge,
    rp: {
      name: "AirlockAI Hybrid Security Appliance",
      id: caps.rpId,
    },
    user: {
      id: userId,
      name: "airlock-local-operator",
      displayName: label,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 }, // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required",
    },
    timeout: 60_000,
    attestation: "none",
    extensions: {
      prf: {
        eval: { first: probeSalt },
      },
    } as unknown as AuthenticationExtensionsClientInputs,
  };

  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) {
    throw new Error("Passkey enrollment was cancelled.");
  }

  const extResults = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } };
  const meta: EnrolledPasskeyMeta = {
    credentialIdBase64Url: bytesToBase64Url(new Uint8Array(cred.rawId)),
    rpId: caps.rpId,
    label,
    prfConfirmed: Boolean(extResults?.prf?.enabled),
    createdAtIso: new Date().toISOString(),
  };

  try {
    localStorage.setItem(PASSKEY_STORAGE_KEY, JSON.stringify(meta));
  } catch {
    // ignore storage quota errors
  }
  return meta;
}

/**
 * Evaluates a 32-byte hardware-enclave PRF secret via W3C WebAuthn navigator.credentials.get().
 */
export async function evaluateHardwarePrfSecret(params: {
  credentialIdBase64Url: string;
  rpId: string;
  prfSaltBytes: Uint8Array<ArrayBuffer>;
}): Promise<Uint8Array<ArrayBuffer>> {
  const challenge = randomExactBytes(32);
  const credIdBytes = base64UrlToExactBytes(params.credentialIdBase64Url);

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: params.rpId,
    allowCredentials: [
      {
        type: "public-key",
        id: credIdBytes,
      },
    ],
    userVerification: "required",
    timeout: 60_000,
    extensions: {
      prf: {
        eval: { first: params.prfSaltBytes },
      },
    } as unknown as AuthenticationExtensionsClientInputs,
  };

  const assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!assertion) {
    throw new Error("Hardware passkey verification was cancelled.");
  }

  const extResults = assertion.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const prfFirst = extResults?.prf?.results?.first;
  if (!prfFirst || prfFirst.byteLength < 16) {
    throw new Error(
      "This authenticator completed WebAuthn assertion but did not return WebAuthn PRF output. Use the PBKDF2 .airlock.enc vault or a PRF-capable passkey (Chrome/Edge/macOS/Android/YubiKey)."
    );
  }
  return copyToExactBytes(prfFirst);
}

/**
 * Seals the live AirlockVault using a real hardware passkey PRF evaluation.
 */
export async function sealVaultWithHardwarePasskey(params: {
  passkey: EnrolledPasskeyMeta;
  policyProfile: PolicyProfile;
  receiptSha256: string;
  entries: ReadonlyArray<VaultEntry>;
  sanitizedText: string;
  sanitizedAuditMarkdown: string | null;
}): Promise<{ readonly json: string; readonly envelope: PasskeyEncryptedVaultEnvelope }> {
  const prfSaltBytes = randomExactBytes(32);
  const prfSecretBytes = await evaluateHardwarePrfSecret({
    credentialIdBase64Url: params.passkey.credentialIdBase64Url,
    rpId: params.passkey.rpId,
    prfSaltBytes,
  });
  return sealVaultWithPrfBytes({
    prfSecretBytes,
    prfSaltBytes,
    credentialIdBase64Url: params.passkey.credentialIdBase64Url,
    rpId: params.passkey.rpId,
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entries: params.entries,
    sanitizedText: params.sanitizedText,
    sanitizedAuditMarkdown: params.sanitizedAuditMarkdown,
  });
}

/**
 * Unseals a Passkey-sealed .airlock.enc file using the matching hardware passkey.
 */
export async function unsealVaultWithHardwarePasskey(
  rawJsonText: string
): Promise<PasskeyDecryptedVaultBundle> {
  const envelope = JSON.parse(rawJsonText) as PasskeyEncryptedVaultEnvelope;
  const prfSaltBytes = base64ToExactBytes(envelope.prfSaltBase64);
  const prfSecretBytes = await evaluateHardwarePrfSecret({
    credentialIdBase64Url: envelope.credentialIdBase64Url,
    rpId: envelope.rpId,
    prfSaltBytes,
  });
  return unsealVaultWithPrfBytes(envelope, prfSecretBytes);
}

/**
 * Deterministic Software-Enclave PRF Cryptographic Self-Test (runs 100% locally in RAM
 * on any device/OS without requiring physical biometric touch):
 * Proves PRF -> HKDF-SHA256 -> AAD-bound AES-256-GCM round-trip, zero raw PII in ciphertext,
 * wrong-PRF rejection, 1-bit ciphertext tamper rejection, and AAD header swap rejection.
 */
export async function runPrfVaultCryptoSelfTest(params: {
  policyProfile: PolicyProfile;
  receiptSha256: string;
  entries: ReadonlyArray<VaultEntry>;
  sanitizedText: string;
  sanitizedAuditMarkdown: string | null;
}): Promise<PrfCryptoSelfTestReport> {
  const t0 = performance.now();
  const prfSaltBytes = randomExactBytes(32);
  const simulatedEnclavePrf = randomExactBytes(32);
  const credId = "sim-prf-enclave-self-test-v1";

  const { json, envelope } = await sealVaultWithPrfBytes({
    prfSecretBytes: simulatedEnclavePrf,
    prfSaltBytes,
    credentialIdBase64Url: credId,
    rpId: typeof window !== "undefined" ? window.location.hostname || "localhost" : "localhost",
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entries: params.entries,
    sanitizedText: params.sanitizedText,
    sanitizedAuditMarkdown: params.sanitizedAuditMarkdown,
  });

  // 1. Verify 0 raw vault secrets appear anywhere in serialized encrypted envelope
  const lowerJson = json.toLowerCase();
  const zeroRawPiiInCiphertext = params.entries.every(
    (e) => e.original.trim().length < 4 || !lowerJson.includes(e.original.trim().toLowerCase())
  );

  // 2. Verify clean round-trip recovery with exact PRF secret
  const unsealed = await unsealVaultWithPrfBytes(envelope, simulatedEnclavePrf);
  const roundTripVerified =
    unsealed.entries.length === params.entries.length &&
    unsealed.sanitizedText === params.sanitizedText &&
    unsealed.entries.every((e, i) => e.original === params.entries[i]?.original);

  // 3. Flip 1 bit in PRF secret -> MUST reject decryption
  const wrongPrf = copyToExactBytes(simulatedEnclavePrf);
  wrongPrf[0] = wrongPrf[0]! ^ 0x01;
  let wrongPrfRejected = false;
  try {
    await unsealVaultWithPrfBytes(envelope, wrongPrf);
  } catch {
    wrongPrfRejected = true;
  }

  // 4. Flip 1 bit in AES-GCM ciphertext -> MUST reject auth tag
  const rawCt = base64ToExactBytes(envelope.ciphertextBase64);
  rawCt[0] = rawCt[0]! ^ 0x01;
  const tamperedCtEnv: PasskeyEncryptedVaultEnvelope = {
    ...envelope,
    ciphertextBase64: bytesToBase64(rawCt),
  };
  let ciphertextTamperRejected = false;
  try {
    await unsealVaultWithPrfBytes(tamperedCtEnv, simulatedEnclavePrf);
  } catch {
    ciphertextTamperRejected = true;
  }

  // 5. Mutate AAD-bound header (receiptSha256) -> MUST reject auth tag
  const tamperedAadEnv: PasskeyEncryptedVaultEnvelope = {
    ...envelope,
    receiptSha256: `${envelope.receiptSha256[0] === "0" ? "1" : "0"}${envelope.receiptSha256.slice(1)}`,
  };
  let aadTamperRejected = false;
  try {
    await unsealVaultWithPrfBytes(tamperedAadEnv, simulatedEnclavePrf);
  } catch {
    aadTamperRejected = true;
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - t0));
  const ok =
    zeroRawPiiInCiphertext &&
    roundTripVerified &&
    wrongPrfRejected &&
    ciphertextTamperRejected &&
    aadTamperRejected;

  return {
    ok,
    latencyMs,
    ciphertextBytes: json.length,
    entryCount: params.entries.length,
    roundTripVerified,
    zeroRawPiiInCiphertext,
    wrongPrfRejected,
    ciphertextTamperRejected,
    aadTamperRejected,
    detail: ok
      ? `WEBAUTHN PRF -> HKDF-SHA256 -> AES-256-GCM (AAD) VERIFIED (${latencyMs}ms · ${params.entries.length} tokens · ${json.length}B ciphertext · 0 raw PII · wrong-PRF / 1-bit CT / AAD tamper all rejected).`
      : "PRF cryptographic self-test detected a verification mismatch.",
  };
}
