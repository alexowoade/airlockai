import { base64ToBytes, bytesToBase64, type PolicyProfile, type VaultEntry } from "@airlock/core";

export interface EncryptedVaultEnvelope {
  readonly format: "AirlockAI.EncryptedVault.v1";
  readonly kdf: "PBKDF2-SHA256";
  readonly iterations: 100000;
  readonly cipher: "AES-256-GCM";
  readonly exportedAtIso: string;
  readonly policyProfile: PolicyProfile;
  readonly receiptSha256: string;
  readonly entryCount: number;
  readonly saltBase64: string;
  readonly ivBase64: string;
  readonly ciphertextBase64: string;
}

export interface DecryptedVaultBundle {
  readonly vaultVersion: "airlock.vault.v1";
  readonly exportedAtIso: string;
  readonly policyProfile: PolicyProfile;
  readonly receiptSha256: string;
  readonly entries: ReadonlyArray<VaultEntry>;
  readonly sanitizedText: string;
  readonly sanitizedAuditMarkdown: string | null;
}

function toArrayBufferBytes(str: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(str);
  const copy = new Uint8Array(encoded.byteLength);
  copy.set(encoded);
  return copy;
}

async function deriveAesKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number
): Promise<CryptoKey> {
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBufferBytes(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts the local token vault + optional sanitized cloud audit with PBKDF2-SHA256 (100k)
 * + AES-256-GCM so zero-knowledge re-hydration survives browser reloads without ever
 * sending secrets to Firebase.
 */
export async function encryptVaultToFileJson(params: {
  passphrase: string;
  policyProfile: PolicyProfile;
  receiptSha256: string;
  entries: ReadonlyArray<VaultEntry>;
  sanitizedText: string;
  sanitizedAuditMarkdown: string | null;
}): Promise<{ readonly json: string; readonly envelope: EncryptedVaultEnvelope }> {
  const trimmedPass = params.passphrase.trim();
  if (trimmedPass.length < 6) {
    throw new Error("Passphrase must be at least 6 characters to derive an AES-256-GCM key.");
  }

  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);

  const exportedAtIso = new Date().toISOString();
  const payload: DecryptedVaultBundle = {
    vaultVersion: "airlock.vault.v1",
    exportedAtIso,
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entries: params.entries.filter((e) => e.category !== "CANARY"),
    sanitizedText: params.sanitizedText,
    sanitizedAuditMarkdown: params.sanitizedAuditMarkdown,
  };

  const key = await deriveAesKeyFromPassphrase(trimmedPass, salt, 100_000);
  const encryptedBuf = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    toArrayBufferBytes(JSON.stringify(payload))
  );

  const envelope: EncryptedVaultEnvelope = {
    format: "AirlockAI.EncryptedVault.v1",
    kdf: "PBKDF2-SHA256",
    iterations: 100000,
    cipher: "AES-256-GCM",
    exportedAtIso,
    policyProfile: params.policyProfile,
    receiptSha256: params.receiptSha256,
    entryCount: payload.entries.length,
    saltBase64: bytesToBase64(salt),
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(encryptedBuf)),
  };

  return { json: JSON.stringify(envelope, null, 2), envelope };
}

/**
 * Decrypts a passphrase-locked .airlock.enc file strictly in browser RAM.
 * Wrong passphrases or 1-byte ciphertext edits fail AES-GCM authentication immediately.
 */
export async function decryptVaultFromFileJson(
  rawFileText: string,
  passphrase: string
): Promise<DecryptedVaultBundle> {
  let envelope: EncryptedVaultEnvelope;
  try {
    envelope = JSON.parse(rawFileText) as EncryptedVaultEnvelope;
  } catch {
    throw new Error("Selected file is not valid JSON (.airlock.enc).");
  }

  if (
    envelope.format !== "AirlockAI.EncryptedVault.v1" ||
    envelope.cipher !== "AES-256-GCM" ||
    !envelope.saltBase64 ||
    !envelope.ivBase64 ||
    !envelope.ciphertextBase64
  ) {
    throw new Error("Unsupported vault file format. Expected AirlockAI.EncryptedVault.v1.");
  }

  const trimmedPass = passphrase.trim();
  if (trimmedPass.length < 6) {
    throw new Error("Enter the vault passphrase (at least 6 characters) before restoring.");
  }

  const salt = base64ToBytes(envelope.saltBase64);
  const iv = base64ToBytes(envelope.ivBase64);
  const ciphertext = base64ToBytes(envelope.ciphertextBase64);
  const key = await deriveAesKeyFromPassphrase(
    trimmedPass,
    salt,
    typeof envelope.iterations === "number" ? envelope.iterations : 100_000
  );

  try {
    const plainBuf = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    const decoded = new TextDecoder().decode(plainBuf);
    const bundle = JSON.parse(decoded) as DecryptedVaultBundle;
    if (bundle.vaultVersion !== "airlock.vault.v1" || !Array.isArray(bundle.entries)) {
      throw new Error("Decrypted vault payload failed schema validation.");
    }
    return bundle;
  } catch (err) {
    if (err instanceof Error && err.message.includes("schema validation")) {
      throw err;
    }
    throw new Error(
      "DECRYPTION FAILED — Wrong passphrase or tampered .airlock.enc ciphertext (AES-GCM auth tag mismatch)."
    );
  }
}

export function rehydrateWithEntries(
  sanitizedText: string,
  entries: ReadonlyArray<VaultEntry>
): string {
  let out = sanitizedText;
  for (const entry of entries) {
    if (entry.category === "CANARY") continue;
    out = out.split(entry.token).join(entry.original);
  }
  return out;
}
