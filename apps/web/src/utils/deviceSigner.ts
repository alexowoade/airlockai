import { sha256Hex } from "@airlock/core";

export interface DeviceKeySummary {
  readonly kid: string;
  readonly algorithm: "ECDSA-P256-SHA256";
  readonly storage: "INDEXEDDB_NON_EXTRACTABLE" | "MEMORY_NON_EXTRACTABLE";
  readonly privateKeyExtractable: boolean;
  readonly publicKeyJwk: JsonWebKey;
  readonly createdAtIso: string;
}

export interface DeviceSignatureBlock {
  readonly algorithm: "ECDSA-P256-SHA256";
  readonly kid: string;
  readonly signedAtIso: string;
  readonly publicKeyJwk: JsonWebKey;
  readonly signatureBase64: string;
}

interface StoredDeviceKeyRecord {
  readonly id: string;
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicKeyJwk: JsonWebKey;
  readonly createdAtIso: string;
}

const DB_NAME = "airlockai-crypto-db";
const STORE_NAME = "deviceKeys";
const KEY_ID = "primary-ecdsa-p256-v1";

let cachedRecord: StoredDeviceKeyRecord | null = null;
let cachedStorage: "INDEXEDDB_NON_EXTRACTABLE" | "MEMORY_NON_EXTRACTABLE" =
  "MEMORY_NON_EXTRACTABLE";

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Deterministic recursive key-sorted canonical JSON for signature stability across platforms.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`)
    .join(",")}}`;
}

export async function computePublicKeyKid(jwk: JsonWebKey): Promise<string> {
  const thumbprintInput = JSON.stringify({
    crv: jwk.crv ?? "",
    kty: jwk.kty ?? "",
    x: jwk.x ?? "",
    y: jwk.y ?? "",
  });
  const digest = await sha256Hex(thumbprintInput);
  return `ecdsa-p256-${digest.slice(0, 16)}`;
}

function openKeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB open failed."));
  });
}

async function readKeyFromDb(): Promise<StoredDeviceKeyRecord | null> {
  if (typeof indexedDB === "undefined") return null;
  try {
    const db = await openKeyDb();
    return await new Promise<StoredDeviceKeyRecord | null>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(KEY_ID);
      req.onsuccess = () => resolve((req.result as StoredDeviceKeyRecord | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function writeKeyToDb(rec: StoredDeviceKeyRecord): Promise<boolean> {
  if (typeof indexedDB === "undefined") return false;
  try {
    const db = await openKeyDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(rec);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Loads or generates a non-extractable WebCrypto ECDSA P-256 device signing keypair
 * persisted in IndexedDB (private key bytes cannot be exported by JavaScript).
 */
async function getOrCreateDeviceKeyRecord(): Promise<StoredDeviceKeyRecord> {
  if (cachedRecord) return cachedRecord;

  const existing = await readKeyFromDb();
  if (existing && existing.privateKey && existing.publicKeyJwk) {
    cachedRecord = existing;
    cachedStorage = "INDEXEDDB_NON_EXTRACTABLE";
    return existing;
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"]
  );
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const kid = await computePublicKeyKid(publicKeyJwk);
  const record: StoredDeviceKeyRecord = {
    id: KEY_ID,
    kid,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyJwk,
    createdAtIso: new Date().toISOString(),
  };

  const persisted = await writeKeyToDb(record);
  cachedRecord = record;
  cachedStorage = persisted ? "INDEXEDDB_NON_EXTRACTABLE" : "MEMORY_NON_EXTRACTABLE";
  return record;
}

export async function getDeviceKeySummary(): Promise<DeviceKeySummary> {
  const rec = await getOrCreateDeviceKeyRecord();
  return {
    kid: rec.kid,
    algorithm: "ECDSA-P256-SHA256",
    storage: cachedStorage,
    privateKeyExtractable: rec.privateKey.extractable,
    publicKeyJwk: rec.publicKeyJwk,
    createdAtIso: rec.createdAtIso,
  };
}

export async function signCanonicalPayload(
  payload: Record<string, unknown>
): Promise<DeviceSignatureBlock> {
  const rec = await getOrCreateDeviceKeyRecord();
  const canonical = canonicalizeJson(payload);
  const encoded = new TextEncoder().encode(canonical);
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    rec.privateKey,
    encoded
  );
  return {
    algorithm: "ECDSA-P256-SHA256",
    kid: rec.kid,
    signedAtIso: new Date().toISOString(),
    publicKeyJwk: rec.publicKeyJwk,
    signatureBase64: bytesToBase64(new Uint8Array(sigBuf)),
  };
}

export async function verifyCanonicalPayloadSignature(
  payload: Record<string, unknown>,
  sig: DeviceSignatureBlock
): Promise<{ readonly ok: boolean; readonly detail: string }> {
  try {
    if (sig.algorithm !== "ECDSA-P256-SHA256") {
      return { ok: false, detail: `Unsupported signature algorithm: ${sig.algorithm}` };
    }
    const expectedKid = await computePublicKeyKid(sig.publicKeyJwk);
    if (expectedKid !== sig.kid) {
      return {
        ok: false,
        detail: `KEY FINGERPRINT MISMATCH: kid (${sig.kid}) != JWK thumbprint (${expectedKid}).`,
      };
    }

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      sig.publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    const canonical = canonicalizeJson(payload);
    const encoded = new TextEncoder().encode(canonical);
    const sigBytes = base64ToBytes(sig.signatureBase64);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      sigBytes,
      encoded
    );

    return {
      ok: valid,
      detail: valid
        ? `ECDSA P-256 SIGNATURE VERIFIED (kid ${sig.kid} · non-repudiation intact).`
        : `ECDSA P-256 SIGNATURE INVALID — Payload or signature bytes were altered after signing.`,
    };
  } catch (err) {
    return {
      ok: false,
      detail: `ECDSA verification error: ${err instanceof Error ? err.message : "malformed key/signature"}`,
    };
  }
}
