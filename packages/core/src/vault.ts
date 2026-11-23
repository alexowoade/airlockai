import type { DetectedSpan, EntityCategory, RawDocument, VaultEntry } from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export interface EncryptedVaultBlob {
  readonly alg: "AES-256-GCM";
  readonly ivBase64: string;
  readonly ciphertextBase64: string;
}

export class AirlockVault {
  private readonly byOriginal = new Map<string, VaultEntry>();
  private readonly byToken = new Map<string, VaultEntry>();
  private readonly categoryCounters = new Map<EntityCategory, number>();
  public readonly canaryToken: string;

  constructor(customCanary?: string) {
    this.canaryToken = customCanary ?? AirlockVault.generateCanary();
    this.register(this.canaryToken, "CANARY", "SYSTEM_CANARY");
  }

  private static generateCanary(): string {
    const bytes = new Uint8Array(9);
    globalThis.crypto.getRandomValues(bytes);
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return `AIRLOCK-CANARY-${hex}`;
  }

  public register(
    original: string,
    category: EntityCategory,
    detectedBy: VaultEntry["detectedBy"]
  ): VaultEntry {
    const trimmed = original.trim();
    const key = `${category}::${trimmed.toLowerCase()}`;
    const existing = this.byOriginal.get(key);
    if (existing) return existing;

    const nextIndex = (this.categoryCounters.get(category) ?? 0) + 1;
    this.categoryCounters.set(category, nextIndex);
    const token = `[${category}_${nextIndex}]`;

    const entry: VaultEntry = {
      token,
      original: trimmed,
      category,
      detectedBy,
    };
    this.byOriginal.set(key, entry);
    this.byToken.set(token, entry);
    return entry;
  }

  /** Applies resolved spans from Gate 1 and Gate 2 to produce a candidate sanitized string */
  public redactSpans(rawDoc: RawDocument, spans: ReadonlyArray<DetectedSpan>): string {
    if (spans.length === 0) return String(rawDoc);

    let out = "";
    let cursor = 0;
    for (const span of spans) {
      if (span.start < cursor) continue;
      const entry = this.register(span.text, span.category, span.detectedBy);
      out += rawDoc.slice(cursor, span.start) + entry.token;
      cursor = span.end;
    }
    out += rawDoc.slice(cursor);
    return out;
  }

  /** Re-hydrates cloud output strictly locally in browser RAM */
  public rehydrate(sanitizedText: string): string {
    let result = sanitizedText;
    for (const [token, entry] of this.byToken.entries()) {
      if (entry.category === "CANARY") continue;
      result = result.split(token).join(entry.original);
    }
    return result;
  }

  public getEntries(includeCanary = false): ReadonlyArray<VaultEntry> {
    return Array.from(this.byToken.values()).filter(
      (entry) => includeCanary || entry.category !== "CANARY"
    );
  }

  /** Encrypts the local vault with a non-extractable ephemeral AES-256-GCM key */
  public static async generateLocalKey(): Promise<CryptoKey> {
    return globalThis.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  public async exportEncrypted(key: CryptoKey): Promise<EncryptedVaultBlob> {
    const iv = new Uint8Array(12);
    globalThis.crypto.getRandomValues(iv);
    const plaintext = encoder.encode(JSON.stringify(this.getEntries(true)));
    const encrypted = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      plaintext
    );
    return {
      alg: "AES-256-GCM",
      ivBase64: bytesToBase64(iv),
      ciphertextBase64: bytesToBase64(new Uint8Array(encrypted)),
    };
  }

  public static async decryptBlob(
    blob: EncryptedVaultBlob,
    key: CryptoKey
  ): Promise<ReadonlyArray<VaultEntry>> {
    const iv = base64ToBytes(blob.ivBase64);
    const ciphertext = base64ToBytes(blob.ciphertextBase64);
    const decrypted = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return JSON.parse(decoder.decode(decrypted)) as VaultEntry[];
  }
}
