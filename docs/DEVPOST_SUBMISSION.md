# AirlockAI — Devpost Submission Copy (#BuildHybridAI 2026)

## Tagline (Max 60 chars)
Zero-leakage hybrid document auditor for Web, Chrome & Android

## Links
- **Live Demo URL:** https://airlockai-2026-alex.web.app
- **Public Repository (Apache 2.0):** https://github.com/alexowoade/airlockai
- **Devpost Draft:** https://devpost.com/software/airlockai

---

## Inspiration
Legal teams, clinics, and finance operators want cloud-scale Gemini reasoning on NDAs, medical bills, and vendor wire invoices, yet uploading raw documents exposes SSNs, bank IBANs, API credentials, diagnoses, and deal terms to third-party servers. Relying solely on an on-device prompt that says "please strip PII" fails in practice: models miss tokens, reformat digits, or get bypassed by prompt injection and encoded exfiltration. We built **AirlockAI** to combine Firebase AI Logic hybrid inference with a mathematically verified, deterministic zero-leakage boundary that works across Web, Chrome Side Panel, and Native Android.

## What it does
AirlockAI turns any browser tab, desktop browser, or Android device into a local-first privacy airlock:
1. **3-Gate Local Airlock (0 bytes sent):** Scans text or document images locally through deterministic regex, Luhn card validation, and Shannon-entropy secret detection (Gate 1), followed by guarded `ONLY_ON_DEVICE` Gemini Nano semantic and multimodal extraction (Gate 2) plus local HTML5 Canvas pixel redaction.
2. **6-Vector Adversarial Pre-Flight Firewall (Gate 3):** Verifies the outbound staging skeleton against every secret in the local AES-256-GCM vault across six leak vectors (exact/case-insensitive, collapsed alphanumeric, partial surname/trailing-6 digits, Base64/Hex/URL exfiltration, Unicode NFKC/zero-width smuggling, and a hidden per-session Canary Token Trap).
3. **Interactive Red-Team Attack Lab & Live Wire Tap:** Judges can inject live adversarial leaks (missed entity, Base64 exfiltration, canary prompt injection, zero-width smuggling) and watch Gate 3 hard-abort with **0 bytes transmitted**, while a live `window.fetch` Wire Tap inspects every actual outbound HTTP request to Google APIs.
4. **Hybrid Triage & Locked Cloud Audits:** Runs `PREFER_ON_DEVICE` triage with honest `ON_DEVICE` vs `IN_CLOUD` telemetry, then audits the verified placeholder skeleton via **Firebase Server Prompt Templates** (`airlock-nda-v1-0-0`, `airlock-hipaa-v1-0-0`, `airlock-invoice-v1-0-0`) controlled by **Firebase Remote Config** (`airlock_policy`).
5. **Local Zero-Knowledge Re-Hydration & Cross-Device Ledger:** Re-hydrates real names and figures strictly client-side with a 1-click diff toggle ("Showing What Cloud Saw" vs "Showing Local Re-Hydrated"), and syncs an append-only, hash-chained SHA-256 attestation receipt to Cloud Firestore protected by server-side `hasNoRawPii` security rules.

## How we built it
AirlockAI is architected as a multi-platform monorepo sharing one canonical protocol (`spec/vectors.json`, `airlock.v1`):
- **Core Cryptographic Engine (`packages/core`):** Zero-dependency TypeScript engine using compile-time branded types (`RawDocument` vs `VerifiedSanitizedPayload`), WebCrypto AES-256-GCM local vault encryption, Shannon-entropy scanning, and a 6-vector pre-flight verifier.
- **Web PWA (`apps/web`):** React 19 + TypeScript + Vite 6 deployed live on Firebase Hosting (`https://airlockai-2026-alex.web.app`). Integrates Firebase AI Logic (`ONLY_ON_DEVICE`, `PREFER_ON_DEVICE`, `ONLY_IN_CLOUD`, `getTemplateGenerativeModel`), Firebase Remote Config, Anonymous Auth, Cloud Firestore, and Firebase App Check via Fraud Defense (`ReCaptchaEnterpriseProvider`).
- **Chrome Side Panel Extension (`apps/extension`):** Manifest V3 Side Panel extension reusing `@airlock/core` directly, with right-click context menu selection scrubbing, least-privilege permissions, and an MV3-CSP-safe App Check `CustomProvider`.
- **Native Android App (`apps/android`):** Kotlin + Jetpack Compose app implementing the exact same branded types (`@JvmInline value class` + `internal constructor`), AES-256-GCM vault, 6-vector firewall, and Firebase AI Logic (`firebase-bom:35.2.0`, `firebase-ai:18.2.0`, `firebase-ai-ondevice:16.0.0-beta08` with `OnDeviceModelOption.PREVIEW` and `templateGenerativeModel()`), syncing to the same zero-PII Firestore ledger.

## Challenges we ran into
- **Preventing Silent Cloud Fallback (`firebase-js-sdk#10635`):** Calling `InferenceMode.ONLY_ON_DEVICE` on browsers lacking `window.LanguageModel` can fall back unexpectedly instead of throwing. We implemented an explicit pre-SDK runtime guard verifying `LanguageModel.availability() === "available"` before invoking `ONLY_ON_DEVICE`, ensuring raw PII never leaves unsupported browsers.
- **MV3 Content Security Policy vs App Check:** Chrome Manifest V3 blocks remote script injection required by standard reCAPTCHA scripts inside extensions. We engineered a dedicated MV3-compliant `CustomProvider` initialization path for the Side Panel while using Fraud Defense (`ReCaptchaEnterpriseProvider`) on the hosted Web PWA.
- **Cross-Platform Cryptographic & Redaction Parity:** Ensuring identical span overlap resolution, Luhn validation, Shannon entropy thresholds, Unicode NFKC normalization, and SHA-256 receipt digests across TypeScript and Kotlin required unifying both implementations against a single shared test suite (`spec/vectors.json`).

## Accomplishments that we're proud of
- **16/16 Automated Proofs Green:** `@airlock/core` passes all 11 shared golden parity vectors (including offline non-Nano NER parity) plus a **1,000-run `fast-check` property-based fuzzing proof** asserting zero leaks across randomized contracts containing Luhn-valid cards, SSNs, emails, phones, and currency values.
- **Defense-in-Depth Down to the Database Rules:** Deployed live `firestore.rules` with server-side `hasNoRawPii` regex assertions and `allow update, delete: if false`, making raw PII persistence structurally impossible even from a modified client.
- **True 3-Surface Multi-Platform Architecture:** Shipped a live hosted Web PWA, an unpacked MV3 Chrome Side Panel Extension, and a Native Kotlin Android app verified by cross-platform CI.

## What we learned
Hybrid AI shines when on-device and cloud models have strictly separated security responsibilities rather than duplicating the same chat flow. Pairing local Gemini Nano extraction with deterministic cryptographic verification and locked Firebase Server Prompt Templates turns a privacy liability into an auditable workflow.

## What's next for AirlockAI
- Full PDF multi-page OCR and bounding-box Canvas redaction natively inside the browser and Android CameraX capture flow.
- Hardware-backed passkey wrapping for persistent cross-session local AES-256-GCM vaults.
- Enterprise SOC2/HIPAA export bundles combining the Firestore hash-chained SHA-256 receipts with downloadable zero-PII verification reports.

## Built With
TypeScript, Kotlin, React, Vite, Jetpack Compose, Chrome Extensions (Manifest V3), Firebase AI Logic, Gemini Nano, Gemini 3.5 Flash Lite, Firebase Server Prompt Templates, Firebase Remote Config, Firebase App Check (Fraud Defense / reCAPTCHA Enterprise), Cloud Firestore, Firebase Auth, Firebase Hosting, WebCrypto (AES-256-GCM), Vitest, fast-check, JUnit 4, GitHub Actions
