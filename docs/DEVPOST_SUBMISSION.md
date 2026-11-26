# AirlockAI - Devpost Submission (#BuildHybridAI 2026)

## Tagline
Two-party Zero-Knowledge Deal Room & hybrid AI firewall

## Links
- Live Demo: https://airlockai-2026-alex.web.app
- Repository (Apache-2.0): https://github.com/alexowoade/airlockai

## Inspiration & What It Does
Standard single-document PII redaction breaks two-party deal verification and can be bypassed by reformatted digits, Base64, hidden PDF text layers, or prompt injection. Modeled on a synthetic corporate scenario (Elena Vance at Helios Robotics Corp checking Apex Foundry LLC 2.1M wire invoice against a 1.45M MSA), AirlockAI seals files locally in 3 steps (Seal -> Check -> Audit), lets Cloud Gemini invoke 4 local browser-RAM Zero-Knowledge Oracles (compare_currency_tokens, compare_date_tokens, verify_iban_jurisdiction, check_token_identity) with optional Laplace epsilon-DP, audits Gemini thinking summaries for 0 raw secrets, flattens PDFs to 0 recoverable text chars, streams Token-Boundary FSM diffs, enforces a 7/7 live client + Firestore PERMISSION_DENIED gauntlet, signs SHA-256 Merkle proofs with non-extractable IndexedDB ECDSA P-256, and seals .airlock.enc vaults via WebAuthn PRF + HKDF-SHA256 + AAD AES-256-GCM.

## Hardware Transparency & How We Built It
Built across packages/core, apps/web, apps/extension (MV3 Side Panel), and apps/android (Kotlin + Jetpack Compose) sharing spec/vectors.json (airlock.v1). Dev laptop (8GB RAM, Ivy Bridge) fails Chrome 16GB RAM / 4GB VRAM Nano requirements, proving our SDK #10635 guard and PREFER_ON_DEVICE cloud fallback live; Android Kotlin parity is tested in GitHub Actions CI JUnit 4 (physical AICore phone Nano not filmed).

## Built With
TypeScript, Kotlin, React, Vite, pdfjs-dist, Jetpack Compose, Chrome Manifest V3, Firebase AI Logic, Gemini Nano, Gemini 3.5 Flash Lite, Function Calling, Streaming, Structured JSON, Server Prompt Templates, Remote Config, App Check Fraud Defense, Firestore, Auth, Hosting, Chrome LanguageDetector/Translator, WebAuthn PRF, WebCrypto (ECDSA P-256, HKDF-SHA256, PBKDF2-SHA256, AES-256-GCM), IndexedDB, Vitest, fast-check, JUnit 4
