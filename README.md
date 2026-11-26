# AirlockAI

Two-Party Zero-Knowledge Deal Room & Hybrid AI Privacy Appliance (Web PWA, Chrome Side Panel, and Native Android).

- Live Web PWA: https://airlockai-2026-alex.web.app
- Devpost Submission: https://devpost.com/software/airlockai
- Shared Protocol Spec: spec/vectors.json (airlock.v1)
- License: Apache-2.0

## 2-Minute Judge Quickstart (Zero API Keys Required)

### Option A: Live Web Demo (60 Seconds)
1. Open https://airlockai-2026-alex.web.app (lands directly on the Zero-Knowledge Deal Room using synthetic corporate data by design: Elena Vance at Helios Robotics Corp verifying Apex Foundry LLC wire invoice against a 1.45M MSA).
2. Click Run Shared-Vault Deal Room Airlock (0B Sent), copy the 64-char SHA-256 attestation, and click Run Zero-Knowledge Oracle Audit (Function Calling) to catch the 3-way wire fraud (+45% cap breach, +46 days past deadline, GB vs DE IBAN mismatch) with 0B raw PII sent.
3. Expand Zero-Knowledge Thinking Inspector to verify 0 Raw Secrets in Thoughts.
4. Open Tab 2 to test stackable 3G + Low Battery Adaptive Routing (Score 0/100) and Run Full 7/7 Defense Gauntlet (4 client aborts + 3 live Firestore PERMISSION_DENIED rejections). Open Tab 3 to verify the SHA-256 Merkle Tree + non-extractable IndexedDB ECDSA P-256 proof offline.

### Option B: Run Local Cryptographic Proofs (Zero Cloud Keys Needed)
npm install && npm run build:core && npm run test:core

## Transparent Proof & Hardware Boundaries
- Verified live in production (0B raw PII sent): Zero-Knowledge Deal Room (4 local RAM oracles, optional Laplace epsilon-DP), Gemini Thinking Inspector (LOW/MEDIUM/HIGH), multi-page PDF pixel redactor + flattened 0-text PDF re-check, streaming Token-Boundary FSM, Policy-as-Code Studio, 7/7 Defense Gauntlet, hardened firestore.rules (email, SSN, card, IBAN, API keys), Air-Gap queue/sync, SHA-256 Merkle + IndexedDB ECDSA P-256 (7ms tamper test), Chrome Side Panel Replace on Page, Audio PCM WAV demo, Multilingual DE/FR/ES, and WebAuthn PRF HKDF/AES-GCM vault sealing + 5-check self-test (8ms).
- Hardware limits: Dev laptop (8GB RAM, Ivy Bridge) lacks Chrome Nano 16GB RAM / 4GB VRAM, proving our SDK #10635 guard and PREFER_ON_DEVICE cloud fallback live. Native Android Kotlin parity runs in GitHub Actions CI JUnit 4 (physical AICore phone Nano not filmed).

## Build & Audit Commands
npm run build:core && npm run test:core
npm run build --workspace=@airlock/web
npm run build:extension
cd apps/android && gradle testDebugUnitTest
./scripts/pre-submission-audit.sh
