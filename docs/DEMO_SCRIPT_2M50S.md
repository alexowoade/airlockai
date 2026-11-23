# AirlockAI — 2:50 Hackathon Demo Video Script

**Hard Target:** 2 minutes 50 seconds (strictly under the 3:00 limit).
**Resolution:** 1920x1080 at 110% browser zoom so badges, SHA-256 receipts, and Wire Tap payloads are crisp on YouTube.

---

## Pre-Recording Setup (60 Seconds Before Rolling)
1. Open **`https://airlockai-2026-alex.web.app`** in Chrome Desktop.
2. Confirm top header shows **`ONLINE`**, **`SDK #10635 Guard Active`**, and **`Firebase AI Logic: CONNECTED`** (plus `Gemini Nano: AVAILABLE` if enabled on your machine).
3. Have a second regular webpage tab open with a sample contract paragraph containing an email and dollar amount, with the **AirlockAI Side Panel** extension already loaded unpacked from `apps/extension/dist`.
4. Have a clean terminal tab ready in `~/airlockai/airlockai` to run `npm run test:core` (takes 1.75s) or show your green GitHub Actions CI run.

---

## Shot-by-Shot Script (0:00 – 2:50)

### 0:00 – 0:20 | The Hook & Architecture (20s)
- **Screen:** `https://airlockai-2026-alex.web.app` with the Synthetic M&A NDA loaded (showing SSN `912-45-6789`, email, `$1,450,000.00`, API key `sk-live-...`, and `Project Obsidian`).
- **Voiceover:**
  > "Every legal, medical, and finance team wants cloud Gemini reasoning on sensitive documents, but pasting raw contracts into the cloud leaks PII and secrets. Simply asking an on-device model to remove PII is probabilistic and breakable. Meet **AirlockAI**: a cross-platform hybrid AI security appliance for Web, Chrome Extension, and Android that mathematically enforces zero leakage before a single byte touches the cloud."

### 0:20 – 0:50 | 3-Gate Local Airlock & Multimodal Pixel Redaction (30s)
- **Action:**
  1. Click **Run Local Airlock (Gate 1 + Nano Gate 2 + Gate 3)**.
  2. Point to the green **6/6 Firewall Checks Passed** badge, SHA-256 Attestation Receipt, and **`0B`** sent in the Live Wire Tap.
  3. Click **Medical Bill PNG** -> **Run Local Airlock** to flash the on-device HTML5 Canvas black redaction overlay (`REDACTED ON-DEVICE — RAW PIXELS NEVER TRANSMITTED`).
- **Voiceover:**
  > "Gate 1 runs deterministic regex, Luhn card checks, and Shannon entropy secret scanning in under 5 milliseconds. Gate 2 runs Gemini Nano strictly on-device via Firebase AI Logic `ONLY_ON_DEVICE`, wrapped in our runtime guard for SDK issue 10635 so unsupported browsers can never silently fall back to the cloud. Even document images are redacted locally on Canvas. Gate 3 verifies six leak vectors and mints a SHA-256 attestation receipt with zero bytes transmitted."

### 0:50 – 1:25 | Live Red-Team Attack Lab (35s)
- **Action:**
  1. Switch back to **Synthetic M&A NDA** and run **Run Local Airlock**.
  2. Click **Base64 Exfil**, then **Canary Injection**, then **Zero-Width Smuggle** in the Red-Team Attack Lab.
  3. Hover over the red **`FIREWALL TRIPPED — 0 BYTES TRANSMITTED`** banner and the `BLOCKED` entries in the Live Wire Tap.
- **Voiceover:**
  > "Don't take our word for it—let's attack AirlockAI live. First, a Base64 exfiltration attempt: blocked before fetch, zero bytes sent. Next, a prompt injection forcing our hidden session canary token into the buffer: tripped immediately by the Canary Trap. Finally, zero-width Unicode smuggling: normalized and blocked. Because our cloud adapter only compiles with a branded `VerifiedSanitizedPayload`, raw PII cannot reach the network."

### 1:25 – 2:05 | Hybrid Offline Triage, Server Prompt Templates & Local Re-Hydration (40s)
- **Action:**
  1. Click **Offline Triage (PREFER_ON_DEVICE)** and highlight the `ON_DEVICE` / `IN_CLOUD` badge + latency.
  2. Click **Deep Cloud Audit (Server Template)** -> point directly to the **`HTTP_WIRE_OUTBOUND`** event in the Live Wire Tap showing only `[EMAIL_1]`, `[SSN_1]`, `[CURRENCY_1]`, `[API_SECRET_1]` crossing the wire.
  3. Click the diff toggle (**Showing What Cloud Saw** <-> **Showing Local Re-Hydrated**) to watch real names and figures snap back locally from the AES-256-GCM vault.
  4. Scroll briefly to the **Firestore Zero-PII Audit Ledger** entry synced via Anonymous Auth + App Check (Fraud Defense).
- **Voiceover:**
  > "Once verified, `PREFER_ON_DEVICE` handles instant triage with honest inference-source telemetry. Then our Deep Cloud Audit invokes locked Firebase Server Prompt Templates backed by Remote Config policies and App Check Fraud Defense. Look at the live HTTP Wire Tap: the cloud only ever saw placeholder tokens. Locally, our AES-256-GCM vault re-hydrates the full redline report, and only a hash-chained, zero-PII receipt syncs to Firestore, protected by server-side regex security rules."

### 2:05 – 2:35 | Multi-Platform Proof: Chrome Side Panel + Android Kotlin Parity (30s)
- **Action:**
  1. Switch to your second Chrome tab, highlight a sensitive paragraph, right-click **AirlockAI: Scrub & Audit Selection**, and click **Run 3-Gate Local Airlock (0B Sent)** inside the MV3 Side Panel.
  2. Switch to your terminal (or GitHub Actions CI tab) and run `npm run test:core` showing **14/14 passing** (10 shared `spec/vectors.json` golden vectors + 1,000-run `fast-check` zero-leak proof) alongside the Kotlin Android JUnit parity suite.
- **Voiceover:**
  > "The exact same `@airlock/core` engine powers our Manifest V3 Chrome Side Panel so users can scrub live emails or contracts in place. And our native Kotlin Android app implements the same protocol using `firebase-ai-ondevice` with `OnDeviceModelOption.PREVIEW` and the same Firestore ledger. Both TypeScript and Kotlin run against one shared `spec/vectors.json` suite, backed by 1,000 randomized `fast-check` fuzzing proofs."

### 2:35 – 2:50 | Closing (15s)
- **Screen:** Back on `https://airlockai-2026-alex.web.app` showing the clean UI + GitHub repo link.
- **Voiceover:**
  > "Web PWA, Chrome Extension, and Native Android. One cryptographic boundary, zero raw PII in the cloud, and full Firebase AI Logic hybrid power. Try AirlockAI live today—thank you."
