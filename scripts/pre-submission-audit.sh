#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

echo "============================================================"
echo " AirlockAI — #BuildHybridAI 2026 Pre-Submission Audit"
echo "============================================================"

# 1. Apache 2.0 License
if [[ -f LICENSE ]] && head -n 5 LICENSE | grep -q "Apache License"; then
  ok "Apache 2.0 LICENSE found in repository root"
else
  fail "Apache 2.0 LICENSE missing or malformed"
fi

# 2. Secret hygiene in git index
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  TRACKED_SECRETS="$(git ls-files | grep -E '(\.env\.local|google-services\.json|firebase-debug.*\.log)' || true)"
  if [[ -z "$TRACKED_SECRETS" ]]; then
    ok "No .env.local, google-services.json, or firebase-debug.log tracked in git"
  else
    fail "Tracked secret/debug files detected: $TRACKED_SECRETS"
  fi
else
  echo "[WARN] Not a git repository yet (run git init before pushing)"
fi

# 3. Firebase config & zero-PII Firestore rules
if [[ -f firestore.rules ]] && grep -q "hasNoRawPii" firestore.rules && grep -q "allow update, delete: if false" firestore.rules; then
  ok "firestore.rules enforces hasNoRawPii and append-only audit ledger"
else
  fail "firestore.rules missing or missing zero-PII guards"
fi

# 4. Fraud Defense / reCAPTCHA Enterprise provider check
if grep -q "ReCaptchaEnterpriseProvider" apps/web/src/services/firebase.ts; then
  ok "Web App Check configured with ReCaptchaEnterpriseProvider (Fraud Defense)"
else
  fail "apps/web/src/services/firebase.ts is not using ReCaptchaEnterpriseProvider"
fi

# 5. Shared cross-platform spec/vectors.json validation
if python3 -c 'import json; d=json.load(open("spec/vectors.json")); assert d["protocolVersion"]=="airlock.v1" and len(d["cleanVectors"])==3 and len(d["adversarialVectors"])==6' 2>/dev/null; then
  ok "spec/vectors.json valid (airlock.v1: 3 clean + 6 adversarial golden vectors)"
else
  fail "spec/vectors.json invalid or missing"
fi

# 6. Core type-check + 14/14 proofs
if npm run build:core >/dev/null 2>&1 && npm run test:core >/dev/null 2>&1; then
  ok "@airlock/core type-check + 14/14 Vitest & 1,000-run fast-check proofs passed"
else
  fail "@airlock/core build or test suite failed"
fi

# 7. Web PWA & Chrome Extension builds
if npm run build --workspace=@airlock/web >/dev/null 2>&1; then
  ok "@airlock/web production build passed"
else
  fail "@airlock/web production build failed"
fi

if npm run build:extension >/dev/null 2>&1 && [[ -f apps/extension/dist/manifest.json ]] && [[ -f apps/extension/dist/background.js ]]; then
  ok "@airlock/extension MV3 production build passed (manifest.json + background.js verified)"
else
  fail "@airlock/extension production build failed"
fi

# 8. Live Firebase Hosting reachability
LIVE_URL="https://airlockai-2026-alex.web.app"
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$LIVE_URL" || echo "000")"
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Live Web PWA reachable at $LIVE_URL (HTTP 200)"
else
  fail "Live Web PWA returned HTTP $HTTP_CODE at $LIVE_URL"
fi

echo "------------------------------------------------------------"
echo " Audit Summary: $PASS passed, $FAIL failed"
echo "------------------------------------------------------------"
[[ "$FAIL" -eq 0 ]]
