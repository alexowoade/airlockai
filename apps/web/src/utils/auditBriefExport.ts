import type { AirlockVault, PolicyProfile, VerifiedSanitizedPayload } from "@airlock/core";
import type { CloudAuditOutput } from "../services/airlockPipeline.js";
import { triggerLocalDownload } from "./chainVerifier.js";

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Exports a print-to-PDF ready HTML compliance brief in two strict modes:
 * - "external": Zero raw PII (redacted placeholders only + SHA-256 attestation footer)
 * - "internal": Locally re-hydrated in browser RAM (0B raw secrets ever sent to cloud)
 */
export function exportExecutiveAuditBrief(params: {
  mode: "external" | "internal";
  policyProfile: PolicyProfile;
  projectId: string;
  verified: VerifiedSanitizedPayload;
  cloudOut: CloudAuditOutput;
  vault: AirlockVault;
}): { readonly filename: string } {
  const isInternal = params.mode === "internal";
  const renderVal = (s: string) => escapeHtml(isInternal ? params.vault.rehydrate(s) : s);

  const badgeText = isInternal
    ? "INTERNAL RE-HYDRATED BRIEF (RESTORED LOCALLY IN RAM)"
    : "EXTERNAL ZERO-PII BRIEF (0 RAW SECRETS — SAFE TO SHARE)";
  const badgeColor = isInternal ? "#059669" : "#0284c7";

  const bodyHtml = params.cloudOut.structured
    ? `
      <div class="box">
        <div class="meta"><strong>Overall Risk Level:</strong> ${escapeHtml(params.cloudOut.structured.overallRiskLevel)}</div>
        <p>${renderVal(params.cloudOut.structured.executiveSummary)}</p>
      </div>
      <h2>Structured Clause Redlines</h2>
      ${params.cloudOut.structured.clauses
        .map(
          (c, i) => `
          <div class="clause">
            <div class="clause-head">
              <strong>#${i + 1} ${escapeHtml(c.clauseTitle)}</strong>
              <span class="sev">${escapeHtml(c.severity)}</span>
            </div>
            <p>${renderVal(c.issue)}</p>
            ${c.quotedExcerpt ? `<div class="excerpt"><strong>Flagged Excerpt:</strong> ${renderVal(c.quotedExcerpt)}</div>` : ""}
            <div class="proposal"><strong>Redline Counter-Proposal:</strong> ${renderVal(c.redlineCounterProposal)}</div>
          </div>`
        )
        .join("")}
    `
    : `<pre class="box">${renderVal(params.cloudOut.sanitizedMarkdown)}</pre>`;

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>AirlockAI Compliance Brief (${escapeHtml(params.mode.toUpperCase())})</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; max-width: 860px; margin: 32px auto; padding: 0 20px; line-height: 1.5; }
    .banner { display: inline-block; background: ${badgeColor}; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; letter-spacing: 0.03em; }
    h1 { margin: 10px 0 4px; font-size: 24px; }
    h2 { margin-top: 24px; font-size: 17px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
    .sub { color: #475569; font-size: 13px; margin-bottom: 18px; }
    .box, .clause { border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #f8fafc; }
    .clause-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .sev { font-family: monospace; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; background: #fee2e2; color: #991b1b; }
    .excerpt { border-left: 3px solid #f59e0b; padding: 6px 10px; background: #fffbeb; margin: 8px 0; font-size: 13px; }
    .proposal { border-left: 3px solid #10b981; padding: 6px 10px; background: #ecfdf5; margin-top: 8px; font-size: 13px; }
    .footer { margin-top: 26px; padding-top: 12px; border-top: 1px solid #cbd5e1; font-family: monospace; font-size: 11px; color: #334155; word-break: break-all; }
    pre { white-space: pre-wrap; font-family: ui-monospace, Menlo, monospace; font-size: 13px; }
  </style>
</head>
<body>
  <div class="banner">${badgeText}</div>
  <h1>AirlockAI Executive Compliance Brief</h1>
  <div class="sub">
    Policy: <strong>${escapeHtml(params.policyProfile)}</strong> ·
    Engine: <strong>${escapeHtml(params.cloudOut.mode)}</strong> ·
    Generated: <strong>${escapeHtml(new Date().toISOString())}</strong> ·
    Raw PII Sent to Cloud: <strong>0 Bytes</strong>
  </div>
  ${bodyHtml}
  <div class="footer">
    <div><strong>Cryptographic Airlock Attestation (airlock.v1)</strong></div>
    <div>Firebase Project: ${escapeHtml(params.projectId)}</div>
    <div>Contains Raw PII: ${isInternal ? "TRUE (Internal Local Copy Only)" : "FALSE (Zero-PII External Copy)"}</div>
    <div>Firewall Checks: ${params.verified.receipt.checksPassed}/6 Passed · Entities Redacted: ${params.verified.receipt.redactedCount}</div>
    <div>receiptSha256: ${escapeHtml(params.verified.receipt.receiptSha256)}</div>
    <div>rawDocSha256: ${escapeHtml(params.verified.receipt.rawDocSha256)}</div>
    <div>sanitizedPayloadSha256: ${escapeHtml(params.verified.receipt.sanitizedPayloadSha256)}</div>
    <div>prevReceiptSha256: ${escapeHtml(params.verified.receipt.prevReceiptSha256 ?? "GENESIS (null)")}</div>
  </div>
</body>
</html>`;

  const stamp = new Date().toISOString().slice(0, 10);
  const filename = `airlock-brief-${params.mode}-${params.policyProfile.toLowerCase()}-${stamp}.html`;
  triggerLocalDownload(filename, html, "text/html;charset=utf-8");
  return { filename };
}
