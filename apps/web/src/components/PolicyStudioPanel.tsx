import { useState } from "react";
import { Plus, SlidersHorizontal, Trash2 } from "lucide-react";
import type { EntityCategory } from "@airlock/core";
import { POLICY_TEMPLATES, type AirlockPolicyConfig } from "../services/firebase.js";
import {
  COMPLIANCE_PACKS,
  PRESET_CUSTOM_REGEX_RULES,
  validateAndCompileCustomRegex,
  type CompliancePackId,
  type CustomRegexRule,
} from "../utils/policyStudio.js";

interface Props {
  readonly policy: AirlockPolicyConfig;
  readonly enabledPacks: ReadonlyArray<CompliancePackId>;
  readonly customRules: ReadonlyArray<CustomRegexRule>;
  readonly onTogglePack: (packId: CompliancePackId) => void;
  readonly onAddRule: (rule: CustomRegexRule) => void;
  readonly onRemoveRule: (id: string) => void;
}

export function PolicyStudioPanel({
  policy,
  enabledPacks,
  customRules,
  onTogglePack,
  onAddRule,
  onRemoveRule,
}: Props) {
  const [open, setOpen] = useState(false);
  const [ruleName, setRuleName] = useState("");
  const [pattern, setPattern] = useState("");
  const [category, setCategory] = useState<EntityCategory>("SECRET_TERM");
  const [compileErr, setCompileErr] = useState<string | null>(null);

  function handleCompileAdd() {
    setCompileErr(null);
    const res = validateAndCompileCustomRegex(pattern);
    if (!res.ok) {
      setCompileErr(res.error);
      return;
    }
    const cleanName = ruleName.trim() || `Custom Rule #${customRules.length + 1}`;
    onAddRule({
      id: crypto.randomUUID(),
      name: cleanName,
      pattern: pattern.trim(),
      category,
      enabled: true,
    });
    setRuleName("");
    setPattern("");
  }

  const activeCount = enabledPacks.length + customRules.filter((r) => r.enabled).length;

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 10,
        padding: "7px 10px",
        background: "rgba(15, 23, 42, 0.55)",
      }}
    >
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          style={{ padding: "3px 8px", fontSize: "0.73rem" }}
        >
          <SlidersHorizontal size={12} />
          Policy-as-Code & Remote Config Studio ({activeCount} active)
        </button>
        <span className="mono muted" style={{ fontSize: "0.68rem" }}>
          RC: {policy.profile} · {policy.templateId}
        </span>
      </div>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 9 }}>
          <div className="wire-item" style={{ fontSize: "0.71rem", padding: "6px 8px" }}>
            <div style={{ fontWeight: 700, marginBottom: 3 }}>
              Live Firebase Remote Config Policy Payload
            </div>
            <div className="mono muted" style={{ wordBreak: "break-word" }}>
              {JSON.stringify({
                airlock_policy: policy.profile,
                ...policy,
                boundTemplateId: policy.templateId,
                allServerTemplates: POLICY_TEMPLATES,
                strictPiiFirewall: true,
              })}
            </div>
          </div>

          <div>
            <div className="muted" style={{ fontSize: "0.72rem", marginBottom: 4 }}>
              <strong>Enterprise Gate-1 Compliance Packs:</strong>
            </div>
            <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
              {COMPLIANCE_PACKS.map((pack) => {
                const active = enabledPacks.includes(pack.id);
                return (
                  <button
                    type="button"
                    key={pack.id}
                    title={pack.summary}
                    onClick={() => onTogglePack(pack.id)}
                    style={{
                      padding: "3px 8px",
                      fontSize: "0.71rem",
                      borderColor: active ? "#10b981" : undefined,
                      color: active ? "#34d399" : undefined,
                    }}
                  >
                    {pack.label}: {active ? "ON" : "OFF"}
                  </button>
                );
              })}
            </div>
          </div>

          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 7 }}>
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
              <strong style={{ fontSize: "0.73rem" }}>ReDoS-Safe Custom Regex Compiler</strong>
              <div className="row" style={{ gap: 4 }}>
                {PRESET_CUSTOM_REGEX_RULES.map((pr) => (
                  <button
                    type="button"
                    key={pr.name}
                    onClick={() => {
                      setRuleName(pr.name);
                      setPattern(pr.pattern);
                      setCategory(pr.category);
                      setCompileErr(null);
                    }}
                    style={{ padding: "2px 6px", fontSize: "0.66rem" }}
                  >
                    + {pr.name}
                  </button>
                ))}
              </div>
            </div>

            <div className="row" style={{ gap: 5, flexWrap: "wrap" }}>
              <input
                type="text"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder="Rule name"
                style={{
                  flex: "1 1 95px",
                  background: "#060a12",
                  color: "#e2e8f0",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "4px 7px",
                  fontSize: "0.72rem",
                }}
              />
              <input
                type="text"
                className="mono"
                value={pattern}
                onChange={(e) => setPattern(e.target.value)}
                placeholder="Regex e.g. \bDEAL-[0-9]{4}-[A-Z]{2}\b"
                style={{
                  flex: "2 1 170px",
                  background: "#060a12",
                  color: "#e2e8f0",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "4px 7px",
                  fontSize: "0.72rem",
                }}
              />
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as EntityCategory)}
                style={{
                  background: "#060a12",
                  color: "#e2e8f0",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "4px 6px",
                  fontSize: "0.71rem",
                }}
              >
                <option value="SECRET_TERM">SECRET_TERM</option>
                <option value="API_SECRET">API_SECRET</option>
                <option value="PERSON">PERSON</option>
                <option value="ORG">ORG</option>
              </select>
              <button
                type="button"
                className="primary"
                onClick={handleCompileAdd}
                style={{ padding: "4px 8px", fontSize: "0.71rem" }}
              >
                <Plus size={12} /> Compile
              </button>
            </div>

            {compileErr && (
              <div className="alert-red" style={{ marginTop: 6, fontSize: "0.71rem" }}>
                <strong>ReDoS / Syntax Guard:</strong> {compileErr}
              </div>
            )}

            {customRules.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 6 }}>
                {customRules.map((r) => (
                  <div
                    key={r.id}
                    className="row mono"
                    style={{
                      justifyContent: "space-between",
                      fontSize: "0.69rem",
                      background: "rgba(16, 185, 129, 0.08)",
                      border: "1px solid rgba(16, 185, 129, 0.3)",
                      borderRadius: 6,
                      padding: "3px 7px",
                    }}
                  >
                    <span>
                      [{r.category}] <strong>{r.name}</strong>: /{r.pattern}/gi
                    </span>
                    <button
                      type="button"
                      onClick={() => onRemoveRule(r.id)}
                      style={{ padding: "1px 5px", fontSize: "0.66rem" }}
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
