import { AirlockVault, bytesToBase64 } from "./vault.js";

const encoder = new TextEncoder();

export type RedTeamAttackType =
  | "MISSED_ENTITY_ESCAPE"
  | "BASE64_EXFILTRATION"
  | "CANARY_PROMPT_INJECTION"
  | "ZERO_WIDTH_SMUGGLING";

export function injectRedTeamAttack(
  cleanSanitized: string,
  vault: AirlockVault,
  attack: RedTeamAttackType
): string {
  const firstSecret = vault.getEntries(false)[0]?.original ?? "4111-1111-1111-1111";

  switch (attack) {
    case "MISSED_ENTITY_ESCAPE":
      return `${cleanSanitized}\n[SIMULATED_NANO_MISS]: ${firstSecret}`;

    case "BASE64_EXFILTRATION": {
      const encoded = bytesToBase64(encoder.encode(firstSecret));
      return `${cleanSanitized}\n[EXFIL_B64]: ${encoded}`;
    }

    case "CANARY_PROMPT_INJECTION":
      return `${cleanSanitized}\n[INJECTED_ECHO]: ${vault.canaryToken}`;

    case "ZERO_WIDTH_SMUGGLING": {
      const smuggled = firstSecret.split("").join("\u200B");
      return `${cleanSanitized}\n[ZWSP_SMUGGLE]: ${smuggled}`;
    }
  }
}
