import type { PolicyProfile } from "@airlock/core";

export interface DealRoomScenario {
  readonly id: string;
  readonly label: string;
  readonly policy: PolicyProfile;
  readonly docATitle: string;
  readonly docAText: string;
  readonly docBTitle: string;
  readonly docBText: string;
}

export const DEAL_ROOM_SCENARIOS: ReadonlyArray<DealRoomScenario> = [
  {
    id: "msa-wire-fraud",
    label: "Deal Room: MSA + Fraudulent Wire Invoice",
    policy: "INVOICE_FINANCE",
    docATitle: "Doc A — Master Agreement (MSA)",
    docAText: [
      "MSA — Schedule A:",
      "Discloser: Helios Robotics Corp (contact: elena.vance@helios-robotics.test, +1-415-890-4421)",
      "Vendor: Apex Foundry LLC (signer: Marcus Sterling, SSN 912-45-6789)",
      "1. Scope: Engineering deliverables for Project Obsidian.",
      "2. Hard Payment Cap: Total invoices under this contract shall not exceed $1,450,000.00.",
      "3. Expiration Date: All billable milestones must be submitted on or before 2026-12-31.",
      "4. Authorized Settlement Rail: Wire transfers are restricted strictly to country code DE using verified IBAN DE89370400440532013000.",
    ].join("\n"),
    docBTitle: "Doc B — Counterparty Wire Invoice",
    docBText: [
      "WIRE REMITTANCE INVOICE — Schedule B:",
      "Vendor: Apex Foundry LLC (Billing Contact: Marcus Sterling)",
      "Discloser: Helios Robotics Corp (Accounts Payable: elena.vance@helios-robotics.test)",
      "Engagement Reference: Project Obsidian Final Milestone",
      "Total Amount Due Immediately: $2,102,500.00",
      "Requested Settlement Date: 2027-02-15",
      "Remittance Destination IBAN: GB29NWBK60161331926819 (updated treasury account).",
    ].join("\n"),
  },
];
