import type { PolicyProfile } from "@airlock/core";

export interface SampleDoc {
  readonly id: string;
  readonly label: string;
  readonly policy: PolicyProfile;
  readonly text: string;
}

export const SAMPLE_DOCS: ReadonlyArray<SampleDoc> = [
  {
    id: "nda",
    label: "Synthetic M&A NDA",
    policy: "NDA_STRICT",
    text: `MUTUAL NON-DISCLOSURE AGREEMENT (Effective 2026-11-15)
Between Helios Robotics Corp ("Discloser", contact: elena.vance@helios-robotics.test, +1-415-890-4421) and Apex Foundry LLC ("Recipient").
1. Confidential Project: All schematics, pricing ($1,450,000.00 licensing floor), and API credentials (sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f) relating to Project Obsidian.
2. Perpetual Indemnity: Recipient assumes unlimited liability including consequential damages with no cap, governed exclusively by courts selected by Discloser.
3. Non-Solicit & IP Assignment: Any derivative ideas conceived by Recipient personnel (Lead Engineer Marcus Sterling, SSN 912-45-6789) automatically vest in Discloser in perpetuity.`,
  },
  {
    id: "invoice",
    label: "Vendor Wire Invoice",
    policy: "INVOICE_FINANCE",
    text: `URGENT WIRE SETTLEMENT INVOICE #INV-2026-8841 (Due: 2026-11-28)
Billed To: Meridian Logistics Group (ap@meridian-logistics.test)
Amount Due: $84,750.00 (Late penalty: 18% compounded weekly after 48 hours).
Updated Remittance Instructions (OVERRIDES PRIOR MASTER AGREEMENT):
Wire full balance immediately to IBAN DE89370400440532013000 or backup settlement card 4532-0151-1283-0366.
Authorized Signer: David Okonkwo (+1-212-555-0194). Disputes waived if not filed within 24 hours.`,
  },
  {
    id: "medical",
    label: "HIPAA Medical Bill",
    policy: "MEDICAL_HIPAA",
    text: `CONFIDENTIAL OUTPATIENT BILLING STATEMENT — Date of Service: 2026-11-04
Patient: Clara Lindqvist | SSN: 901-33-4482 | Email: clara.lindqvist@mail.test | Phone: +1-312-555-0188
Facility: Northstar Oncology & Imaging Center
Primary Diagnosis: Stage II Thyroid Carcinoma follow-up panel + contrast MRI.
Charges: Out-of-network facility fee $14,200.00 + duplicate pathology code 88305 ($3,850.00). Total Patient Balance: $18,050.00.
Payment Account on File: 4111-1111-1111-1111. Unpaid balances sent to collections in 10 days.`,
  },
];
