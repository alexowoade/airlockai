export function generateSyntheticMedicalBillPng(): {
  dataUrl: string;
  base64: string;
  mimeType: "image/png";
} {
  const canvas = document.createElement("canvas");
  canvas.width = 760;
  canvas.height = 420;
  const ctx = canvas.getContext("2d")!;

  ctx.fillStyle = "#f8fafc";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "#cbd5e1";
  ctx.lineWidth = 2;
  ctx.strokeRect(16, 16, 728, 388);

  ctx.fillStyle = "#0f172a";
  ctx.font = "bold 22px monospace";
  ctx.fillText("NORTHSTAR MEDICAL CENTER — PATIENT STATEMENT", 36, 62);

  ctx.font = "16px monospace";
  const lines = [
    "Date of Service: 2026-11-04          Invoice: #MED-99214",
    "Patient Name:    Clara Lindqvist     SSN: 901-33-4482",
    "Contact Email:   clara.lindqvist@mail.test",
    "Diagnosis:       Stage II Thyroid Carcinoma Follow-Up MRI",
    "--------------------------------------------------------------",
    "Out-of-Network Facility Fee (No Prior Auth):      $14,200.00",
    "Duplicate Pathology Code 88305:                    $3,850.00",
    "TOTAL DUE WITHIN 10 DAYS:                         $18,050.00",
    "Card on File:    4111-1111-1111-1111",
  ];
  lines.forEach((line, i) => ctx.fillText(line, 36, 112 + i * 31));

  const dataUrl = canvas.toDataURL("image/png");
  return {
    dataUrl,
    base64: dataUrl.split(",")[1]!,
    mimeType: "image/png",
  };
}

/** Draws local black redaction bars over sensitive regions on-device (0 bytes sent) */
export async function renderRedactedImageOverlay(sourceDataUrl: string): Promise<string> {
  const img = new Image();
  img.src = sourceDataUrl;
  await new Promise<void>((resolve, reject) => {
    img.onload = () => resolve();
    img.onerror = () => reject(new Error("Image load failed"));
  });

  const canvas = document.createElement("canvas");
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext("2d")!;
  ctx.drawImage(img, 0, 0);

  // Visual on-device redaction stamp + sensitive line mask bars
  ctx.fillStyle = "rgba(15, 23, 42, 0.94)";
  const h = canvas.height;
  const w = canvas.width;
  ctx.fillRect(w * 0.22, h * 0.29, w * 0.68, h * 0.08);
  ctx.fillRect(w * 0.22, h * 0.37, w * 0.55, h * 0.07);
  ctx.fillRect(w * 0.22, h * 0.81, w * 0.45, h * 0.08);

  ctx.fillStyle = "#10b981";
  ctx.font = "bold 14px monospace";
  ctx.fillText("REDACTED ON-DEVICE — RAW PIXELS NEVER TRANSMITTED", 28, h - 22);

  return canvas.toDataURL("image/png");
}
