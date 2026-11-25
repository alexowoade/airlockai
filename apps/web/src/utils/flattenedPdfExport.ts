import type { ParsedPdfDocument } from "./pdfRedactor.js";

const enc = new TextEncoder();

async function dataUrlToJpeg(dataUrl: string): Promise<{
  bytes: Uint8Array;
  width: number;
  height: number;
}> {
  const img = await new Promise<HTMLImageElement>((resolve, reject) => {
    const el = new Image();
    el.onload = () => resolve(el);
    el.onerror = () => reject(new Error("Failed to rasterize redacted page."));
    el.src = dataUrl;
  });
  const canvas = document.createElement("canvas");
  canvas.width = img.naturalWidth || img.width;
  canvas.height = img.naturalHeight || img.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas 2D context unavailable.");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);

  const jpegDataUrl = canvas.toDataURL("image/jpeg", 0.9);
  const b64 = jpegDataUrl.split(",")[1] ?? "";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return { bytes, width: canvas.width, height: canvas.height };
}

/**
 * Builds a valid multi-page binary PDF 1.4 containing ONLY rasterized JPEG /XObject streams
 * (zero /Font resources, zero BT/ET/Tj text operators) so hidden PDF text layers are
 * physically eliminated against copy-paste redaction leaks.
 */
export async function exportFlattenedRedactedPdf(pdfDoc: ParsedPdfDocument): Promise<{
  filename: string;
  byteLength: number;
  pageCount: number;
}> {
  const pages = await Promise.all(
    pdfDoc.pages.map((p) => dataUrlToJpeg(p.redactedDataUrl ?? p.originalDataUrl))
  );

  const chunks: Uint8Array[] = [];
  let cursor = 0;
  const pushBytes = (b: Uint8Array) => {
    chunks.push(b);
    cursor += b.byteLength;
  };
  const pushStr = (s: string) => pushBytes(enc.encode(s));

  // PDF 1.4 header + binary marker
  pushBytes(
    new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a])
  );

  const totalObjs = 2 + pages.length * 3;
  const offsets: number[] = new Array(totalObjs + 1).fill(0);

  // Obj 1: Catalog
  offsets[1] = cursor;
  pushStr("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

  // Obj 2: Pages
  const kids = pages.map((_, i) => `${5 + i * 3} 0 R`).join(" ");
  offsets[2] = cursor;
  pushStr(`2 0 obj\n<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>\nendobj\n`);

  // Per-page objects: Image XObject, Drawing Content Stream (no text), Page Dictionary
  pages.forEach((pg, i) => {
    const imgId = 3 + i * 3;
    const contentId = 4 + i * 3;
    const pageId = 5 + i * 3;
    const pageW = 595.28;
    const pageH = Number(((pageW * pg.height) / Math.max(1, pg.width)).toFixed(2));

    offsets[imgId] = cursor;
    pushStr(
      `${imgId} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${pg.width} /Height ${pg.height} ` +
        `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${pg.bytes.byteLength} >>\nstream\n`
    );
    pushBytes(pg.bytes);
    pushStr("\nendstream\nendobj\n");

    const drawCmd = `q\n${pageW} 0 0 ${pageH} 0 0 cm\n/Im0 Do\nQ\n`;
    const drawBytes = enc.encode(drawCmd);
    offsets[contentId] = cursor;
    pushStr(`${contentId} 0 obj\n<< /Length ${drawBytes.byteLength} >>\nstream\n`);
    pushBytes(drawBytes);
    pushStr("endstream\nendobj\n");

    offsets[pageId] = cursor;
    pushStr(
      `${pageId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageW} ${pageH}] ` +
        `/Resources << /XObject << /Im0 ${imgId} 0 R >> >> /Contents ${contentId} 0 R >>\nendobj\n`
    );
  });

  const xrefOffset = cursor;
  pushStr(`xref\n0 ${totalObjs + 1}\n`);
  pushStr("0000000000 65535 f \n");
  for (let id = 1; id <= totalObjs; id++) {
    pushStr(`${String(offsets[id]).padStart(10, "0")} 00000 n \n`);
  }
  pushStr(`trailer\n<< /Size ${totalObjs + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`);

  const out = new Uint8Array(cursor);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }

  const base = pdfDoc.fileName.replace(/\.pdf$/i, "");
  const filename = `${base}-FLATTENED-0TEXT.pdf`;
  const blob = new Blob([out], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  return { filename, byteLength: out.byteLength, pageCount: pages.length };
}
