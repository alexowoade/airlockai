import * as pdfjsLib from "pdfjs-dist";
import pdfWorkerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import type { DetectedSpan } from "@airlock/core";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorkerUrl;

export interface PdfTextBox {
  readonly start: number;
  readonly end: number;
  readonly text: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface ParsedPdfPage {
  readonly pageNumber: number;
  readonly width: number;
  readonly height: number;
  readonly originalDataUrl: string;
  readonly redactedDataUrl?: string;
  readonly redactionCount: number;
  readonly textBoxes: ReadonlyArray<PdfTextBox>;
}

export interface ParsedPdfDocument {
  readonly fileName: string;
  readonly totalPages: number;
  readonly fullText: string;
  readonly pages: ReadonlyArray<ParsedPdfPage>;
}

interface PdfTextItemLike {
  str?: string;
  transform?: number[];
  width?: number;
  height?: number;
  hasEOL?: boolean;
}

const MAX_RENDER_PAGES = 6;
const PDF_RENDER_SCALE = 1.5;

/**
 * 100% client-side multi-page PDF parser & Canvas renderer using Vite-bundled pdf.js worker.
 * Zero bytes leave the device.
 */
export async function parseLocalPdf(
  fileName: string,
  bytes: Uint8Array
): Promise<ParsedPdfDocument> {
  const loadingTask = pdfjsLib.getDocument({ data: bytes });
  const pdf = await loadingTask.promise;
  const totalPages = Math.min(pdf.numPages, MAX_RENDER_PAGES);

  const pages: ParsedPdfPage[] = [];
  let fullText = "";

  for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
    const page = await pdf.getPage(pageNum);
    const viewport = page.getViewport({ scale: PDF_RENDER_SCALE });

    const canvas = document.createElement("canvas");
    canvas.width = Math.ceil(viewport.width);
    canvas.height = Math.ceil(viewport.height);
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      throw new Error("HTML5 Canvas 2D context unavailable for local PDF rendering.");
    }

    await page.render({ canvasContext: ctx, viewport }).promise;
    const originalDataUrl = canvas.toDataURL("image/png");

    const textContent = await page.getTextContent();
    const textBoxes: PdfTextBox[] = [];

    if (pageNum > 1 && fullText.length > 0 && !fullText.endsWith("\n")) {
      fullText += "\n\n";
    }

    let lastBaselineY: number | null = null;

    for (const rawItem of textContent.items as PdfTextItemLike[]) {
      const str = rawItem.str ?? "";
      if (!str) {
        if (rawItem.hasEOL && !fullText.endsWith("\n")) {
          fullText += "\n";
        }
        continue;
      }

      const tx = rawItem.transform
        ? pdfjsLib.Util.transform(viewport.transform, rawItem.transform)
        : [1, 0, 0, 1, 0, 0];

      const fontHeight = Math.max(
        10,
        Math.hypot(tx[2] ?? 0, tx[3] ?? 0) || (rawItem.height ?? 10) * PDF_RENDER_SCALE
      );
      const boxWidth = Math.max(8, (rawItem.width ?? str.length * 6) * PDF_RENDER_SCALE);
      const x = tx[4] ?? 0;
      const baselineY = tx[5] ?? 0;
      const y = baselineY - fontHeight * 0.85;

      if (lastBaselineY !== null && Math.abs(baselineY - lastBaselineY) > fontHeight * 0.6) {
        if (!fullText.endsWith("\n")) {
          fullText += "\n";
        }
      } else if (fullText.length > 0 && !fullText.endsWith("\n") && !fullText.endsWith(" ")) {
        fullText += " ";
      }
      lastBaselineY = baselineY;

      const start = fullText.length;
      fullText += str;
      const end = fullText.length;

      textBoxes.push({
        start,
        end,
        text: str,
        x,
        y,
        width: boxWidth,
        height: fontHeight * 1.15,
      });

      if (rawItem.hasEOL) {
        fullText += "\n";
      }
    }

    pages.push({
      pageNumber: pageNum,
      width: canvas.width,
      height: canvas.height,
      originalDataUrl,
      redactionCount: 0,
      textBoxes,
    });
  }

  return {
    fileName,
    totalPages: pdf.numPages,
    fullText: fullText.trim(),
    pages,
  };
}

/**
 * Burns permanent black redaction rectangles onto the exact pixel bounding boxes of every
 * Gate 1 / Gate 2 / Custom-Secret span on each rendered PDF page.
 */
export async function renderRedactedPdfPages(
  parsed: ParsedPdfDocument,
  spans: ReadonlyArray<DetectedSpan>
): Promise<ParsedPdfDocument> {
  const updatedPages: ParsedPdfPage[] = [];

  for (const page of parsed.pages) {
    const img = await loadImage(page.originalDataUrl);
    const canvas = document.createElement("canvas");
    canvas.width = page.width;
    canvas.height = page.height;
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      updatedPages.push(page);
      continue;
    }

    ctx.drawImage(img, 0, 0);
    let redactionCount = 0;

    for (const box of page.textBoxes) {
      const boxLen = Math.max(1, box.end - box.start);
      for (const span of spans) {
        const overlapStart = Math.max(box.start, span.start);
        const overlapEnd = Math.min(box.end, span.end);
        if (overlapStart >= overlapEnd) continue;

        const fracStart = (overlapStart - box.start) / boxLen;
        const fracEnd = (overlapEnd - box.start) / boxLen;
        const rx = Math.max(0, box.x + box.width * fracStart - 2);
        const rw = Math.max(14, box.width * (fracEnd - fracStart) + 4);
        const ry = Math.max(0, box.y - 2);
        const rh = Math.max(12, box.height + 4);

        ctx.fillStyle = "#090d16";
        ctx.fillRect(rx, ry, rw, rh);
        ctx.strokeStyle = "#10b981";
        ctx.lineWidth = 1;
        ctx.strokeRect(rx, ry, rw, rh);

        if (rw >= 48) {
          ctx.fillStyle = "#34d399";
          ctx.font = "bold 9px monospace";
          ctx.fillText(`[${span.category}]`, rx + 3, ry + Math.min(rh - 3, 11));
        }
        redactionCount += 1;
      }
    }

    ctx.fillStyle = "#022c22";
    ctx.fillRect(0, canvas.height - 26, canvas.width, 26);
    ctx.fillStyle = "#34d399";
    ctx.font = "bold 11px monospace";
    ctx.fillText(
      `AIRLOCKAI LOCAL PDF REDACTION — PAGE ${page.pageNumber}/${parsed.pages.length} (${redactionCount} PIXEL BOXES DESTROYED · 0 BYTES SENT)`,
      12,
      canvas.height - 9
    );

    updatedPages.push({
      ...page,
      redactedDataUrl: canvas.toDataURL("image/png"),
      redactionCount,
    });
  }

  return {
    ...parsed,
    pages: updatedPages,
  };
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Failed to load rendered PDF page image."));
    img.src = src;
  });
}

function escapePdfText(input: string): string {
  return input.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

/**
 * Generates a real, standards-compliant 2-page binary PDF locally in memory so judges
 * can test coordinate-exact PDF bounding-box redaction, Fail-Closed Residual Guard,
 * and HIPAA Safe Harbor toggling in 1 click without needing a local file.
 */
export function generateSyntheticMultiPageNdaPdfBytes(): Uint8Array {
  const page1Lines = [
    "MUTUAL NON-DISCLOSURE AGREEMENT (Effective 2026-11-15)",
    "Between Helios Robotics Corp (Discloser) and Apex Foundry LLC (Recipient).",
    "Primary Contact: elena.vance@helios-robotics.test | Phone: +1-415-890-4421.",
    "1. Confidential Project: All schematics, pricing ($1,450,000.00 licensing floor),",
    "and API credentials (sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f) for Project Obsidian.",
    "2. Perpetual Indemnity: Recipient assumes unlimited liability including",
    "consequential damages with no cap, governed exclusively by Discloser courts.",
  ];

  const page2Lines = [
    "SCHEDULE A - PERSONNEL & WIRE ESCROW (Ref: INV-2026-8841).",
    "Lead Engineer: Marcus Sterling | SSN: 912-45-6789.",
    "Escrow IBAN: DE89370400440532013000 | Authorized Signer: David Okonkwo.",
    "Web link: https://docs.escrow-vault.test/8841 (IP 192.168.4.22).",
    "Headquarters ZIP: 94301 | Review Officer: Kaelen.",
    "3. IP Assignment: All derivative inventions vest in Discloser in perpetuity.",
  ];

  const makeStream = (lines: string[]): string => {
    const ops: string[] = ["BT", "/F1 12 Tf", "48 740 Td", "22 TL"];
    lines.forEach((line, idx) => {
      ops.push(idx === 0 ? `(${escapePdfText(line)}) Tj` : `T* (${escapePdfText(line)}) Tj`);
    });
    ops.push("ET");
    return ops.join("\n");
  };

  const stream1 = makeStream(page1Lines);
  const stream2 = makeStream(page2Lines);

  const objects = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>\nendobj\n",
    "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>\nendobj\n",
    "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    `6 0 obj\n<< /Length ${stream1.length} >>\nstream\n${stream1}\nendstream\nendobj\n`,
    `7 0 obj\n<< /Length ${stream2.length} >>\nstream\n${stream2}\nendstream\nendobj\n`,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [0];
  for (const obj of objects) {
    offsets.push(pdf.length);
    pdf += obj;
  }

  const xrefStart = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += "0000000000 65535 f \n";
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;

  return new TextEncoder().encode(pdf);
}
