import { SupabaseClient } from "@supabase/supabase-js";
import { PDFDocument, PDFFont, StandardFonts, rgb } from "pdf-lib";
import { generateQrDataUrl } from "@/lib/crypto/qrcode";
import { verifySignature } from "@/lib/crypto/verify";

/**
 * A compact, separate verification label for a registry record.
 *
 * This deliberately has no platform mark or logo and is never merged into a
 * submitted document. Signing keeps only the original file's hash and the
 * registry signature, so the original bytes remain untouched.
 */
export type VerificationLabelDocument = {
  id: string;
  institution_id: string;
  institution_name: string | null;
  document_type: string;
  recipient_name: string | null;
  verification_id: string;
  qr_payload: string;
  file_hash: string | null;
  signature: string | null;
  signing_public_key_snapshot: string | null;
  institution_signing_public_key: string | null;
};

/** Fetches only registry data. It never reads, stores, or changes document bytes. */
export async function fetchDocumentForVerificationLabel(
  admin: SupabaseClient,
  documentId: string
): Promise<VerificationLabelDocument | null> {
  const { data: doc } = await admin
    .from("documents")
    .select(
      "id, institution_id, document_type, recipient_name, verification_id, qr_payload, file_hash, signature, signing_public_key_snapshot, institutions(name, signing_public_key)"
    )
    .eq("id", documentId)
    .maybeSingle();

  if (!doc) return null;

  const institution = Array.isArray(doc.institutions) ? doc.institutions[0] : doc.institutions;
  return {
    id: doc.id,
    institution_id: doc.institution_id,
    institution_name: institution?.name ?? null,
    document_type: doc.document_type,
    recipient_name: doc.recipient_name,
    verification_id: doc.verification_id,
    qr_payload: doc.qr_payload,
    file_hash: doc.file_hash,
    signature: doc.signature,
    signing_public_key_snapshot: doc.signing_public_key_snapshot ?? null,
    institution_signing_public_key: institution?.signing_public_key ?? null,
  };
}

/**
 * A label is only issued when the document's stored SHA-256 hash still has a
 * valid issuer signature. This is deliberately stricter than a legacy lookup:
 * the label is a fresh assurance artifact, never a substitute for a record
 * whose cryptographic chain cannot be checked.
 */
export function hasValidRegistrySignature(doc: VerificationLabelDocument): boolean {
  const signingKey = doc.signing_public_key_snapshot ?? doc.institution_signing_public_key;
  if (!doc.file_hash || !doc.signature || !signingKey) return false;
  return verifySignature(doc.file_hash, doc.signature, signingKey);
}

/** A neutral, predictable filename. It does not advertise a third party on the issuer's document. */
export function verificationLabelFilename(
  doc: Pick<VerificationLabelDocument, "verification_id">
): string {
  return `Verification-Label-${doc.verification_id}.pdf`;
}

/** Creates the download response for a separate label, never the original file. */
export function buildVerificationLabelPdfResponse(pdfBytes: Uint8Array, filename: string): Response {
  const body = new Uint8Array(pdfBytes);
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Length": String(body.byteLength),
      "Cache-Control": "private, no-store",
    },
  });
}

const PAGE_WIDTH = 432;
const PAGE_HEIGHT = 252;
const MARGIN = 24;
const COLOR = {
  ink: rgb(0.08, 0.08, 0.08),
  muted: rgb(0.33, 0.33, 0.33),
  faint: rgb(0.52, 0.52, 0.52),
  border: rgb(0.8, 0.8, 0.8),
  white: rgb(1, 1, 1),
};

function truncateText(text: string, font: PDFFont, size: number, maxWidth: number): string {
  if (font.widthOfTextAtSize(text, size) <= maxWidth) return text;
  const suffix = "...";
  let end = text.length;
  while (end > 0 && font.widthOfTextAtSize(`${text.slice(0, end)}${suffix}`, size) > maxWidth) {
    end -= 1;
  }
  return `${text.slice(0, end)}${suffix}`;
}

function wrapText(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) > maxWidth && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines;
}

/**
 * Generates a generic QR label that can be printed or sent alongside the
 * original. No original bytes are included or modified by this operation.
 */
export async function generateVerificationLabelPdf(
  doc: VerificationLabelDocument
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create();
  pdfDoc.setTitle(`Document verification label - ${doc.verification_id}`);
  pdfDoc.setSubject("Separate QR verification label; the original document remains unchanged.");

  const page = pdfDoc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const helveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const courierBold = await pdfDoc.embedFont(StandardFonts.CourierBold);

  page.drawRectangle({
    x: 0,
    y: 0,
    width: PAGE_WIDTH,
    height: PAGE_HEIGHT,
    color: COLOR.white,
    borderColor: COLOR.border,
    borderWidth: 1,
  });
  page.drawText("DOCUMENT VERIFICATION LABEL", {
    x: MARGIN,
    y: PAGE_HEIGHT - MARGIN - 3,
    size: 13,
    font: helveticaBold,
    color: COLOR.ink,
  });
  page.drawText("Keep this label with the original document", {
    x: MARGIN,
    y: PAGE_HEIGHT - MARGIN - 18,
    size: 8.5,
    font: helvetica,
    color: COLOR.muted,
  });

  page.drawText("SCAN TO VIEW LIVE STATUS", {
    x: PAGE_WIDTH - MARGIN - 118,
    y: PAGE_HEIGHT - MARGIN - 3,
    size: 7.5,
    font: helveticaBold,
    color: COLOR.muted,
  });

  const qrSize = 114;
  const qrY = 79;
  const qrDataUrl = await generateQrDataUrl(doc.qr_payload);
  const qrImage = await pdfDoc.embedPng(qrDataUrl);
  page.drawRectangle({
    x: MARGIN,
    y: qrY - 4,
    width: qrSize + 8,
    height: qrSize + 8,
    color: COLOR.white,
    borderColor: COLOR.border,
    borderWidth: 1,
  });
  page.drawImage(qrImage, { x: MARGIN + 4, y: qrY, width: qrSize, height: qrSize });
  page.drawText("SCAN FOR CURRENT RECORD STATUS", {
    x: MARGIN,
    y: qrY - 13,
    size: 6.7,
    font: helveticaBold,
    color: COLOR.muted,
  });

  const textX = MARGIN + qrSize + 28;
  const textWidth = PAGE_WIDTH - textX - MARGIN;
  const valueX = textX;
  let cursorY = PAGE_HEIGHT - 72;
  const drawField = (label: string, value: string, font = helvetica, size = 10) => {
    page.drawText(label, {
      x: textX,
      y: cursorY,
      size: 6.8,
      font: helveticaBold,
      color: COLOR.faint,
    });
    page.drawText(truncateText(value, font, size, textWidth), {
      x: valueX,
      y: cursorY - 12,
      size,
      font,
      color: COLOR.ink,
    });
    cursorY -= 30;
  };

  drawField("ISSUER", doc.institution_name ?? "Unknown issuer", helveticaBold, 9.5);
  drawField("VERIFICATION ID", doc.verification_id, courierBold, 12);
  drawField("DOCUMENT TYPE", doc.document_type, helvetica, 9.5);
  if (doc.recipient_name) drawField("RECIPIENT", doc.recipient_name, helvetica, 9.5);

  const dividerY = 56;
  page.drawLine({
    start: { x: MARGIN, y: dividerY },
    end: { x: PAGE_WIDTH - MARGIN, y: dividerY },
    thickness: 0.7,
    color: COLOR.border,
  });
  const statement =
    "Scan the QR code or enter the ID to see the live record status. The registry has a validated cryptographic " +
    "signature of the original file's SHA-256. This separate label does not alter, stamp, or embed a signature in " +
    "the original file. For an exact file match, submit the original digital file.";
  const lines = wrapText(statement, helvetica, 7.2, PAGE_WIDTH - MARGIN * 2);
  lines.slice(0, 4).forEach((line, index) => {
    page.drawText(line, {
      x: MARGIN,
      y: dividerY - 13 - index * 9,
      size: 7.2,
      font: helvetica,
      color: COLOR.muted,
    });
  });

  return pdfDoc.save();
}
