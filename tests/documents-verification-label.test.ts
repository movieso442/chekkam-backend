import { describe, expect, test } from "vitest";
import { PDFDocument } from "pdf-lib";
import {
  buildVerificationLabelPdfResponse,
  fetchDocumentForVerificationLabel,
  generateVerificationLabelPdf,
  hasValidRegistrySignature,
  verificationLabelFilename,
  VerificationLabelDocument,
} from "@/lib/documents/verification-label";
import { fakeSupabase } from "../test-support/fake-supabase";
import { generateSigningKeyPair, hashDocument, signHash } from "@/lib/crypto/sign";

const sampleDoc: VerificationLabelDocument = {
  id: "doc-1",
  institution_id: "0b8929f6-22e2-400a-8d91-af9e7f70280c",
  institution_name: "Lycée Bilingue de Yaoundé",
  document_type: "certificate",
  recipient_name: "Jean Dupont",
  verification_id: "CHK-4F7K-9QRT",
  qr_payload: "http://localhost:3000/verify/CHK-4F7K-9QRT",
  file_hash: null,
  signature: null,
  signing_public_key_snapshot: null,
  institution_signing_public_key: null,
};

describe("fetchDocumentForVerificationLabel", () => {
  test("returns null when the registry record does not exist", async () => {
    const admin = fakeSupabase({ documents: { data: null } });
    await expect(fetchDocumentForVerificationLabel(admin, "unknown-document")).resolves.toBeNull();
  });

  test("reads registry metadata only and unwraps the issuing institution", async () => {
    const admin = fakeSupabase({
      documents: {
        data: {
          ...sampleDoc,
          institutions: [{ name: sampleDoc.institution_name }],
        },
      },
    });

    await expect(fetchDocumentForVerificationLabel(admin, sampleDoc.id)).resolves.toMatchObject({
      id: sampleDoc.id,
      institution_name: sampleDoc.institution_name,
      verification_id: sampleDoc.verification_id,
    });
  });
});

describe("hasValidRegistrySignature", () => {
  test("requires a valid issuer signature over the original file hash", () => {
    const { publicKey, privateKey } = generateSigningKeyPair();
    const fileHash = hashDocument(Buffer.from("original certificate bytes"));
    const signature = signHash(fileHash, privateKey);
    const signedRecord: VerificationLabelDocument = {
      ...sampleDoc,
      file_hash: fileHash,
      signature,
      institution_signing_public_key: publicKey,
    };

    expect(hasValidRegistrySignature(signedRecord)).toBe(true);
    expect(hasValidRegistrySignature({ ...signedRecord, signature: "not-a-valid-signature" })).toBe(false);
    expect(hasValidRegistrySignature(sampleDoc)).toBe(false);
  });
});

describe("verificationLabelFilename", () => {
  test("uses a neutral, safe filename", () => {
    expect(verificationLabelFilename(sampleDoc)).toBe("Verification-Label-CHK-4F7K-9QRT.pdf");
  });
});

describe("buildVerificationLabelPdfResponse", () => {
  test("returns a private PDF attachment", async () => {
    const bytes = new TextEncoder().encode("test label bytes");
    const response = buildVerificationLabelPdfResponse(bytes, "Verification-Label-CHK-4F7K-9QRT.pdf");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/pdf");
    expect(response.headers.get("content-disposition")).toBe(
      'attachment; filename="Verification-Label-CHK-4F7K-9QRT.pdf"'
    );
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  });
});

describe("generateVerificationLabelPdf", () => {
  test("creates a one-page unbranded, separate label", async () => {
    const bytes = await generateVerificationLabelPdf(sampleDoc);
    expect(Buffer.from(bytes.slice(0, 5)).toString()).toBe("%PDF-");

    const pdf = await PDFDocument.load(bytes);
    expect(pdf.getPageCount()).toBe(1);
    expect(pdf.getTitle()).toBe("Document verification label - CHK-4F7K-9QRT");
    expect(pdf.getSubject()).toBe(
      "Separate QR verification label; the original document remains unchanged."
    );
    // pdf-lib owns its producer metadata, but the label must never surface the
    // platform's brand in its visible document metadata.
    expect(pdf.getTitle()).not.toContain("Chekkam");
    expect(pdf.getSubject()).not.toContain("Chekkam");
  });

  test("renders without an optional recipient or any document bytes", async () => {
    const bytes = await generateVerificationLabelPdf({
      ...sampleDoc,
      recipient_name: null,
    });
    await expect(PDFDocument.load(bytes)).resolves.toBeInstanceOf(PDFDocument);
  });
});
