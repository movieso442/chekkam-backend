import { SupabaseClient } from "@supabase/supabase-js";
import {
  hashDocument,
  getInstitutionPrivateKey,
  normalizePublicKeyPem,
  publicKeyFromPrivateKey,
  signHash,
} from "@/lib/crypto/sign";
import { generateVerificationId, generatePinCode } from "@/lib/crypto/ids";
import { buildVerificationUrl, generateQrDataUrl } from "@/lib/crypto/qrcode";
import { embedInvisibleMarker } from "@/lib/documents/embed";
import { bufferToBytea } from "@/lib/documents/bytea";
import { ConfigError } from "@/lib/errors";

/**
 * The one and only document signing path (SRS 10.1). Extracted from
 * app/api/documents/sign/route.ts so WhatsApp/Telegram officer-signing calls
 * the exact same logic instead of a re-implementation. The HTTP route is now
 * a thin wrapper around this function — behavior is unchanged.
 *
 * Callers are responsible for their own authorization check before calling
 * this (web route: requireRole + requireInstitutionMember; bots: a verified
 * channel_identities row with a non-null institution_id).
 */
export type SignDocumentInput = {
  institutionId: string;
  documentType: string;
  recipientName?: string | null;
  fileBuffer: Buffer;
  /** Original upload filename, when known (web form upload). Bot-sourced media has none. */
  fileName?: string | null;
  actorId: string | null;
  actorType?: "user" | "system" | "api_partner";
  auditAction?: string;
  /** ISO date string. Most document types have no expiry (e.g. certificates); optional. */
  expiryDate?: string | null;
  /**
   * Pre-chosen verification ID/PIN instead of freshly generated ones.
   * Default (every existing caller): omit these, get random ones as always.
   * Only needed when the caller must embed the real ID/PIN into the file's
   * own visible content *before* signing it — e.g. a certificate template
   * that prints its own verification ID/QR (scripts/seed-demo-trust.ts) —
   * since otherwise the printed ID and the DB row's ID could never match.
   */
  verificationId?: string;
  pinCode?: string;
  /** Overrides the recorded issue timestamp (defaults to now()). For deterministic demo/test data only. */
  issuedAt?: string;
};

export type SignDocumentResult = {
  id: string;
  verification_id: string;
  pin_code: string;
  qr_payload: string;
  qr_image: string;
  status: string;
  /** Whether an invisibly-marked original is available via GET /api/documents/:id/download-original. */
  has_original_download: boolean;
};

/**
 * Generates the verification ID up front (rather than after hashing, as
 * before) specifically so it can be embedded *inside* supported file formats
 * (PDF/DOCX/PNG) before the file is hashed and signed — the stored
 * file_hash/signature then cover this embedded version, so the existing
 * hash-based verifyByUpload() path needs no changes to recognize a
 * re-downloaded copy as genuine. Unsupported formats (including video) sign
 * exactly as before, with no original retained — see lib/documents/embed/.
 */
export async function signDocumentCore(
  admin: SupabaseClient,
  input: SignDocumentInput
): Promise<SignDocumentResult> {
  const verificationId = input.verificationId ?? generateVerificationId();
  const pinCode = input.pinCode ?? generatePinCode();
  const qrPayload = buildVerificationUrl(verificationId);
  const qrImage = await generateQrDataUrl(qrPayload);

  const embedded = await embedInvisibleMarker(input.fileBuffer, `Chekkam:${verificationId}`).catch(
    () => null
  );
  const signedBuffer = embedded?.buffer ?? input.fileBuffer;

  const fileHash = hashDocument(signedBuffer);
  const privateKey = getInstitutionPrivateKey(input.institutionId);
  const signingPublicKey = publicKeyFromPrivateKey(privateKey);

  // Never issue a record with a private key that does not correspond to the
  // issuer's active registry key. That failure used to create a signature
  // which every later verification reported as Tampered. Rotation is an
  // explicit, auditable operation (scripts/rotate-institution-signing-key.ts)
  // that preserves historic documents through their key snapshots.
  const { data: institution, error: institutionError } = await admin
    .from("institutions")
    .select("signing_public_key")
    .eq("id", input.institutionId)
    .maybeSingle();
  if (institutionError) throw institutionError;
  if (!institution?.signing_public_key) {
    throw new ConfigError("This institution has no registered signing public key.");
  }
  if (normalizePublicKeyPem(institution.signing_public_key) !== signingPublicKey) {
    throw new ConfigError(
      "The configured signing key does not match this institution's registered key. " +
        "An administrator must complete the explicit signing-key rotation before issuing documents."
    );
  }

  // Register the active key before inserting the immutable document snapshot.
  // This also keeps ordinary onboarding/seed paths compatible with the
  // database trigger introduced for safe key rotation.
  const { error: keyHistoryError } = await admin
    .from("institution_signing_keys")
    .upsert(
      { institution_id: input.institutionId, public_key: signingPublicKey },
      { onConflict: "institution_id,public_key", ignoreDuplicates: true }
    );
  if (keyHistoryError) {
    throw new ConfigError(
      "Document signing key history is not configured. Apply the latest database migration before issuing documents."
    );
  }
  const signature = signHash(fileHash, privateKey);

  const { data, error } = await admin
    .from("documents")
    .insert({
      institution_id: input.institutionId,
      document_type: input.documentType,
      recipient_name: input.recipientName,
      file_hash: fileHash,
      signature,
      verification_id: verificationId,
      qr_payload: qrPayload,
      pin_code: pinCode,
      expiry_date: input.expiryDate ?? null,
      issued_at: input.issuedAt,
      signing_public_key_snapshot: signingPublicKey,
      original_file_data: embedded ? bufferToBytea(signedBuffer) : null,
      original_file_mime_type: embedded?.mimeType ?? null,
      original_file_name: embedded ? (input.fileName ?? "document") : null,
    })
    .select("id, verification_id, pin_code, qr_payload, status")
    .single();

  if (error) throw error;

  await admin.from("audit_logs").insert({
    actor_id: input.actorId,
    actor_type: input.actorType ?? "user",
    action: input.auditAction ?? "document.sign",
    target_table: "documents",
    target_id: data.id,
    metadata: { institution_id: input.institutionId, document_type: input.documentType },
  });

  return {
    id: data.id,
    verification_id: data.verification_id,
    pin_code: data.pin_code,
    qr_payload: data.qr_payload,
    qr_image: qrImage,
    status: data.status,
    has_original_download: embedded !== null,
  };
}
