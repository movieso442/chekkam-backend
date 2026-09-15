import { SupabaseClient } from "@supabase/supabase-js";
import { hashDocument } from "@/lib/crypto/sign";
import { verifySignature } from "@/lib/crypto/verify";

/**
 * The one and only document verification path (SRS 10.2). Extracted from
 * app/api/documents/verify/[verificationId]/route.ts and verify-upload/route.ts
 * so WhatsApp, Telegram, and any future channel call the exact same logic
 * instead of a re-implementation. The two HTTP routes are now thin wrappers
 * around these functions — behavior is unchanged.
 */
export type VerifierChannel =
  | "mobile"
  | "web"
  | "api"
  | "whatsapp"
  | "telegram"
  | "extension"
  | "widget"
  | "share_intent";

const VERIFIER_CHANNELS: readonly VerifierChannel[] = [
  "mobile",
  "web",
  "api",
  "whatsapp",
  "telegram",
  "extension",
  "widget",
  "share_intent",
];

/** Ensures a public endpoint cannot write an arbitrary channel string into the database. */
export function verifierChannelFrom(
  value: string | null | undefined,
  fallback: VerifierChannel = "web"
): VerifierChannel {
  return VERIFIER_CHANNELS.includes(value as VerifierChannel) ? (value as VerifierChannel) : fallback;
}

export type VerifyResult = {
  status: "genuine" | "tampered" | "revoked" | "expired" | "not_found";
  institution?: string | null;
  /** True only when Chekkam has separately verified the issuing organisation. */
  institution_verified?: boolean;
  document_type?: string;
  recipient_name?: string | null;
  verification_id?: string;
  issued_at?: string;
  revoked_at?: string;
  expiry_date?: string | null;
  reason?: string | null;
};

const TAMPERED_CONTENT_REASON =
  "The submitted file's content does not match what the issuing institution originally signed.";
const TAMPERED_SIGNATURE_REASON =
  "This record's digital signature does not match the issuing institution's key. It may not be genuine.";

function isExpired(expiryDate: string | null | undefined): boolean {
  return !!expiryDate && new Date(expiryDate) < new Date();
}

/**
 * Re-validates the stored ECDSA signature against the institution's public
 * key, catching a DB record forged without ever holding the institution's
 * private key (hash comparison alone can't detect this). Graceful by
 * design: a missing signature/public key (e.g. a pre-signature-check record)
 * is not treated as tampering — there's nothing to check against.
 */
function hasValidStoredSignature(
  fileHash: string | null | undefined,
  signature: string | null | undefined,
  publicKey: string | null | undefined
): boolean {
  if (!fileHash || !signature || !publicKey) return true;
  return verifySignature(fileHash, signature, publicKey);
}

async function logAttempt(
  admin: SupabaseClient,
  documentId: string | null,
  attempted: string,
  result: VerifyResult["status"],
  channel: VerifierChannel
) {
  await admin.from("document_verification_logs").insert({
    document_id: documentId,
    verification_id_attempted: attempted,
    result,
    verifier_channel: channel,
  });
}

/**
 * Look up by verification ID or PIN. No uploaded file, so content-tamper
 * detection isn't possible — but the stored hash+signature pair is still
 * re-validated against the institution's public key (SRS 10.2 steps 1-3,
 * extended with signature re-validation).
 */
export async function verifyByIdOrPin(
  admin: SupabaseClient,
  verificationId: string,
  channel: VerifierChannel
): Promise<VerifyResult> {
  const { data: doc } = await admin
    .from("documents")
    .select(
      "id, verification_id, document_type, recipient_name, status, issued_at, revoked_at, revocation_reason, expiry_date, file_hash, signature, signing_public_key_snapshot, institutions(name, verified, signing_public_key)"
    )
    .or(`verification_id.eq.${verificationId},pin_code.eq.${verificationId}`)
    .maybeSingle();

  if (!doc) {
    await logAttempt(admin, null, verificationId, "not_found", channel);
    return { status: "not_found", verification_id: verificationId };
  }

  const institution = Array.isArray(doc.institutions) ? doc.institutions[0] : doc.institutions;

  if (doc.status === "revoked") {
    await logAttempt(admin, doc.id, verificationId, "revoked", channel);
    return {
      status: "revoked",
      institution: institution?.name ?? null,
      institution_verified: institution?.verified === true,
      document_type: doc.document_type,
      verification_id: doc.verification_id,
      revoked_at: doc.revoked_at,
      reason: doc.revocation_reason,
    };
  }

  if (isExpired(doc.expiry_date)) {
    await logAttempt(admin, doc.id, verificationId, "expired", channel);
    return {
      status: "expired",
      institution: institution?.name ?? null,
      institution_verified: institution?.verified === true,
      document_type: doc.document_type,
      verification_id: doc.verification_id,
      expiry_date: doc.expiry_date,
      reason: `This document's validity period ended on ${doc.expiry_date}.`,
    };
  }

  if (
    !hasValidStoredSignature(
      doc.file_hash,
      doc.signature,
      doc.signing_public_key_snapshot ?? institution?.signing_public_key
    )
  ) {
    await logAttempt(admin, doc.id, verificationId, "tampered", channel);
    return {
      status: "tampered",
      institution: institution?.name ?? null,
      institution_verified: institution?.verified === true,
      document_type: doc.document_type,
      verification_id: doc.verification_id,
      reason: TAMPERED_SIGNATURE_REASON,
    };
  }

  await logAttempt(admin, doc.id, verificationId, "genuine", channel);
  return {
    status: "genuine",
    institution: institution?.name ?? null,
    institution_verified: institution?.verified === true,
    document_type: doc.document_type,
    recipient_name: doc.recipient_name,
    verification_id: doc.verification_id,
    issued_at: doc.issued_at,
  };
}

/**
 * Verify by uploaded file bytes, optionally scoped to a known verification
 * ID/PIN (hash comparison -> genuine/tampered), or by hash-only search when
 * no ID is given (SRS 10.2 step 4 + "given only an uploaded file").
 */
export async function verifyByUpload(
  admin: SupabaseClient,
  fileBuffer: Buffer,
  verificationId: string | null | undefined,
  channel: VerifierChannel
): Promise<VerifyResult> {
  const computedHash = hashDocument(fileBuffer);

  if (verificationId) {
    const { data: doc } = await admin
      .from("documents")
      .select(
        "id, verification_id, file_hash, signature, signing_public_key_snapshot, document_type, recipient_name, status, revoked_at, revocation_reason, expiry_date, institutions(name, verified, signing_public_key)"
      )
      .or(`verification_id.eq.${verificationId},pin_code.eq.${verificationId}`)
      .maybeSingle();

    if (!doc) {
      await logAttempt(admin, null, verificationId, "not_found", channel);
      return { status: "not_found", verification_id: verificationId };
    }

    const institution = Array.isArray(doc.institutions) ? doc.institutions[0] : doc.institutions;

    if (doc.status === "revoked") {
      await logAttempt(admin, doc.id, verificationId, "revoked", channel);
      return {
        status: "revoked",
        institution: institution?.name ?? null,
        institution_verified: institution?.verified === true,
        document_type: doc.document_type,
        verification_id: doc.verification_id,
        reason: doc.revocation_reason,
      };
    }

    if (isExpired(doc.expiry_date)) {
      await logAttempt(admin, doc.id, verificationId, "expired", channel);
      return {
        status: "expired",
        institution: institution?.name ?? null,
        institution_verified: institution?.verified === true,
        document_type: doc.document_type,
        verification_id: doc.verification_id,
        expiry_date: doc.expiry_date,
        reason: `This document's validity period ended on ${doc.expiry_date}.`,
      };
    }

    const hashMatches = doc.file_hash === computedHash;
    const signatureValid = hasValidStoredSignature(
      doc.file_hash,
      doc.signature,
      doc.signing_public_key_snapshot ?? institution?.signing_public_key
    );
    const genuine = hashMatches && signatureValid;
    await logAttempt(admin, doc.id, verificationId, genuine ? "genuine" : "tampered", channel);
    return {
      status: genuine ? "genuine" : "tampered",
      institution: institution?.name ?? null,
      institution_verified: institution?.verified === true,
      document_type: doc.document_type,
      recipient_name: doc.recipient_name,
      verification_id: doc.verification_id,
      reason: genuine
        ? undefined
        : hashMatches
          ? TAMPERED_SIGNATURE_REASON
          : TAMPERED_CONTENT_REASON,
    };
  }

  // No verification_id given: search by hash alone.
  const { data: doc } = await admin
    .from("documents")
    .select(
      "id, verification_id, document_type, status, revocation_reason, expiry_date, file_hash, signature, signing_public_key_snapshot, institutions(name, verified, signing_public_key)"
    )
    .eq("file_hash", computedHash)
    .maybeSingle();

  if (!doc) {
    // If hash-only lookup failed, check if the uploaded file contains a
    // findable Verification ID (CHK-XXXX-XXXX) — e.g. printed on a
    // certificate, or (since lib/documents/embed/) invisibly embedded in the
    // file's own metadata. Recurses into this same function WITH that ID so
    // the hash/signature of *these exact uploaded bytes* still gets checked
    // via the branch above — never verifyByIdOrPin, which has no file to
    // hash and would report "genuine" for a tampered copy purely because a
    // findable ID happens to still be readable inside it.
    const bufferString = fileBuffer.toString("binary");
    const match = bufferString.match(/CHK-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}/i);
    if (match) {
      const extractedId = match[0].toUpperCase();
      return verifyByUpload(admin, fileBuffer, extractedId, channel);
    }

    await logAttempt(admin, null, "(hash-only lookup)", "not_found", channel);
    return { status: "not_found" };
  }

  const institution = Array.isArray(doc.institutions) ? doc.institutions[0] : doc.institutions;

  let result: VerifyResult["status"];
  let reason: string | null | undefined;
  if (doc.status === "revoked") {
    result = "revoked";
    reason = doc.revocation_reason;
  } else if (isExpired(doc.expiry_date)) {
    result = "expired";
    reason = `This document's validity period ended on ${doc.expiry_date}.`;
  } else if (
    !hasValidStoredSignature(
      doc.file_hash,
      doc.signature,
      doc.signing_public_key_snapshot ?? institution?.signing_public_key
    )
  ) {
    result = "tampered";
    reason = TAMPERED_SIGNATURE_REASON;
  } else {
    result = "genuine";
    reason = undefined;
  }

  await logAttempt(admin, doc.id, doc.verification_id, result, channel);
  return {
    status: result,
    institution: institution?.name ?? null,
    institution_verified: institution?.verified === true,
    document_type: doc.document_type,
    verification_id: doc.verification_id,
    expiry_date: result === "expired" ? doc.expiry_date : undefined,
    reason,
  };
}
