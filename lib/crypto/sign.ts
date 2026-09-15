import crypto from "node:crypto";
import { ConfigError } from "@/lib/errors";

/** SHA-256 hex digest of raw document bytes. SRS 10.1 step 1-2. */
export function hashDocument(content: Buffer): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * Looks up an institution's ECDSA private key from the environment.
 * Private key material never touches the database (SRS 5.2, 10.1 step 3) —
 * it lives only as an env var named DOCUMENT_SIGNING_KEY_<INSTITUTION_ID>
 * (SRS 14), PEM-encoded with literal "\n" line breaks.
 */
export function getInstitutionPrivateKey(institutionId: string): string {
  const envVar = `DOCUMENT_SIGNING_KEY_${institutionId.replace(/-/g, "_").toUpperCase()}`;
  const raw = process.env[envVar];
  if (!raw) {
    throw new ConfigError(
      `No signing key configured for this institution. Generate one with the ` +
        `key-gen script (docs/ENVIRONMENT.md) and set ${envVar} in your environment.`
    );
  }
  return raw.replace(/\\n/g, "\n");
}

/**
 * Canonical PEM form used for registry comparisons and per-document key
 * snapshots. Normalising line endings avoids false key-mismatch failures
 * when a secret manager rewrites PEM newlines on deployment.
 */
export function normalizePublicKeyPem(publicKeyPem: string): string {
  return publicKeyPem.replace(/\r\n/g, "\n").trim();
}

/** Returns the public half of an ECDSA private key without exposing it. */
export function publicKeyFromPrivateKey(privateKeyPem: string): string {
  return normalizePublicKeyPem(
    crypto
      .createPublicKey(privateKeyPem)
      .export({ type: "spki", format: "pem" })
      .toString()
  );
}

/**
 * Looks up Chekkam's own platform-level ECDSA private key, used to sign
 * verification receipts (FR-111) — a receipt attests "Chekkam verified
 * this," not "institution X issued this," so it is never signed with an
 * institution's key. Same env-var-only, PEM-with-literal-\n convention as
 * getInstitutionPrivateKey.
 */
export function getChekkamReceiptSigningKey(): string {
  const raw = process.env.CHEKKAM_RECEIPT_SIGNING_KEY;
  if (!raw) {
    throw new ConfigError(
      "No CHEKKAM_RECEIPT_SIGNING_KEY configured. Generate one with " +
        "`npm run generate-signing-key` and set it in your environment."
    );
  }
  return raw.replace(/\\n/g, "\n");
}

/** Signs a SHA-256 hash with an institution's ECDSA (P-256) private key. SRS 10.1 step 3. */
export function signHash(hashHex: string, privateKeyPem: string): string {
  const signer = crypto.createSign("SHA256");
  signer.update(hashHex);
  signer.end();
  return signer.sign(privateKeyPem).toString("base64");
}

/**
 * Generates a new ECDSA P-256 key pair for onboarding an institution.
 * Run via the `generate-signing-key` script; store the private key in the
 * environment/secrets manager and `publicKey` in institutions.signing_public_key.
 */
export function generateSigningKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1", // NIST P-256
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}
