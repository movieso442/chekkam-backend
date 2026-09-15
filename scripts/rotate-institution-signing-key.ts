// Explicit, idempotent signing-key rotation for an institution.
//
// Usage:
//   CONFIRM_SIGNING_KEY_ROTATION=<institution-id> \
//     npm run rotate-signing-key -- <institution-id>
//
// The migration 0019_document_signing_key_history.sql must be applied first.
// It snapshots the previous issuer key on every existing document, so moving
// the institution to the configured private key does not invalidate historic
// documents. This script never prints private-key material.
import { createClient } from "@supabase/supabase-js";
import { loadEnv, requireEnv } from "./lib/load-env.mjs";
import {
  getInstitutionPrivateKey,
  normalizePublicKeyPem,
  publicKeyFromPrivateKey,
} from "../lib/crypto/sign";

loadEnv();
requireEnv(["NEXT_PUBLIC_SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]);

const institutionId = process.argv[2]?.trim();

function fail(message: string): never {
  console.error(`[rotate-signing-key] ${message}`);
  process.exit(1);
}

if (!institutionId) {
  fail("Provide the institution UUID: npm run rotate-signing-key -- <institution-id>");
}
if (process.env.CONFIRM_SIGNING_KEY_ROTATION !== institutionId) {
  fail(
    "Refusing to rotate without an exact confirmation. Set CONFIRM_SIGNING_KEY_ROTATION to the same institution UUID."
  );
}

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } }
);

async function ensureKeyRegistered(publicKey: string) {
  const { error } = await supabase
    .from("institution_signing_keys")
    .upsert(
      { institution_id: institutionId, public_key: publicKey },
      { onConflict: "institution_id,public_key", ignoreDuplicates: true }
    );
  if (error) {
    fail(
      "Could not register the signing key history. Apply database migration 0019_document_signing_key_history.sql first."
    );
  }
}

async function main() {
  const { data: institution, error: institutionError } = await supabase
    .from("institutions")
    .select("id, name, signing_public_key")
    .eq("id", institutionId)
    .maybeSingle();
  if (institutionError) fail("Could not load the institution record.");
  if (!institution) fail("No institution exists for that UUID.");

  const { count, error: countError } = await supabase
    .from("documents")
    .select("id", { count: "exact", head: true })
    .eq("institution_id", institutionId);
  if (countError) fail("Could not inspect existing documents.");

  const oldPublicKey = institution.signing_public_key
    ? normalizePublicKeyPem(institution.signing_public_key)
    : null;
  if (!oldPublicKey && (count ?? 0) > 0) {
    fail("The institution has existing documents but no current public key; refusing an unsafe rotation.");
  }

  const newPublicKey = publicKeyFromPrivateKey(getInstitutionPrivateKey(institutionId));

  // Preserve the current trust chain before the institution profile changes.
  if (oldPublicKey) {
    await ensureKeyRegistered(oldPublicKey);
    const { error: snapshotError } = await supabase
      .from("documents")
      .update({ signing_public_key_snapshot: oldPublicKey })
      .eq("institution_id", institutionId)
      .is("signing_public_key_snapshot", null);
    if (snapshotError) {
      fail("Could not snapshot historic documents; the institution key was not changed.");
    }
  }

  await ensureKeyRegistered(newPublicKey);

  if (oldPublicKey === newPublicKey) {
    console.log(`[rotate-signing-key] ${institution.name}: key already matches; historic snapshots are ready.`);
    return;
  }

  const { error: updateError } = await supabase
    .from("institutions")
    .update({ signing_public_key: newPublicKey })
    .eq("id", institutionId);
  if (updateError) {
    fail("Could not activate the new signing key; the previous registry key remains active.");
  }

  if (oldPublicKey) {
    const { error: retireError } = await supabase
      .from("institution_signing_keys")
      .update({ retired_at: new Date().toISOString() })
      .eq("institution_id", institutionId)
      .eq("public_key", oldPublicKey);
    if (retireError) {
      // The new key is already active and historic snapshots preserve every
      // document. Leaving the historic key unretired is conservative and can
      // be corrected by re-running this idempotent script.
      console.warn("[rotate-signing-key] New key is active; historic key retirement could not be recorded.");
    }
  }

  console.log(`[rotate-signing-key] ${institution.name}: rotation complete; historic documents remain verifiable.`);
}

void main();
