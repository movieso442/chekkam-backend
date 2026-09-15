import { describe, expect, it, vi } from "vitest";
import { verifyByIdOrPin, verifyByUpload } from "@/lib/documents/verify";
import { hashDocument, generateSigningKeyPair, signHash } from "@/lib/crypto/sign";

function makeAdmin(doc: Record<string, unknown> | null) {
  const docBuilder: Record<string, unknown> = {
    select: vi.fn(() => docBuilder),
    or: vi.fn(() => docBuilder),
    eq: vi.fn(() => docBuilder),
    maybeSingle: vi.fn(async () => ({ data: doc, error: null })),
  };
  const logInsert = vi.fn(async () => ({ data: null, error: null }));
  return {
    from: vi.fn((table: string) =>
      table === "document_verification_logs" ? { insert: logInsert } : docBuilder
    ),
  };
}

const { publicKey, privateKey } = generateSigningKeyPair();
const { publicKey: wrongPublicKey } = generateSigningKeyPair();
const fileHash = hashDocument(Buffer.from("doc content"));
const validSignature = signHash(fileHash, privateKey);

describe("verifyByIdOrPin", () => {
  it("returns not_found when no document matches", async () => {
    const admin = makeAdmin(null);
    const result = await verifyByIdOrPin(admin as never, "CHK-XXXX-XXXX", "web");
    expect(result.status).toBe("not_found");
  });

  it("returns revoked (with reason) when the document is revoked", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "revoked",
      revoked_at: "2026-01-01T00:00:00Z",
      revocation_reason: "Reported as fraudulent",
      document_type: "certificate",
      institutions: { name: "Test University" },
    });
    const result = await verifyByIdOrPin(admin as never, "CHK-XXXX-XXXX", "web");
    expect(result.status).toBe("revoked");
    expect(result.reason).toBe("Reported as fraudulent");
  });

  it("returns expired when expiry_date is in the past", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "active",
      expiry_date: "2020-01-01T00:00:00Z",
      document_type: "license",
      institutions: { name: "Test University" },
    });
    const result = await verifyByIdOrPin(admin as never, "CHK-XXXX-XXXX", "web");
    expect(result.status).toBe("expired");
  });

  it("returns genuine when active, not expired, and the stored signature is valid", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "active",
      expiry_date: null,
      file_hash: fileHash,
      signature: validSignature,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: publicKey },
    });
    const result = await verifyByIdOrPin(admin as never, "CHK-XXXX-XXXX", "web");
    expect(result.status).toBe("genuine");
  });

  it("returns tampered when the stored signature doesn't verify against the institution's public key", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "active",
      expiry_date: null,
      file_hash: fileHash,
      signature: validSignature,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: wrongPublicKey },
    });
    const result = await verifyByIdOrPin(admin as never, "CHK-XXXX-XXXX", "web");
    expect(result.status).toBe("tampered");
  });

  it("keeps a historic document genuine after its institution rotates to a new public key", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "active",
      expiry_date: null,
      file_hash: fileHash,
      signature: validSignature,
      signing_public_key_snapshot: publicKey,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: wrongPublicKey },
    });
    const result = await verifyByIdOrPin(admin as never, "CHK-XXXX-XXXX", "web");
    expect(result.status).toBe("genuine");
  });
});

describe("verifyByUpload", () => {
  it("returns tampered when the uploaded file's hash doesn't match the stored hash", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "active",
      expiry_date: null,
      file_hash: "a-completely-different-hash",
      signature: validSignature,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: publicKey },
    });
    const result = await verifyByUpload(
      admin as never,
      Buffer.from("doc content"),
      "CHK-XXXX-XXXX",
      "web"
    );
    expect(result.status).toBe("tampered");
  });

  it("returns genuine when the uploaded file's hash matches and the signature is valid", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "active",
      expiry_date: null,
      file_hash: fileHash,
      signature: validSignature,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: publicKey },
    });
    const result = await verifyByUpload(
      admin as never,
      Buffer.from("doc content"),
      "CHK-XXXX-XXXX",
      "web"
    );
    expect(result.status).toBe("genuine");
  });

  it("returns not_found for a hash-only lookup that matches nothing", async () => {
    const admin = makeAdmin(null);
    const result = await verifyByUpload(admin as never, Buffer.from("nothing"), null, "web");
    expect(result.status).toBe("not_found");
  });

  it("returns revoked even when the uploaded bytes still match exactly (precedence over genuine)", async () => {
    const admin = makeAdmin({
      id: "doc-1",
      status: "revoked",
      revoked_at: "2026-02-01T00:00:00Z",
      revocation_reason: "Superseded",
      expiry_date: null,
      file_hash: fileHash,
      signature: validSignature,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: publicKey },
    });
    const result = await verifyByUpload(
      admin as never,
      Buffer.from("doc content"),
      "CHK-XXXX-XXXX",
      "web"
    );
    expect(result.status).toBe("revoked");
    expect(result.reason).toBe("Superseded");
  });

  it("returns tampered — not genuine — when a hash mismatch is only rescued by a findable ID inside the bytes", async () => {
    // Regression test: the hash-only lookup's ID-extraction fallback used to
    // call verifyByIdOrPin() directly, which has no uploaded file to hash —
    // so ANY tampered copy that still contains its own findable
    // "CHK-XXXX-XXXX" text (printed on a certificate, or, since
    // lib/documents/embed/, invisibly embedded in the file's own metadata)
    // was reported "genuine" purely because the ID existed and was active,
    // regardless of whether these exact bytes matched what was signed.
    //
    // Needs a mock that actually distinguishes the two lookups (the shared
    // makeAdmin() ignores its filter arguments and would return the same
    // doc for both, defeating the scenario) — first .maybeSingle() call is
    // the failed hash-only lookup, second is the ID-based one the fallback
    // triggers.
    const doc = {
      id: "doc-1",
      status: "active",
      expiry_date: null,
      file_hash: fileHash,
      signature: validSignature,
      document_type: "certificate",
      institutions: { name: "Test University", signing_public_key: publicKey },
    };
    let maybeSingleCallCount = 0;
    const docBuilder: Record<string, unknown> = {
      select: vi.fn(() => docBuilder),
      or: vi.fn(() => docBuilder),
      eq: vi.fn(() => docBuilder),
      maybeSingle: vi.fn(async () => {
        maybeSingleCallCount += 1;
        // 1st call: hash-only lookup — no row has this (wrong) hash.
        // 2nd call: the ID-extraction fallback's own lookup — finds the doc.
        return { data: maybeSingleCallCount === 1 ? null : doc, error: null };
      }),
    };
    const logInsert = vi.fn(async () => ({ data: null, error: null }));
    const admin = {
      from: vi.fn((table: string) =>
        table === "document_verification_logs" ? { insert: logInsert } : docBuilder
      ),
    };

    const tamperedBufferWithFindableId = Buffer.from(
      "this is NOT the original content, but it still has CHK-XXXX-XXXX printed in it"
    );
    const result = await verifyByUpload(admin as never, tamperedBufferWithFindableId, null, "web");
    expect(result.status).toBe("tampered");
  });
});
