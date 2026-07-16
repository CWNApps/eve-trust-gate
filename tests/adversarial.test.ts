/**
 * Adversarial tests required by pol.must_do.150 BEFORE codex review.
 *
 * These test the CLIENT's request-building/response-handling logic, not the
 * hosted server's cryptography (this package is a thin client — the server owns
 * signing and verification). What must hold here: the client never silently
 * downgrades an explicit PQ requirement, and never trusts a malformed kid.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { isValidKid } from "../src/client.js";
import { verifyReceipt } from "../src/tools/verify-receipt.js";

function mockFetchOnce(responseBody: unknown, status = 200) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const original = globalThis.fetch;
  // @ts-expect-error -- test double, not the full fetch signature
  globalThis.fetch = async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return {
      ok: status < 400,
      status,
      json: async () => responseBody,
      text: async () => JSON.stringify(responseBody),
    } as Response;
  };
  return { calls, restore: () => (globalThis.fetch = original) };
}

function lastRpcArgs(calls: Array<{ init?: RequestInit }>): Record<string, unknown> {
  const body = JSON.parse(String(calls[calls.length - 1].init?.body));
  return body.params.arguments;
}

// --- H3: PQ-strip attack -----------------------------------------------------

test("verifyReceipt: requirePq left undefined is NOT sent — server obeys its own default-true", async () => {
  const { calls, restore } = mockFetchOnce({
    result: { structuredContent: { ok: true, signed: true } },
  });
  try {
    await verifyReceipt.execute({ receipt: { evidence_hash: "x", signature_b64: "y" } });
    const args = lastRpcArgs(calls);
    assert.equal(
      "require_pq" in args,
      false,
      "client must not inject a require_pq value when the caller didn't specify one"
    );
  } finally {
    restore();
  }
});

test("verifyReceipt: explicit requirePq:false passes through untouched (opt-out, not swallowed)", async () => {
  const { calls, restore } = mockFetchOnce({
    result: { structuredContent: { ok: true, signed: true, quantum_verified: false } },
  });
  try {
    await verifyReceipt.execute({
      receipt: { evidence_hash: "x", signature_b64: "y" },
      requirePq: false,
    });
    const args = lastRpcArgs(calls);
    assert.equal(args.require_pq, false);
  } finally {
    restore();
  }
});

test("verifyReceipt: explicit requirePq:true passes through untouched (not dropped as a no-op)", async () => {
  const { calls, restore } = mockFetchOnce({
    result: { structuredContent: { ok: true, signed: true, quantum_verified: true } },
  });
  try {
    await verifyReceipt.execute({
      receipt: { evidence_hash: "x", signature_b64: "y" },
      requirePq: true,
    });
    const args = lastRpcArgs(calls);
    assert.equal(args.require_pq, true);
  } finally {
    restore();
  }
});

test("verifyReceipt: a stripped-PQ server response (quantum_verified:false) is surfaced to the caller untouched, never hidden or upgraded", async () => {
  const { restore } = mockFetchOnce({
    result: {
      structuredContent: {
        ok: true,
        signed: true,
        quantum_verified: false,
        reason: "ML-DSA-65 signature stripped",
      },
    },
  });
  try {
    const result = (await verifyReceipt.execute({
      receipt: { evidence_hash: "x", signature_b64: "y" },
    })) as Record<string, unknown>;
    assert.equal(
      result.quantum_verified,
      false,
      "a PQ-stripped response must reach the caller as-is — the client must never mask a downgrade"
    );
  } finally {
    restore();
  }
});

// --- H4: kid width (128-bit / 32 hex chars) ---------------------------------

const VALID_32_HEX_KID = "a1b2c3d4e5f60718293a4b5c6d7e8f9a"; // 32 hex chars exactly

test("isValidKid: accepts a well-formed 128-bit (32 hex char) kid", () => {
  assert.equal(VALID_32_HEX_KID.length, 32, "fixture must actually be 32 chars");
  assert.equal(isValidKid(VALID_32_HEX_KID), true);
});

test("isValidKid: rejects a kid one character too short (31 hex chars)", () => {
  const tooShort = VALID_32_HEX_KID.slice(0, 31);
  assert.equal(tooShort.length, 31);
  assert.equal(isValidKid(tooShort), false);
});

test("isValidKid: rejects a kid one character too long (33 hex chars)", () => {
  const tooLong = VALID_32_HEX_KID + "0";
  assert.equal(tooLong.length, 33);
  assert.equal(isValidKid(tooLong), false);
});

test("isValidKid: rejects a kid of the wrong width (e.g. a full SHA-256, 64 hex chars — untruncated)", () => {
  assert.equal(isValidKid(VALID_32_HEX_KID.repeat(2)), false);
});

test("isValidKid: rejects non-hex and non-string kid values", () => {
  assert.equal(isValidKid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), false);
  assert.equal(isValidKid(undefined), false);
  assert.equal(isValidKid(12345), false);
});
