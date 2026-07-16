/**
 * Adversarial tests required by pol.must_do.150 BEFORE codex review.
 *
 * These test the CLIENT's request-building/response-handling logic, not the hosted
 * server's cryptography (this package is a thin client — the server owns signing and
 * verification). What must hold here: the client never silently downgrades an explicit
 * PQ requirement, never trusts a malformed kid, and never lets a slow/oversized response
 * consume unbounded time or memory.
 *
 * The PQ-strip response fixtures below are the REAL shape returned by the live hosted
 * server (confirmed via a manual call against trust-gate-mcp.onrender.com with a receipt
 * whose PQ signature fields were absent) — not an invented field name. Default (no
 * require_pq) returned `{ok:false, legs:{ed25519:"ok",ml_dsa:"absent",slh_dsa:"absent"},
 * reason:"PQ-required: ..."}`; `require_pq:false` on the same receipt returned
 * `{ok:true, legs:{...}, reason:"...verified from the cert alone via: ed25519"}`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { isValidKid, mcpCall, TrustGateError } from "../src/client.js";
import { verifyReceipt } from "../src/tools/verify-receipt.js";
import { mintActionReceipt } from "../src/tools/mint-action-receipt.js";

function installMockFetch(handler: (url: string, init?: RequestInit) => Promise<Response> | Response) {
  const original = globalThis.fetch;
  // @ts-expect-error -- test double, not the full fetch signature
  globalThis.fetch = handler;
  return () => {
    globalThis.fetch = original;
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  const text = JSON.stringify(body);
  return {
    ok: status < 400,
    status,
    text: async () => text,
    json: async () => body,
    body: null, // forces the text()-fallback path in readJsonCapped
  } as unknown as Response;
}

function lastRpcArgs(calls: Array<{ init?: RequestInit }>): Record<string, unknown> {
  const body = JSON.parse(String(calls[calls.length - 1].init?.body));
  return body.params.arguments;
}

function mockFetchOnce(responseBody: unknown, status = 200) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const restore = installMockFetch(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return jsonResponse(responseBody, status);
  });
  return { calls, restore };
}

// --- H3: PQ-strip attack (real server response shape) -----------------------

test("verifyReceipt: requirePq left undefined is NOT sent — server obeys its own default-true", async () => {
  const { calls, restore } = mockFetchOnce({
    result: {
      structuredContent: {
        ok: false,
        legs: { ed25519: "ok", ml_dsa: "absent", slh_dsa: "absent" },
        reason: "PQ-required: no post-quantum signature leg verified",
      },
    },
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

test("verifyReceipt: a PQ-stripped receipt under the DEFAULT (no requirePq) is surfaced as rejected, not silently accepted", async () => {
  // Real server response for a receipt with absent ml_dsa/slh_dsa legs, requested
  // without require_pq (server obeys its own default-true).
  const { restore } = mockFetchOnce({
    result: {
      structuredContent: {
        ok: false,
        hash_ok: true,
        sig_ok: true,
        signed: true,
        legs: { ed25519: "ok", ml_dsa: "absent", slh_dsa: "absent" },
        reason:
          "PQ-required: no post-quantum signature leg verified (ml_dsa=absent, slh_dsa=absent).",
      },
    },
  });
  try {
    const result = (await verifyReceipt.execute({
      receipt: { evidence_hash: "x", signature_b64: "y" },
    })) as Record<string, unknown>;
    assert.equal(
      result.ok,
      false,
      "a stripped-PQ receipt must be surfaced as ok:false under the default — never hidden or upgraded"
    );
    assert.match(String(result.reason), /PQ-required/);
  } finally {
    restore();
  }
});

test("verifyReceipt: the SAME stripped-PQ receipt is accepted only when the caller explicitly opts out with requirePq:false", async () => {
  const { calls, restore } = mockFetchOnce({
    result: {
      structuredContent: {
        ok: true,
        hash_ok: true,
        sig_ok: true,
        signed: true,
        legs: { ed25519: "ok", ml_dsa: "absent", slh_dsa: "absent" },
        reason: "hash valid; verified from the cert alone via: ed25519",
      },
    },
  });
  try {
    const result = (await verifyReceipt.execute({
      receipt: { evidence_hash: "x", signature_b64: "y" },
      requirePq: false,
    })) as Record<string, unknown>;
    assert.equal(lastRpcArgs(calls).require_pq, false, "the opt-out must actually reach the server");
    assert.equal(result.ok, true, "an explicit opt-out is honored — the client doesn't second-guess it");
  } finally {
    restore();
  }
});

test("verifyReceipt: explicit requirePq:true is not dropped as a no-op", async () => {
  const { calls, restore } = mockFetchOnce({
    result: { structuredContent: { ok: true, legs: { ed25519: "ok", ml_dsa: "ok", slh_dsa: "absent" } } },
  });
  try {
    await verifyReceipt.execute({
      receipt: { evidence_hash: "x", signature_b64: "y" },
      requirePq: true,
    });
    assert.equal(lastRpcArgs(calls).require_pq, true);
  } finally {
    restore();
  }
});

// --- H4: kid width (128-bit / 32 hex chars), wired into mcpCall itself ------

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

// Real hosted server shape, confirmed live: mint_action_receipt's structuredContent is
// itself `{ result: { atom_id, kid, ... } }` -- one level deeper than a flat kid field.
// The kid check must reach it there, not just at the top level.

test("mcpCall: a mint response with a malformed kid is REJECTED, not silently passed through (H4 wired end-to-end, real nested shape)", async () => {
  const { restore } = mockFetchOnce({
    result: {
      structuredContent: {
        result: {
          atom_id: "oao-x",
          signed: true,
          kid: "not-a-valid-kid-this-is-way-too-long-to-be-128-bits",
        },
      },
    },
  });
  try {
    await assert.rejects(
      () => mintActionReceipt.execute({ agentId: "a", operation: "deploy", target: "prod" }),
      (err: unknown) => err instanceof TrustGateError && /malformed kid/i.test(err.message)
    );
  } finally {
    restore();
  }
});

test("mcpCall: a mint response with a well-formed kid (real nested shape) passes through untouched", async () => {
  const { restore } = mockFetchOnce({
    result: { structuredContent: { result: { atom_id: "oao-x", signed: true, kid: VALID_32_HEX_KID } } },
  });
  try {
    const result = (await mintActionReceipt.execute({
      agentId: "a",
      operation: "deploy",
      target: "prod",
    })) as Record<string, unknown>;
    assert.equal((result.result as Record<string, unknown>).kid, VALID_32_HEX_KID);
  } finally {
    restore();
  }
});

// --- R4: response body must be bounded in both size and time ----------------

function mockStreamResponse(
  chunkBytes: number[],
  opts: { hangAfter?: boolean } = {}
): Response {
  let i = 0;
  const reader = {
    read: async () => {
      if (i < chunkBytes.length) {
        const value = new Uint8Array(chunkBytes[i]).fill(97); // 'a'
        i++;
        return { done: false, value };
      }
      if (opts.hangAfter) {
        // Simulates a stalled connection: this promise never resolves on its own.
        return new Promise<{ done: boolean; value?: Uint8Array }>(() => {});
      }
      return { done: true, value: undefined };
    },
    cancel: async () => {},
  };
  return {
    ok: true,
    status: 200,
    body: { getReader: () => reader },
    text: async () => {
      throw new Error("text() should not be called when a streamable body is present");
    },
    json: async () => {
      throw new Error("json() should not be called when a streamable body is present");
    },
  } as unknown as Response;
}

test("mcpCall: a response body over the byte cap is rejected rather than buffered without bound", async () => {
  const restore = installMockFetch(async () => mockStreamResponse([600_000, 600_000]));
  try {
    await assert.rejects(
      () => mcpCall("mint_action_receipt", { agent_id: "a" }),
      (err: unknown) => err instanceof TrustGateError && /byte cap/i.test(err.message)
    );
  } finally {
    restore();
  }
});

test("mcpCall: a stalled body (headers received, body never completes) is bounded by the timeout, not left to hang", async () => {
  const restore = installMockFetch(async () => mockStreamResponse([10], { hangAfter: true }));
  const start = Date.now();
  try {
    await assert.rejects(
      () => mcpCall("mint_action_receipt", { agent_id: "a" }, { timeoutMs: 150 }),
      (err: unknown) => err instanceof TrustGateError
    );
    const elapsed = Date.now() - start;
    assert.ok(
      elapsed < 2000,
      `expected the stalled read to be aborted near the 150ms timeout, took ${elapsed}ms`
    );
  } finally {
    restore();
  }
});
