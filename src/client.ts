/**
 * Transport layer for the hosted Trust Gate MCP server.
 *
 * Same wire protocol as langchain-trust-gate / crewai-trust-gate / llama-index-trust-gate:
 * one JSON-RPC 2.0 `tools/call` POST to `/mcp`, plus one fire-and-forget telemetry ping to
 * `/x?via=eve`. No PII, no cookies — telemetry is a bare channel-attribution tag and never
 * blocks or fails a tool call.
 */

export const TRUST_GATE_URL =
  process.env.TRUST_GATE_URL ?? "https://trust-gate-mcp.onrender.com";

const VIA = "eve";

// R4 (pol.must_do.150): a stalled or malicious server can hold the connection open past
// headers and drip an unbounded body. 1MB is generous for a receipt/decision JSON payload
// and small enough to bound memory regardless of how slowly it arrives.
const MAX_RESPONSE_BYTES = 1_000_000;

export class TrustGateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrustGateError";
  }
}

interface McpCallOptions {
  timeoutMs?: number;
}

async function withTimeout<T>(
  run: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await run(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

function abortRejection(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    const fail = () => reject(new TrustGateError("Trust Gate response read aborted (timeout)"));
    if (signal.aborted) {
      fail();
      return;
    }
    signal.addEventListener("abort", fail, { once: true });
  });
}

/**
 * Reads a Response body under `signal` and a byte cap. The timeout/abort deadline must
 * cover this, not just the initial `fetch()` — `fetch()` commonly resolves once headers
 * arrive, before the body has streamed, so a timer that stops at `fetch()` leaves the body
 * read unbounded (R4: a stalled-body or unbounded-body resource-exhaustion path).
 *
 * Each read races against the abort signal directly (not just a pre-read check) so a
 * stalled stream is bounded by the timeout even if the underlying runtime's reader
 * doesn't itself reject on abort.
 */
async function readJsonCapped(
  response: Response,
  signal: AbortSignal
): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) {
    // Some runtimes/mocks don't expose a streamable body; fall back to text(), still
    // under the same signal via the caller's overall withTimeout scope.
    const text = await Promise.race([response.text(), abortRejection(signal)]);
    if (text.length > MAX_RESPONSE_BYTES) {
      throw new TrustGateError(
        `Trust Gate response exceeded ${MAX_RESPONSE_BYTES} byte cap`
      );
    }
    return JSON.parse(text);
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), abortRejection(signal)]);
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new TrustGateError(
          `Trust Gate response exceeded ${MAX_RESPONSE_BYTES} byte cap`
        );
      }
      chunks.push(value);
    }
  } catch (err) {
    reader.cancel().catch(() => {});
    if (err instanceof TrustGateError) throw err;
    throw new TrustGateError(`Trust Gate response read failed: ${(err as Error).message}`);
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(combined));
}

/** H4 (pol.must_do.150): a Trust Gate `kid` is `sha256(pubkey_bytes)[:32]` hex chars —
 * exactly 128 bits. A `kid` of any other width indicates a malformed or spoofed
 * response and must not be trusted as a same-notary check. */
export function isValidKid(kid: unknown): kid is string {
  return typeof kid === "string" && /^[0-9a-f]{32}$/i.test(kid);
}

/** One JSON-RPC `tools/call` against the hosted Trust Gate MCP server. */
export async function mcpCall(
  method: string,
  args: Record<string, unknown>,
  options: McpCallOptions = {}
): Promise<Record<string, unknown>> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const payload = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: method, arguments: args },
  };

  let body: { error?: unknown; result?: unknown };
  try {
    body = (await withTimeout(async (signal) => {
      const response = await fetch(`${TRUST_GATE_URL}/mcp`, {
        method: "POST",
        signal,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": "2025-03-26",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const text = await readJsonCapped(response, signal).catch(() => "");
        throw new TrustGateError(
          `Trust Gate MCP ${response.status}: ${JSON.stringify(text).slice(0, 200)}`
        );
      }

      // Body read happens INSIDE the same timed/aborted scope as the fetch itself —
      // this is the fix for the R4 finding: headers-only resolution no longer leaves
      // the body read unbounded.
      return readJsonCapped(response, signal) as Promise<{
        error?: unknown;
        result?: unknown;
      }>;
    }, timeoutMs)) as { error?: unknown; result?: unknown };
  } catch (err) {
    if (err instanceof TrustGateError) throw err;
    throw new TrustGateError(
      `Cannot reach Trust Gate at ${TRUST_GATE_URL}: ${(err as Error).message}`
    );
  }

  if (body.error) {
    throw new TrustGateError(`Trust Gate MCP error: ${JSON.stringify(body.error)}`);
  }

  const result = extractResult(body.result);

  // H4: any kid present in a response must be well-formed, or the offline same-notary
  // check this field exists for cannot be trusted. Fail closed rather than pass a
  // malformed kid through silently.
  //
  // The kid can be one level deeper than `result` itself: confirmed live against the
  // hosted server, mint_action_receipt's structuredContent is itself shaped as
  // `{ result: { atom_id, kid, ... } }` (not flat) — the Python siblings pass this
  // exact shape through unmodified too (langchain/crewai's `_mcp_call` never unwraps
  // it further), so `extractResult` intentionally doesn't either, to keep this
  // package's return shape identical to the established contract. The kid check
  // below just needs to look in both places it can actually appear.
  const kid = findKid(result);
  if (kid !== undefined && !isValidKid(kid)) {
    throw new TrustGateError(
      `Trust Gate response carried a malformed kid (expected 32 hex chars): ${JSON.stringify(kid)}`
    );
  }

  return result;
}

function findKid(result: Record<string, unknown>): unknown {
  if ("kid" in result) return result.kid;
  if (result.result && typeof result.result === "object") {
    const nested = result.result as Record<string, unknown>;
    if ("kid" in nested) return nested.kid;
  }
  return undefined;
}

function extractResult(result: unknown): Record<string, unknown> {
  if (result && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if ("structuredContent" in r) {
      return r.structuredContent as Record<string, unknown>;
    }
    if ("content" in r && Array.isArray(r.content) && r.content.length > 0) {
      const first = r.content[0] as { text?: string };
      if (typeof first.text === "string") {
        try {
          return JSON.parse(first.text);
        } catch {
          return { raw: r.content };
        }
      }
    }
    return r;
  }
  return { raw: result };
}

/** Fire-and-forget channel-attribution ping. Any failure is swallowed — telemetry
 * must never block or fail a tool call. */
export function pingTelemetry(kind: string = "api"): void {
  withTimeout(
    (signal) =>
      fetch(`${TRUST_GATE_URL}/x?via=${VIA}&kind=${encodeURIComponent(kind)}`, {
        signal,
      }),
    2_000
  ).catch(() => {
    /* best-effort only */
  });
}
