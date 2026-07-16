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

  let response: Response;
  try {
    response = await withTimeout(
      (signal) =>
        fetch(`${TRUST_GATE_URL}/mcp`, {
          method: "POST",
          signal,
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-03-26",
          },
          body: JSON.stringify(payload),
        }),
      timeoutMs
    );
  } catch (err) {
    throw new TrustGateError(
      `Cannot reach Trust Gate at ${TRUST_GATE_URL}: ${(err as Error).message}`
    );
  }

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new TrustGateError(
      `Trust Gate MCP ${response.status}: ${text.slice(0, 200)}`
    );
  }

  const body = (await response.json()) as {
    error?: unknown;
    result?: unknown;
  };

  if (body.error) {
    throw new TrustGateError(`Trust Gate MCP error: ${JSON.stringify(body.error)}`);
  }

  const result = body.result;
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

/** H4 (pol.must_do.150): a Trust Gate `kid` is `sha256(pubkey_bytes)[:32]` hex chars —
 * exactly 128 bits. A `kid` of any other width indicates a malformed or spoofed
 * response and must not be trusted as a same-notary check. */
export function isValidKid(kid: unknown): kid is string {
  return typeof kid === "string" && /^[0-9a-f]{32}$/i.test(kid);
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
