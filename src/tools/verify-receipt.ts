import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const verifyReceipt = defineTool({
  description:
    "Calls the hosted Trust Gate server to verify a receipt's signature and evidence " +
    "hash (a networked call, not a local/offline check -- the receipt format itself is " +
    "designed to be independently verifiable offline from the certificate alone, but " +
    "this tool takes the convenient hosted-verification path rather than performing " +
    "that check locally). Returns {ok, hash_ok, sig_ok, signed, legs, signature_alg, reason}. " +
    "Defaults to PQ-required mode on the server -- defends against Ed25519-only downgrade " +
    "by requiring at least one verified PQ leg.",
  inputSchema: z.object({
    receipt: z.record(z.string(), z.unknown()).describe("The Trust Gate receipt to verify."),
    // H3 (pol.must_do.150): left undefined by default so the hosted server obeys its own
    // TRUST_GATE_REQUIRE_PQ env (default true). This tool never silently forces it false —
    // only an explicit caller-supplied `false` opts out of PQ-required verification.
    requirePq: z
      .boolean()
      .optional()
      .describe(
        "Undefined = obey the server's TRUST_GATE_REQUIRE_PQ (default true). " +
          "false = allow Ed25519-only receipts (downgrade — opt in explicitly)."
      ),
  }),
  async execute({ receipt, requirePq }) {
    pingTelemetry();
    const args: Record<string, unknown> = { receipt };
    if (requirePq !== undefined) args.require_pq = requirePq;
    return mcpCall("verify_receipt", args);
  },
});
