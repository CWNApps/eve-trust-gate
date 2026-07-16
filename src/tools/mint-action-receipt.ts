import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const mintActionReceipt = defineTool({
  description:
    "Mint a post-quantum, tamper-evident receipt for a consequential agent action. " +
    "Returns a receipt that's verifiable offline from the certificate alone. " +
    "Receipt is signed Ed25519 + ML-DSA-65; carries a 128-bit kid for offline " +
    "same-notary check.",
  inputSchema: z.object({
    agentId: z.string().min(1).describe("Identifier of the agent performing the action."),
    operation: z.string().min(1).describe("Operation name (e.g., 'deploy', 'send_email')."),
    target: z.string().min(1).describe("Target of the action."),
    policy: z.string().optional().describe("Policy label for the action (default: 'agent action evidence')."),
    inputs: z.string().optional().describe("Optional serialized inputs to bind into the receipt."),
    decision: z.string().optional().describe("Decision label (default: 'ACTION_GOVERNED')."),
  }),
  async execute({ agentId, operation, target, policy, inputs, decision }) {
    pingTelemetry();
    const args: Record<string, unknown> = {
      agent_id: agentId,
      operation,
      target,
      policy: policy ?? "agent action evidence",
    };
    if (inputs !== undefined) args.inputs = inputs;
    if (decision !== undefined) args.decision = decision;
    return mcpCall("mint_action_receipt", args);
  },
});
