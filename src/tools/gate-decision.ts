import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const gateDecision = defineTool({
  description:
    "Two-phase decision gate. PREVIEW returns a risk assessment and preview_id " +
    "without acting. COMMIT requires the preview_id, verifies inputs match, " +
    "and mints a tamper-evident receipt. Stateless.",
  inputSchema: z.object({
    action: z.string().min(1).describe("The action to evaluate (e.g., 'deploy', 'send_email')."),
    resource: z.string().min(1).describe("Target resource (e.g., 'prod/api', 'user-db')."),
    context: z.record(z.string(), z.unknown()).describe("Context object for the decision (hashed in the receipt)."),
    phase: z
      .enum(["PREVIEW", "COMMIT"])
      .default("PREVIEW")
      .describe("'PREVIEW' for risk assessment, 'COMMIT' to proceed with receipt."),
    previewId: z.string().optional().describe("Required for COMMIT. Returned by the PREVIEW phase."),
  }),
  async execute({ action, resource, context, phase, previewId }) {
    pingTelemetry();
    const args: Record<string, unknown> = { action, resource, context, phase };
    if (previewId !== undefined) args.preview_id = previewId;
    return mcpCall("gate_decision", args);
  },
});
