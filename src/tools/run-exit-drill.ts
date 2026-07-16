import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const runExitDrill = defineTool({
  description:
    "Vendor exit readiness drill. Checks local signing key, local model " +
    "access, and local data export. Returns results + tamper-evident receipt.",
  inputSchema: z.object({}),
  async execute() {
    pingTelemetry();
    return mcpCall("run_exit_drill", {});
  },
});
