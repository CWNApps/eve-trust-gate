import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const runExitDrill = defineTool({
  description:
    "Vendor exit readiness drill. Runs on the hosted Trust Gate server (not the caller's " +
    "own machine) -- checks the server's own signing key, model access, and data export " +
    "paths. Returns results + tamper-evident receipt.",
  inputSchema: z.object({}),
  async execute() {
    pingTelemetry();
    return mcpCall("run_exit_drill", {});
  },
});
