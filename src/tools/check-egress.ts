import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const checkEgress = defineTool({
  description:
    "Egress classification check. Scans data for sensitivity markers and " +
    "classifies as PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED. Blocks " +
    "RESTRICTED-class egress. Returns classification + tamper-evident receipt.",
  inputSchema: z.object({
    destination: z.string().min(1).describe("Where data is being sent (e.g., 'openai.com')."),
    dataSample: z.string().min(1).describe("Sample of the data being sent (scanned for sensitivity)."),
    provider: z.string().min(1).describe("The provider/service receiving the data."),
  }),
  async execute({ destination, dataSample, provider }) {
    pingTelemetry();
    return mcpCall("check_egress", {
      destination,
      data_sample: dataSample,
      provider,
    });
  },
});
