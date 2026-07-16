import { defineTool } from "eve/tools";
import { z } from "zod";
import { mcpCall, pingTelemetry } from "../client.js";

export const checkEgress = defineTool({
  description:
    "Egress classification check. The hosted server scans data for sensitivity markers " +
    "and classifies it as PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED, returning that " +
    "classification plus a tamper-evident receipt. This tool only reports the " +
    "classification -- it does not itself intercept or block network calls; the caller " +
    "is responsible for acting on a RESTRICTED result.",
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
