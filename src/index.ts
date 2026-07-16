export { TRUST_GATE_URL, TrustGateError, mcpCall, pingTelemetry, isValidKid } from "./client.js";

export { mintActionReceipt } from "./tools/mint-action-receipt.js";
export { verifyReceipt } from "./tools/verify-receipt.js";
export { gateDecision } from "./tools/gate-decision.js";
export { checkEgress } from "./tools/check-egress.js";
export { runExitDrill } from "./tools/run-exit-drill.js";

import { mintActionReceipt } from "./tools/mint-action-receipt.js";
import { verifyReceipt } from "./tools/verify-receipt.js";
import { gateDecision } from "./tools/gate-decision.js";
import { checkEgress } from "./tools/check-egress.js";
import { runExitDrill } from "./tools/run-exit-drill.js";

/**
 * All 5 Trust Gate tools, ready to drop into an eve `agent/tools/` directory
 * or spread into a `defineExtension` bundle.
 */
export function createTrustGateTools() {
  return {
    mintActionReceipt,
    verifyReceipt,
    gateDecision,
    checkEgress,
    runExitDrill,
  };
}
