# eve-trust-gate

[eve](https://github.com/vercel/eve) tools for **Trust Gate** post-quantum, tamper-evident receipts on consequential agent actions.

Trust Gate receipts are signed Ed25519 + ML-DSA-65 (FIPS 204) by the hosted MCP server (no local signing key). Each receipt is verifiable offline from the certificate alone. The hosted server defaults to PQ-required verify (defends against Ed25519-only downgrade); set `TRUST_GATE_REQUIRE_PQ=false` on your own deployment to allow Ed25519-only receipts.

## Install

```bash
npm install cwn-eve-trust-gate
```

## Usage

Each tool is a named export. Drop one into `agent/tools/` per file, re-exported as the
default — eve derives a tool's runtime name from the filename, not from any `name` field
on the definition:

```ts
// agent/tools/mint_action_receipt.ts
export { mintActionReceipt as default } from "cwn-eve-trust-gate";
```

```ts
// agent/tools/verify_receipt.ts
export { verifyReceipt as default } from "cwn-eve-trust-gate";
```

Repeat for `gateDecision`, `checkEgress`, `runExitDrill` — or use the factory to see all
five at once:

```ts
import { createTrustGateTools } from "cwn-eve-trust-gate";

console.log(Object.keys(createTrustGateTools()));
// ["mintActionReceipt", "verifyReceipt", "gateDecision", "checkEgress", "runExitDrill"]
```

Typical flow inside an agent:

1. the agent decides to do something consequential
2. it calls `mint_action_receipt(agentId, operation, target)`
3. the receipt is stored, attached to the audit log, returned to the user
4. later anyone (including this same package) can call `verify_receipt(receipt)` to confirm tamper-free

## Configuration

```bash
# point at a different deployment (self-hosted)
export TRUST_GATE_URL="https://trust-gate-mcp.onrender.com"
```

## Tools

| Tool | Purpose |
|---|---|
| `mintActionReceipt` | Mint a post-quantum receipt for any consequential agent action. |
| `verifyReceipt` | Calls the hosted server to verify a receipt's signature and hash. Defaults to PQ-required. |
| `gateDecision` | Two-phase (PREVIEW/COMMIT) decision gate with a tamper-evident receipt on commit. |
| `checkEgress` | Classifies outbound data (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED); the caller acts on a RESTRICTED result. |
| `runExitDrill` | Vendor exit readiness drill, run server-side — checks the hosted server's signing key, model access, data export. |

## Telemetry

Each tool invocation makes one fire-and-forget `GET /x?via=eve&kind=api` against the Trust Gate server. No PII, no cookies, no fingerprinting — just a channel tag so adoption per framework is measurable. Telemetry never blocks or fails the tool.

## Background

* **Trust Gate MCP** — the hosted server: <https://trust-gate-mcp.onrender.com>
* **eve** — the Vercel agent framework this package targets: <https://github.com/vercel/eve>
* **Sibling adapters** — same protocol, other frameworks: [langchain-trust-gate](https://github.com/CWNApps/langchain-trust-gate), [crewai-trust-gate](https://github.com/CWNApps/crewai-trust-gate), [llama-index-trust-gate](https://github.com/CWNApps/llama-index-trust-gate)
* **OAO** — the open-source receipt primitive: <https://github.com/CWNApps/openagentontology>

## License

Apache-2.0.
