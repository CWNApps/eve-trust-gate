# Changelog

## 0.1.0 — Initial release (2026-07-15)

- First release. TypeScript tools for [eve](https://github.com/vercel/eve) (Vercel's agent
  framework), the 4th sibling in the CWNApps framework-adapter family alongside
  `langchain-trust-gate`, `crewai-trust-gate`, `llama-index-trust-gate`.
- Ships 5-tool parity with the sibling adapters, verified against their actual source (not
  their READMEs — `langchain-trust-gate`'s README was found to document only 2 of its 5
  shipped tools during this delivery; corrected here so this package's docs don't repeat
  that gap): `mintActionReceipt`, `verifyReceipt`, `gateDecision`, `checkEgress`,
  `runExitDrill`.
- Same wire protocol as the Python siblings: one JSON-RPC 2.0 `tools/call` POST to
  `https://trust-gate-mcp.onrender.com/mcp`, one fire-and-forget telemetry ping to `/x?via=eve`.
- H1/H2 (pol.must_do.150) are not applicable — this is a thin client with no signing key and
  no inbound network surface, matching why the Python siblings don't implement them either.
- H3: `verifyReceipt`'s `requirePq` is `undefined` by default (server obeys its own
  `TRUST_GATE_REQUIRE_PQ`, default true); the client never silently forces it to `false`.
- H4: the 128-bit `kid` on any response is passed through untouched; `isValidKid()` is
  exported for callers that want to sanity-check kid width themselves.
