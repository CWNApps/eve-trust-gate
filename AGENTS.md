# AGENTS.md — eve-trust-gate delivery leaf

> Frozen 2026-07-15 before work began (architect-loop pattern). These gates do not change
> once committed — if requirements evolve, add a new dated section below, don't edit this one.

## What this is

`cwn-eve-trust-gate` — TypeScript tool definitions for Vercel's `eve` agent framework that
call the hosted Trust Gate MCP server (`https://trust-gate-mcp.onrender.com`) via JSON-RPC.
The 4th sibling in the CWNApps framework-adapter family, architecturally identical to
`langchain-trust-gate`, `crewai-trust-gate`, and `llama-index-trust-gate` (all Python, all
live, all pip-installable, Apache-2.0).

## Frozen acceptance gates (done-criteria — quote verbatim when checking)

1. **5-tool parity, verified against source not docs.** `mint_action_receipt`,
   `verify_receipt`, `gate_decision`, `check_egress`, `run_exit_drill` — matching
   `crewai-trust-gate/src/crewai_trust_gate/tool.py` and `langchain-trust-gate`'s actual
   `tool.py` (NOT their READMEs — langchain's README is confirmed stale, documenting only
   2 of its 5 shipped tools).
2. **Same wire protocol, ported faithfully, not reinvented.** One `POST /mcp` JSON-RPC 2.0
   `tools/call` envelope per tool invocation, `MCP-Protocol-Version: 2025-03-26` header,
   `Accept: application/json, text/event-stream`. One fire-and-forget `GET /x?via=eve&kind=api`
   telemetry ping, all errors swallowed, 2s timeout, no PII/cookies.
3. **H3 (PQ-required verify, default-ON).** `verify_receipt`'s `requirePq` param is
   `undefined` by default (server obeys `TRUST_GATE_REQUIRE_PQ`, default true) — the client
   does not silently force it to `false` anywhere.
4. **H4 (128-bit kid surfaced faithfully).** The `kid` field from a verify/mint response is
   passed through untouched; an adversarial test asserts it's exactly 32 hex chars when present.
5. **Adversarial tests exist BEFORE codex review**, per pol.must_do.150: a PQ-strip test
   (stripped ml_dsa/slh_dsa fields → strict mode rejects, `requirePq:false` accepts) and a
   kid-width test.
6. **Codex APPROVE or APPROVE-WITH-EDITS (edits applied) before first push.** Sequence is
   write → codex-review → apply edits → verify any claimed SHAs/versions against the
   canonical source → push. Not the reverse.
7. **All GitHub Actions in the release workflow pinned to full commit SHA**, verified via
   `gh api repos/<owner>/<repo>/commits/<tag>` at write time, not from memory or codex output.
8. **npm publish is a separate, explicitly-confirmed step**, not bundled into "proceed until
   completed" — it's the one irreversible action (permanent public package-name claim) in
   this delivery.

## Disagreements raised at freeze time (Phase 0 — mandatory disagreement)

- **Scope correction from the original plan:** the scope presented to the user before this
  build named only 2 tools (mint + verify), sourced from `langchain-trust-gate`'s README.
  Direct inspection of both `langchain-trust-gate` and `crewai-trust-gate`'s actual `tool.py`
  source shows 5 tools in both. Adopting 5-tool parity here, not 2 — flagged as a correction,
  not silent scope creep, since matching the verified sibling precedent is the actually-minimal
  (non-diverging) choice.
- **Commit boundary consolidation:** the original 7-item commit table separated "telemetry
  parity" (item 4) from "TS client" (item 2), but in the Python precedent the telemetry
  helper lives in the same file as the JSON-RPC call helper. Telemetry ships inside the
  client-commit rather than as its own commit — flagged here rather than forcing an
  artificial empty commit to hit a number.
- **H1/H2 are not applicable to this artifact.** pol.must_do.150's H1 (signing-key
  persistence) and H2 (per-IP rate limiting) apply to deploy owners and network surfaces.
  This package is a thin client that makes outbound calls only — it never receives inbound
  traffic and never holds a signing key. Only H3 and H4 apply. This mirrors why the 3
  existing sibling repos also don't implement H1/H2.

## Must-not-skip before calling this "done"

- [ ] `npm run build` (tsc) succeeds with no errors
- [ ] Adversarial tests (PQ-strip, kid-width) pass
- [ ] Codex adversarial review run BEFORE first push, edits applied
- [ ] Every pinned SHA in release.yml verified via live GitHub API, not memory
- [ ] README + CHANGELOG accurately describe what's actually implemented (no stale-doc
      repeat of the langchain-trust-gate mistake found during this delivery)
- [ ] Graph SBOM: LoreAtom + HyperEdge + CodeSymbol + Receipt wired for this capability
- [ ] npm publish confirmed explicitly with Nigel before the tag push that triggers it
