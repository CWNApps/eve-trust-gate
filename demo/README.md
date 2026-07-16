# eve-trust-gate demo agent

Minimal `eve` agent scaffold showing all 5 Trust Gate tools dropped into `agent/tools/`.

## Run it

```bash
cd demo
npm install
npm run dev
```

Then ask the agent to do something consequential — e.g. "deploy the pricing-service and mint
a receipt for it" — and it will call `mint_action_receipt`, then you can ask it to
"verify that last receipt" to exercise `verify_receipt`.

No API keys or signing keys required locally — every tool call goes to the hosted
`https://trust-gate-mcp.onrender.com` server, same as the sibling langchain/crewai/llama-index
demos.
