# CanaryGuard 402

[![Base Mainnet](https://img.shields.io/badge/Network-Base%20Mainnet%20(8453)-blue)](https://base.org)
[![x402 Protocol](https://img.shields.io/badge/Protocol-x402%20v2-green)](https://x402.org)
[![Coinbase CDP Bazaar](https://img.shields.io/badge/CDP%20Bazaar-Active%20%26%20Indexed-purple)](https://docs.cdp.coinbase.com/x402)
[![ElizaOS Plugin](https://img.shields.io/npm/v/@kurox_real/plugin-canaryguard?label=ElizaOS%20Plugin&color=orange)](https://www.npmjs.com/package/@kurox_real/plugin-canaryguard)
[![AgentKit Plugin](https://img.shields.io/npm/v/@kurox_real/agentkit-canaryguard-402?label=AgentKit%20Action&color=crimson)](https://www.npmjs.com/package/@kurox_real/agentkit-canaryguard-402)
[![Client SDK](https://img.shields.io/npm/v/@kurox_real/canaryguard-client?label=TS%20SDK&color=teal)](https://www.npmjs.com/package/@kurox_real/canaryguard-client)

Deterministic prompt-injection firewall and honeypot scrubber for autonomous AI agents. `POST /v1/sanitize` costs **0.003 USDC** on Base mainnet through the Coinbase CDP x402 facilitator. A remote MCP tool exposes the same inspection with payment per tool call.

- 🌐 **Live Web Playground**: [canaryguard-402.onrender.com](https://canaryguard-402.onrender.com)
- 🤖 **Agent Discovery**: [canaryguard-402.onrender.com/llms.txt](https://canaryguard-402.onrender.com/llms.txt)
- 📦 **NPM Packages**:
  - `@kurox_real/plugin-canaryguard` — Official ElizaOS Plugin
  - `@kurox_real/agentkit-canaryguard-402` — Coinbase AgentKit Action Provider
  - `@kurox_real/canaryguard-client` — TypeScript SDK with automatic x402 payment handling

---

## Agent Quickstarts

### 1. ElizaOS Agents (ai16z)
```bash
npm install @kurox_real/plugin-canaryguard
```
```typescript
import { canaryGuardPlugin } from "@kurox_real/plugin-canaryguard";

export const character = {
  name: "AutonomousAgent",
  plugins: [canaryGuardPlugin],
};
```

### 2. Coinbase AgentKit
```bash
npm install @kurox_real/agentkit-canaryguard-402
```
```typescript
import { canaryGuardActionProvider } from "@kurox_real/agentkit-canaryguard-402";

const agent = await createAgent({
  actionProviders: [canaryGuardActionProvider()],
});
```

### 3. TypeScript Client
```bash
npm install @kurox_real/canaryguard-client
```
```typescript
import { CanaryGuardClient } from "@kurox_real/canaryguard-client";

const client = new CanaryGuardClient();
const result = await client.sanitize("Untrusted scraped text or user prompt", { strictMode: true });
```

---

## Configuration

| Setting | Value |
| --- | --- |
| Merchant recipient | `0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1` |
| Base chain ID | `8453` |
| x402 v2 network | `eip155:8453` |
| Base USDC asset | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Amount | `3000` micro-USDC = `0.003` USDC |
| Intended public origin | `https://canaryguard-402.onrender.com` |
| GitHub repository | `https://github.com/ak10082247-max/canaryguard-402` |

These addresses and URLs are public configuration. A URL in this README does not establish that deployment or registry submission has succeeded. Verify health, payment challenges, settlement and catalog visibility separately.

## Local setup

Use Node.js 24 or newer. From the repository directory:

```sh
npm ci
npm run build
npm test
```

Create an ignored local `.env.local` with server configuration. Enter CDP credentials privately; do not place actual values in a shell command, screenshot or tracked file.

```dotenv
CDP_API_KEY_ID=<your CDP key ID>
CDP_API_KEY_SECRET=<your CDP secret>
PUBLIC_URL=https://canaryguard-402.onrender.com
X402_RECIPIENT_ADDRESS=0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1
NETWORK=base
PORT=4020
```

`PUBLIC_URL` must be the HTTPS origin buyers will use, without a path, query or credentials. It supplies discovery URLs even during local testing. CDP verify/settle calls must originate from an IP range allowed by your CDP key. The `NETWORK=base` configuration alias is normalized to `eip155:8453` in protocol messages.

```sh
npm run dev
curl -i http://localhost:4020/health
curl -i -X POST http://localhost:4020/v1/sanitize \
  -H 'Content-Type: application/json' \
  -d '{"content":"Example external text","strict_mode":true}'
```

On Windows, use `curl.exe` when the shell defines `curl` as an alias. The unpaid POST must return HTTP 402 with a base64 JSON `PAYMENT-REQUIRED` header. Decode that header to inspect `x402Version: 2`, `accepts[].amount: "3000"`, the merchant recipient, USDC asset and `network: "eip155:8453"`. The JSON error body alone is not the payment challenge. An unpaid GET to `/v1/sanitize` also supports the requested curl smoke check; actual data requests use POST.

The server requires usable CDP facilitator credentials at startup and fails closed when the facilitator cannot be initialized. This is a real-payment service; unit tests use an explicit fake facilitator rather than a runtime payment bypass.

For a local unpaid transport check without credentials, run `node --import tsx scripts/smoke_server.ts` and then `curl.exe -i http://localhost:4020/v1/sanitize`. This separate smoke server cannot verify or settle any payment and is excluded from the Docker image.

## HTTP API

| Route | Method | Payment |
| --- | --- | --- |
| `/health` | GET | Free |
| `/.well-known/x402.json` | GET | Free discovery metadata |
| `/.well-known/mcp/server-card.json` | GET | Free MCP capability metadata |
| `/v1/sanitize` | POST | 0.003 USDC |
| `/mcp` | POST | Free handshake and tool listing; paid `canary_sanitize` calls |

Input must be an object with `content` (1–50,000 characters), optional boolean `strict_mode` (default `true`), and no additional fields. The JSON transport limit is 256 KiB. The service imposes a 120-request-per-minute limit per client IP; `/health` is excluded.

```json
{
  "content": "Raw scraped text to inspect",
  "strict_mode": true
}
```

The standard payment flow is unpaid request → HTTP 402 challenge → client-signed authorization → retry with `PAYMENT-SIGNATURE` → facilitator verification and settlement → HTTP 200 plus `PAYMENT-RESPONSE`. `X-PAYMENT` is accepted for compatible legacy clients; use the v2 header for new clients. The exact scheme signs USDC authorization through the x402 EVM SDK; a transaction hash submitted as a payment header is insufficient.

CORS allows `*` and exposes `WWW-Authenticate`, `X-PAYMENT`, `PAYMENT-SIGNATURE`, `X-402-Version`, `Location`, `PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`, `EXTENSION-RESPONSES` and `Idempotency-Replayed`.

The response contains `status` (`clean`, `sanitized` or `blocked`), `risk_score`, `injection_detected`, `threats_neutralized`, `sanitized_content`, `safety_receipt`, `crypto_addresses` and an `inspection` limitations object. In strict mode, a detected role/instruction override or wallet transfer command empties the entire returned text. In non-strict mode, matching instruction lines are removed. HTML/Unicode cleanup still applies in both modes. EVM addresses are extracted and scored from text context; scores do not verify ownership, on-chain reputation or contract safety.

Missing or invalid payment returns 402; malformed JSON and invalid input return 400; oversized bodies return 413; changed content with an already-used cached payment returns 409; capacity/rate limits return 429; facilitator outages return 503. Check HTTP status before interpreting the response.

## Retry receipts

HTTP receipts are keyed by the canonicalized payment payload hash and bind to the JSON body. Identical completed payment/body retries return the original response and settlement receipt, with `Idempotency-Replayed: true`. Different content with the same cached payment is rejected. Cache entries live for at most ten minutes and are bounded by entry count and memory. MCP has a separate small bounded retry cache binding payment to tool arguments.

Both caches are **volatile and local to one process**. Restart, Render sleep, deployment or eviction loses them. USDC authorization nonces still prevent repeat on-chain settlement, but a response lost across a process restart cannot be recovered from this cache. Do not automatically create another authorization when a request times out after signing: inspect the retained authorization and settlement state first. Durable receipt storage is required before claiming durable idempotency or operating several replicas.

## Render deployment

[Deploy the blueprint](https://render.com/deploy?repo=https://github.com/ak10082247-max/canaryguard-402).

The Docker image compiles TypeScript, installs locked production dependencies and serves HTTP. Render supplies `PORT`; `/health` is the health check. The blueprint uses the free plan and asks for `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET` as private environment values. Set `PUBLIC_URL` to Render's actual allocated HTTPS origin if the intended name is unavailable, then redeploy. Check the new service's actual outbound IP ranges in Render before enabling them in the CDP key allowlist; another service's ranges are not proof of the new service's ranges.

Keep the buyer's key and seed-state files on the operator's machine. The server needs the recipient's public address and CDP facilitator credentials; it does not need either wallet's private key. `.gitignore` and `.dockerignore` exclude `.env`, `.env.*`, `node_modules`, `dist` and `*.pem`. Inspect staged files before publishing. Use an external local buyer directory so secrets and seed receipts are outside the Docker build context.

### Health checks and free-plan limits

The included standalone checker makes one free request and verifies the exact health JSON:

```sh
node scripts/health-check.mjs --url https://canaryguard-402.onrender.com
```

No recurring schedule is enabled by this repository. After confirming a real deployment, an external scheduler can call `/health` every ten minutes. For example, use a monitoring service that supports that interval, or install this cron entry on an already-running external Linux host:

```cron
*/10 * * * * /usr/bin/curl --fail --silent --show-error --max-time 90 https://canaryguard-402.onrender.com/health >/dev/null
```

Confirm that host's curl path before installing the entry; keep the cron job on an external host so it survives Render sleeping. Monitoring reduces idle cold starts but does not guarantee availability. An in-process self-ping cannot run once the service has slept. Render free services sleep after 15 minutes idle, can restart anytime, and share **750 active instance hours per workspace per calendar month**. Keeping both CanaryGuard and the existing Ujrah service awake continuously exceeds that shared allowance. Exhausting it suspends all free web services until the next month. Avoid continuous pings for both services; use paid hosting if dependable latency is required. [Render's free-plan documentation](https://render.com/docs/free)

## One real seed payment

Run the buyer script locally after the cloud health and unpaid 402 checks pass. Store `BUYER_PRIVATE_KEY` privately in an unversioned `.env.local` **outside this repository**. Never upload it to Render, GitHub, registry configuration or MCP client settings. A private key revealed in a chat should be retired after use; this project cannot make a disclosed key secret again.

```sh
npm run seed -- \
  --env-file /absolute/local-buyer/.env.local \
  --url https://canaryguard-402.onrender.com \
  --state-dir /absolute/local-buyer
```

Use native absolute paths on Windows. The script is intended to persist one signed authorization/state and make at most one 0.003 USDC settlement. It validates the challenge recipient, asset, network and exact amount before signing. Retain the settlement transaction hash and verify the Base receipt and USDC transfer. A successful request tests the payment pipeline; it is not organic revenue or proof that buyers will use the service.

## Discovery and registry status

### CDP Bazaar

The paid POST publishes `extensions.bazaar` schemas and examples through the standard x402 server extension. There is no separate `POST /discovery` registration or on-chain discovery metadata transaction. Validate the public HTTPS endpoint, complete a successfully settled CDP payment, then independently query the catalog. These operations are distinct; validation alone does not index anything. [CDP seller discovery guide](https://docs.cdp.coinbase.com/x402/seller/get-discovered)

Run the included read-only checker:

```sh
node --import tsx scripts/registry.ts --url https://canaryguard-402.onrender.com
```

It checks health, calls the public `POST https://api.cdp.coinbase.com/platform/v2/x402/validate` with `{resource,method:"POST"}`, and queries public discovery search using a hostname substring. It then verifies the exact resource URL, protocol version, recipient, network, asset and amount locally. This avoids a combined remote-filter query that returned an empty result for a newly indexed resource even though merchant lookup and hostname search confirmed it. It reads no wallet/CDP secrets, signs no payments and submits no registration. `--require-indexed` exits with status 2 when visibility is unconfirmed, useful for an operator check after settlement. API errors are reported separately from an empty catalog.

On the CDP facilitator's server-to-server verify/settle response, `EXTENSION-RESPONSES` can report `bazaar.status` as `success`, `processing` or `rejected`. The installed x402 SDK reads and logs this operator diagnostic, but deliberately omits `extensionResponses` from the buyer's payment receipt and does not forward the diagnostic header. Consequently, a buyer seed report with `discovery: null` is expected and does not establish indexing failure. Use catalog visibility and validator `index.active` as independent evidence. `processing` is pending, not proof of eventual inclusion. Catalog absence can reflect indexing delay or rejection. Listing is not permanent; resources without settlement for 30 days may be removed. [Discovery status and validation](https://docs.cdp.coinbase.com/x402/seller/get-discovered), [SDK receipt encoding](https://github.com/x402-foundation/x402/blob/main/typescript/packages/core/src/http/index.ts), [public buyer discovery](https://docs.cdp.coinbase.com/x402/buyer/discover-services)

### Smithery

Publish the public HTTPS Streamable HTTP `/mcp` URL through [Smithery's publishing UI](https://smithery.ai/new) or its authenticated CLI:

```sh
smithery auth login
smithery mcp publish https://canaryguard-402.onrender.com/mcp -n YOUR_OWNED_NAMESPACE/canaryguard-402
```

A Smithery account with namespace ownership or an API key is required. Handshake/tool listing is free so scanners can discover the tool; tool calls require an x402-aware buyer. Generic MCP clients and directory scanners do not necessarily support x402 payments. Confirm published scan/release status before claiming a listing.

`smithery.yaml` supplies a legacy container-build descriptor for repository tooling. It is not a registration request and does not point Smithery's gateway at the Render URL. Current remote URL publishing uses the command/UI above. The static MCP server card assists metadata discovery. [Current Smithery publishing documentation](https://smithery.ai/docs/build/publish)

### Glama

`glama.json` identifies the GitHub maintainer using the [published schema](https://glama.ai/mcp/schemas/server.json). The schema provides a maintainer list, not a live-URL registration field.

Submit the public repository using **Add MCP Server** on [Glama servers](https://glama.ai/mcp/servers), or submit the HTTPS `/mcp` URL through **Add MCP Server → Connector** on [Glama connectors](https://glama.ai/mcp/connectors). Sign in if the flow requires it. Confirm health/index status in the resulting listing. No undocumented indexer endpoint is used by this project. [Glama submission instructions](https://glama.ai/mcp/faq)

## License

MIT. See [LICENSE](LICENSE).
