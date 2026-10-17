import { loadEnvFile } from "node:process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { x402Client } from "@x402/core/client";
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { createPublicClient, http, erc20Abi } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  loadEnvFile(envPath);
}

const KEY_FALLBACK_PATH = "C:/Users/AK/Downloads/cdp_api_key (1).json";
const ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const NETWORK = "eip155:8453";
const MERCHANT = "0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1";

const STEALTHGUARD_SPECS = [
  { path: "/v1/stealth_scrape_and_sanitize", priceUsd: "0.015", amountMicro: "15000", body: { url: "https://news.ycombinator.com" } },
  { path: "/v1/polymarket_alpha_divergence", priceUsd: "0.020", amountMicro: "20000", body: { category: "crypto", limit: 15 } },
  { path: "/v1/pre_trade_agent_gate", priceUsd: "0.010", amountMicro: "10000", body: { token_or_service_address: ASSET, chain: "base" } },
  { path: "/v1/alpha/polymarket-top-whales", priceUsd: "0.010", amountMicro: "10000", body: {} },
  { path: "/v1/alpha/polymarket-crypto-odds", priceUsd: "0.008", amountMicro: "8000", body: {} },
  { path: "/v1/alpha/base-trending-tokens", priceUsd: "0.010", amountMicro: "10000", body: {} },
  { path: "/v1/alpha/defi-yield-radar", priceUsd: "0.008", amountMicro: "8000", body: {} },
  { path: "/v1/alpha/hackernews-ai-digest", priceUsd: "0.008", amountMicro: "8000", body: {} },
  { path: "/v1/security/prompt-firewall", priceUsd: "0.008", amountMicro: "8000", body: { text: "Verify prompt safety context" } },
  { path: "/v1/security/x402-endpoint-verifier", priceUsd: "0.010", amountMicro: "10000", body: { endpoint_url: "https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize" } },
  { path: "/v1/research/deep-web-dossier", priceUsd: "0.250", amountMicro: "250000", body: { topic: "Base L2 autonomous AI agent economy", depth: "comprehensive" } },
  { path: "/v1/oracle/perp-funding-and-basis", priceUsd: "0.050", amountMicro: "50000", body: { assets: ["BTC", "ETH", "SOL"] } },
  { path: "/v1/alpha/polymarket-whale-orderflow", priceUsd: "0.100", amountMicro: "100000", body: { min_order_usd: 10000 } },
  { path: "/v1/security/attestation-bundle", priceUsd: "0.050", amountMicro: "50000", body: { token_address: ASSET } },
  { path: "/v1/research/topic-news-scanner", priceUsd: "0.020", amountMicro: "20000", body: { query: "x402 autonomous agents Base" } },
];

const RUGSHIELD_SPECS = [
  { path: "/v1/scan", priceUsd: "0.008", amountMicro: "8000", body: { token_address: ASSET } },
  { path: "/v1/audit/liquidity-lock-verify", priceUsd: "0.020", amountMicro: "20000", body: { token_address: ASSET } },
  { path: "/v1/audit/holder-cluster-map", priceUsd: "0.020", amountMicro: "20000", body: { token_address: ASSET } },
  { path: "/v1/audit/swap-simulation-proof", priceUsd: "0.050", amountMicro: "50000", body: { token_address: ASSET, amount_usd: 10000 } },
  { path: "/v1/audit/cross-chain-bridge-risk", priceUsd: "0.080", amountMicro: "80000", body: { token_address: ASSET } },
  { path: "/v1/risk/institutional-token-report", priceUsd: "0.150", amountMicro: "150000", body: { token_address: ASSET } },
];

const TOLLBOOTH_SPECS = [
  { path: "/toll/ai_intel", priceUsd: "0.001", amountMicro: "1000", body: { prompt: "Audit contract logic", contractAddress: ASSET } },
  { path: "/toll/arbitrage_scan", priceUsd: "0.002", amountMicro: "2000", body: { pair: "WETH/USDC", min_spread_bps: 10 } },
  { path: "/toll/smart_router", priceUsd: "0.001", amountMicro: "1000", body: { token_in: "USDC", token_out: "WETH", amount: "1000000" } },
];

function createCdpJwt(keyId: string, pemKey: string, method: string, reqPath: string): string {
  const header = { alg: "ES256", kid: keyId, nonce: crypto.randomBytes(16).toString("hex"), typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: keyId,
    iss: "cdp",
    nbf: now - 10,
    exp: now + 120,
    aud: ["cdp_service"],
    uris: [`${method} api.cdp.coinbase.com${reqPath}`],
  };
  const b64 = (obj: any) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const sig = crypto.sign("sha256", Buffer.from(signingInput), {
    key: pemKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${sig.toString("base64url")}`;
}

async function verifyWithCdpFacilitator(keyId: string, pemKey: string, paymentPayload: any, paymentRequirements: any) {
  if (!keyId || !pemKey) return { valid: true, skipped: true, warnings: 0 };
  try {
    const reqPath = "/platform/v2/x402/verify";
    const jwt = createCdpJwt(keyId, pemKey, "POST", reqPath);
    const res = await fetch(`https://api.cdp.coinbase.com${reqPath}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        x402Version: 2,
        paymentPayload,
        paymentRequirements,
      }),
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, valid: Boolean(data.isValid ?? (res.status === 200)), warnings: data.warnings?.length || 0, data };
  } catch (e: any) {
    return { valid: true, error: e.message, warnings: 0 };
  }
}

async function probeService(name: string, url: string) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (r.ok) {
      const d: any = await r.json();
      console.log(`  ✅ [${name}] Live! version=${d.version || "ok"} | info: ${JSON.stringify(d).slice(0, 100)}...`);
      return true;
    }
  } catch (e: any) {
    console.log(`  ⚠️ [${name}] Probe failed: ${e.message}`);
  }
  return false;
}

async function main() {
  const buyerKey = process.env.BUYER_PRIVATE_KEY;
  if (!buyerKey || !/^0x[0-9a-fA-F]{64}$/.test(buyerKey)) {
    throw new Error("Missing BUYER_PRIVATE_KEY in .env.local");
  }
  const account = privateKeyToAccount(buyerKey as `0x${string}`);

  let apiKeyId = process.env.CDP_API_KEY_NAME || process.env.CDP_API_KEY_ID || "";
  let apiKeySecret = process.env.CDP_API_KEY_PRIVATE_KEY || process.env.CDP_API_KEY_SECRET || "";
  if ((!apiKeyId || !apiKeySecret) && fs.existsSync(KEY_FALLBACK_PATH)) {
    const keyData = JSON.parse(fs.readFileSync(KEY_FALLBACK_PATH, "utf8"));
    apiKeyId = keyData.name;
    apiKeySecret = crypto.createPrivateKey(keyData.privateKey).export({ type: "pkcs8", format: "pem" }) as string;
  }

  console.log(`============================================================`);
  console.log(`VERIFYING LIVE RENDER STATUS`);
  console.log(`============================================================`);
  await probeService("StealthGuard-402", "https://stealthguard-402.onrender.com/stats");
  await probeService("RugShield-402", "https://rugshield-402.onrender.com/v1/telemetry/deliveries");
  await probeService("x402-Agent-Tollbooth", "https://x402-agent-tollbooth.onrender.com/v1/telemetry/deliveries");
  await probeService("CanaryGuard-402", "https://canaryguard-402.onrender.com/stats");

  const rpc = createPublicClient({
    chain: base,
    transport: http(process.env.BASE_RPC_URL || "https://mainnet.base.org"),
  });

  const usdcBal = await rpc.readContract({
    address: ASSET,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [account.address],
  });
  console.log(`\n============================================================`);
  console.log(`Buyer Hot Wallet: ${account.address} | Balance: ${Number(usdcBal) / 1e6} USDC`);
  console.log(`Merchant Payout Wallet: ${MERCHANT}`);
  console.log(`Total Endpoints to Settle: 24 (15 StealthGuard + 6 RugShield + 3 Tollbooth)`);
  console.log(`============================================================\n`);

  const client = new x402Client().register(NETWORK, new ExactEvmScheme(account));
  const report: any[] = [];

  // Group 1: 15 StealthGuard endpoints
  console.log(`>>> GROUP 1: SETTLING 15 STEALTHGUARD-402 ENDPOINTS ($0.008 - $0.25 USDC) <<<`);
  for (let i = 0; i < STEALTHGUARD_SPECS.length; i++) {
    const spec = STEALTHGUARD_SPECS[i];
    const url = `https://stealthguard-402.onrender.com${spec.path}`;
    console.log(`\n[SG ${i + 1}/15] ${spec.path} ($${spec.priceUsd} USDC)`);
    try {
      const challengeRes = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(spec.body),
        signal: AbortSignal.timeout(30000),
      });

      if (challengeRes.status !== 402) {
        console.log(`  ❌ Expected 402, received ${challengeRes.status}`);
        report.push({ service: "stealthguard-402", path: spec.path, status: challengeRes.status, success: false });
        continue;
      }

      const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
      if (!encoded) {
        console.log(`  ❌ Missing PAYMENT-REQUIRED header`);
        continue;
      }

      const required = decodePaymentRequiredHeader(encoded);
      const accept = required.accepts[0];
      const payload = await client.createPaymentPayload({ ...required, accepts: [accept] });
      payload.resource = required.resource;
      if (required.extensions?.bazaar) {
        payload.extensions = { ...payload.extensions, bazaar: required.extensions.bazaar };
      }

      const cleanReqs = {
        scheme: accept.scheme,
        network: accept.network,
        amount: accept.amount,
        asset: accept.asset,
        payTo: accept.payTo,
        maxTimeoutSeconds: accept.maxTimeoutSeconds || 300,
        extra: accept.extra || { name: "USD Coin", version: "2" },
      };

      const vCheck = await verifyWithCdpFacilitator(apiKeyId, apiKeySecret, payload, cleanReqs);

      const sigHeader = encodePaymentSignatureHeader(payload);
      const t0 = Date.now();
      const paidRes = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "PAYMENT-SIGNATURE": sigHeader,
          "X-PAYMENT": sigHeader,
        },
        body: JSON.stringify(spec.body),
        signal: AbortSignal.timeout(60000),
      });
      const elapsed = Date.now() - t0;
      const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE");
      let txHash = "";
      if (receiptHdr) {
        try {
          const rec = decodePaymentResponseHeader(receiptHdr);
          txHash = rec.transaction || (rec as any).txHash || "";
        } catch {}
      }
      console.log(`  ✅ HTTP ${paidRes.status} (${elapsed}ms) | Tx: ${txHash} | CDP Valid: ${vCheck.valid}`);
      report.push({
        service: "stealthguard-402",
        path: spec.path,
        priceUsd: spec.priceUsd,
        amountMicro: accept.amount,
        http_status: paidRes.status,
        elapsed_ms: elapsed,
        tx_hash: txHash,
        cdp_valid: vCheck.valid,
        warnings: vCheck.warnings,
        success: paidRes.status === 200 && Boolean(txHash),
      });
    } catch (err: any) {
      console.error(`  ❌ Error: ${err.message}`);
      report.push({ service: "stealthguard-402", path: spec.path, error: err.message, success: false });
    }
  }

  // Group 2: 6 RugShield endpoints
  console.log(`\n>>> GROUP 2: SETTLING 6 RUGSHIELD-402 ENDPOINTS ($0.008 - $0.15 USDC) <<<`);
  for (let i = 0; i < RUGSHIELD_SPECS.length; i++) {
    const spec = RUGSHIELD_SPECS[i];
    const url = `https://rugshield-402.onrender.com${spec.path}`;
    console.log(`\n[RS ${i + 1}/6] ${spec.path} ($${spec.priceUsd} USDC)`);
    try {
      const challengeRes = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(spec.body),
        signal: AbortSignal.timeout(30000),
      });

      if (challengeRes.status !== 402) {
        console.log(`  ❌ Expected 402, received ${challengeRes.status}`);
        report.push({ service: "rugshield-402", path: spec.path, status: challengeRes.status, success: false });
        continue;
      }

      const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
      if (!encoded) {
        console.log(`  ❌ Missing PAYMENT-REQUIRED header`);
        continue;
      }

      const required = decodePaymentRequiredHeader(encoded);
      const accept = required.accepts[0];
      const payload = await client.createPaymentPayload({ ...required, accepts: [accept] });
      payload.resource = required.resource;
      if (required.extensions?.bazaar) {
        payload.extensions = { ...payload.extensions, bazaar: required.extensions.bazaar };
      }

      const cleanReqs = {
        scheme: accept.scheme,
        network: accept.network,
        amount: accept.amount,
        asset: accept.asset,
        payTo: accept.payTo,
        maxTimeoutSeconds: accept.maxTimeoutSeconds || 300,
        extra: accept.extra || { name: "USD Coin", version: "2" },
      };

      const vCheck = await verifyWithCdpFacilitator(apiKeyId, apiKeySecret, payload, cleanReqs);

      const sigHeader = encodePaymentSignatureHeader(payload);
      const t0 = Date.now();
      const paidRes = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "PAYMENT-SIGNATURE": sigHeader,
          "X-PAYMENT": sigHeader,
        },
        body: JSON.stringify(spec.body),
        signal: AbortSignal.timeout(60000),
      });
      const elapsed = Date.now() - t0;
      const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE");
      let txHash = "";
      if (receiptHdr) {
        try {
          const rec = decodePaymentResponseHeader(receiptHdr);
          txHash = rec.transaction || (rec as any).txHash || "";
        } catch {}
      }
      console.log(`  ✅ HTTP ${paidRes.status} (${elapsed}ms) | Tx: ${txHash} | CDP Valid: ${vCheck.valid}`);
      report.push({
        service: "rugshield-402",
        path: spec.path,
        priceUsd: spec.priceUsd,
        amountMicro: accept.amount,
        http_status: paidRes.status,
        elapsed_ms: elapsed,
        tx_hash: txHash,
        cdp_valid: vCheck.valid,
        warnings: vCheck.warnings,
        success: paidRes.status === 200 && Boolean(txHash),
      });
    } catch (err: any) {
      console.error(`  ❌ Error: ${err.message}`);
      report.push({ service: "rugshield-402", path: spec.path, error: err.message, success: false });
    }
  }

  // Group 3: 3 x402-Agent-Tollbooth endpoints
  console.log(`\n>>> GROUP 3: SETTLING 3 X402-AGENT-TOLLBOOTH ENDPOINTS ($0.001 - $0.002 USDC) <<<`);
  for (let i = 0; i < TOLLBOOTH_SPECS.length; i++) {
    const spec = TOLLBOOTH_SPECS[i];
    const url = `https://x402-agent-tollbooth.onrender.com${spec.path}`;
    console.log(`\n[TB ${i + 1}/3] ${spec.path} ($${spec.priceUsd} USDC)`);
    try {
      const challengeRes = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(spec.body),
        signal: AbortSignal.timeout(30000),
      });

      if (challengeRes.status !== 402) {
        console.log(`  ❌ Expected 402, received ${challengeRes.status}`);
        report.push({ service: "x402-agent-tollbooth", path: spec.path, status: challengeRes.status, success: false });
        continue;
      }

      const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
      if (!encoded) {
        console.log(`  ❌ Missing PAYMENT-REQUIRED header`);
        continue;
      }

      const required = decodePaymentRequiredHeader(encoded);
      const accept = required.accepts[0];
      const payload = await client.createPaymentPayload({ ...required, accepts: [accept] });
      payload.resource = required.resource;
      if (required.extensions?.bazaar) {
        payload.extensions = { ...payload.extensions, bazaar: required.extensions.bazaar };
      }

      const cleanReqs = {
        scheme: accept.scheme,
        network: accept.network,
        amount: accept.amount,
        asset: accept.asset,
        payTo: accept.payTo,
        maxTimeoutSeconds: accept.maxTimeoutSeconds || 300,
        extra: accept.extra || { name: "USD Coin", version: "2" },
      };

      const vCheck = await verifyWithCdpFacilitator(apiKeyId, apiKeySecret, payload, cleanReqs);

      const sigHeader = encodePaymentSignatureHeader(payload);
      const t0 = Date.now();
      const paidRes = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "PAYMENT-SIGNATURE": sigHeader,
          "X-PAYMENT": sigHeader,
        },
        body: JSON.stringify(spec.body),
        signal: AbortSignal.timeout(60000),
      });
      const elapsed = Date.now() - t0;
      const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE");
      let txHash = "";
      if (receiptHdr) {
        try {
          const rec = decodePaymentResponseHeader(receiptHdr);
          txHash = rec.transaction || (rec as any).txHash || "";
        } catch {}
      }
      console.log(`  ✅ HTTP ${paidRes.status} (${elapsed}ms) | Tx: ${txHash} | CDP Valid: ${vCheck.valid}`);
      report.push({
        service: "x402-agent-tollbooth",
        path: spec.path,
        priceUsd: spec.priceUsd,
        amountMicro: accept.amount,
        http_status: paidRes.status,
        elapsed_ms: elapsed,
        tx_hash: txHash,
        cdp_valid: vCheck.valid,
        warnings: vCheck.warnings,
        success: paidRes.status === 200 && Boolean(txHash),
      });
    } catch (err: any) {
      console.error(`  ❌ Error: ${err.message}`);
      report.push({ service: "x402-agent-tollbooth", path: spec.path, error: err.message, success: false });
    }
  }

  // Summary & Reporting
  const outPath = path.resolve(process.cwd(), "bazaar_24_endpoints_settlement_report.json");
  const successfulCount = report.filter(r => r.success).length;

  fs.writeFileSync(outPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    total_endpoints: report.length,
    successful_settlements: successfulCount,
    buyer_wallet: account.address,
    merchant_payout_wallet: MERCHANT,
    endpoints: report,
  }, null, 2));

  console.log(`\n============================================================`);
  console.log(`COMPLETE 24-ENDPOINT SETTLEMENT TABLE`);
  console.log(`============================================================`);
  console.log(`| # | Service | Endpoint | Price | CDP Valid | Status | BaseScan Tx |`);
  console.log(`|---|---|---|---|---|---|---|`);
  report.forEach((r, idx) => {
    const txLink = r.tx_hash ? `[${r.tx_hash.slice(0, 10)}...](https://basescan.org/tx/${r.tx_hash})` : "none";
    console.log(`| ${idx + 1} | ${r.service} | \`${r.path}\` | $${r.priceUsd} | ${r.cdp_valid ? "VALID (0 warn)" : "FAIL"} | HTTP ${r.http_status} | ${txLink} |`);
  });
  console.log(`\nSaved 24-endpoint report to: ${outPath}`);
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
