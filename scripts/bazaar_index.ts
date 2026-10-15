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
import { ASSET, ENDPOINT_SPECS, NETWORK, RECIPIENT } from "../src/config.js";

const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  loadEnvFile(envPath);
}

const KEY_FALLBACK_PATH = "C:/Users/AK/Downloads/cdp_api_key (1).json";

const STEALTHGUARD_ENDPOINTS = [
  { path: "/v1/stealth_scrape_and_sanitize", body: { url: "https://example.com" } },
  { path: "/v1/polymarket_alpha_divergence", body: { category: "crypto" } },
  { path: "/v1/pre_trade_agent_gate", body: { token_or_service_address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" } },
  { path: "/v1/alpha/polymarket-top-whales", body: { min_usd: 5000 } },
  { path: "/v1/alpha/polymarket-crypto-odds", body: { asset: "BTC" } },
  { path: "/v1/alpha/base-trending-tokens", body: { limit: 5 } },
  { path: "/v1/alpha/defi-yield-radar", body: { asset: "USDC" } },
  { path: "/v1/alpha/hackernews-ai-digest", body: { limit: 5 } },
  { path: "/v1/security/prompt-firewall", body: { content: "Verify prompt safety" } },
  { path: "/v1/security/x402-endpoint-verifier", body: { target_url: "https://canaryguard-402.onrender.com/v1/sanitize" } },
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
  return { status: res.status, valid: Boolean(data.isValid ?? (res.status === 200)), data };
}

async function main() {
  const buyerKey = process.env.BUYER_PRIVATE_KEY;
  if (!buyerKey || !/^0x[0-9a-fA-F]{64}$/.test(buyerKey)) {
    throw new Error("Missing BUYER_PRIVATE_KEY in .env.local");
  }
  const account = privateKeyToAccount(buyerKey as `0x${string}`);

  let apiKeyId = process.env.CDP_API_KEY_ID || "";
  let apiKeySecret = process.env.CDP_API_KEY_SECRET || "";
  if ((!apiKeyId || !apiKeySecret) && fs.existsSync(KEY_FALLBACK_PATH)) {
    const keyData = JSON.parse(fs.readFileSync(KEY_FALLBACK_PATH, "utf8"));
    apiKeyId = keyData.name;
    apiKeySecret = crypto.createPrivateKey(keyData.privateKey).export({ type: "pkcs8", format: "pem" }) as string;
  }

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
  console.log(`Buyer Hot Wallet: ${account.address} | Base USDC Balance: ${Number(usdcBal) / 1e6} USDC`);
  console.log(`Merchant Payout Wallet: ${RECIPIENT}`);

  const client = new x402Client().register(NETWORK, new ExactEvmScheme(account));

  const allTargets: Array<{ service: string; url: string; body: any }> = [
    ...ENDPOINT_SPECS.map(s => ({
      service: "canaryguard-402",
      url: `https://canaryguard-402.onrender.com${s.path}`,
      body: s.inputExample,
    })),
    ...STEALTHGUARD_ENDPOINTS.map(s => ({
      service: "stealthguard-402",
      url: `https://stealthguard-402.onrender.com${s.path}`,
      body: s.body,
    })),
  ];

  const results: any[] = [];

  for (let i = 0; i < allTargets.length; i++) {
    const target = allTargets[i];
    console.log(`\n[${i + 1}/${allTargets.length}] Probing & Indexing: ${target.url}`);
    try {
      const challengeRes = await fetch(target.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(target.body),
        signal: AbortSignal.timeout(30000),
      });

      const encoded = challengeRes.headers.get("PAYMENT-REQUIRED");
      if (challengeRes.status !== 402 || !encoded) {
        console.error(`  ❌ Expected 402 challenge, got HTTP ${challengeRes.status}`);
        results.push({ url: target.url, status: challengeRes.status, valid: false, settled: false });
        continue;
      }

      const required = decodePaymentRequiredHeader(encoded);
      const accept = required.accepts[0];
      const payload = await client.createPaymentPayload({ ...required, accepts: [accept] });
      payload.resource = required.resource;
      if (required.extensions?.bazaar) {
        payload.extensions = { ...payload.extensions, bazaar: required.extensions.bazaar };
      }

      // 1. Validate against Coinbase CDP /platform/v2/x402/verify
      const cleanReqs = {
        scheme: accept.scheme,
        network: accept.network,
        amount: accept.amount,
        asset: accept.asset,
        payTo: accept.payTo,
        maxTimeoutSeconds: accept.maxTimeoutSeconds || 120,
        extra: accept.extra || { name: "USD Coin", version: "2" },
      };

      const vCheck = await verifyWithCdpFacilitator(apiKeyId, apiKeySecret, payload, cleanReqs);
      console.log(`  • CDP /verify: valid=${vCheck.valid} (amount=${accept.amount} microunits)`);

      // 2. Execute live paid call to settle on Base & register in Bazaar
      const sigHeader = encodePaymentSignatureHeader(payload);
      const startMs = Date.now();
      const paidRes = await fetch(target.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "PAYMENT-SIGNATURE": sigHeader,
          "X-PAYMENT": sigHeader,
        },
        body: JSON.stringify(target.body),
        signal: AbortSignal.timeout(60000),
      });
      const elapsedMs = Date.now() - startMs;

      const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE");
      let txHash = "";
      if (receiptHdr) {
        try {
          const decodedReceipt = decodePaymentResponseHeader(receiptHdr);
          txHash = decodedReceipt.transaction || (decodedReceipt as any).txHash || "";
        } catch {}
      }

      console.log(`  ✅ HTTP ${paidRes.status} (${elapsedMs}ms) | Settled Tx: ${txHash || "verified"}`);
      results.push({
        service: target.service,
        url: target.url,
        amount_micro: accept.amount,
        cdp_valid: vCheck.valid,
        http_status: paidRes.status,
        elapsed_ms: elapsedMs,
        tx_hash: txHash,
      });
    } catch (err: any) {
      console.error(`  ❌ Error on ${target.url}: ${err.message}`);
      results.push({ url: target.url, error: err.message });
    }
  }

  fs.writeFileSync(
    path.resolve(process.cwd(), "..", "scripts", "bazaar_25_seed_report.json"),
    JSON.stringify({ timestamp: new Date().toISOString(), total: results.length, results }, null, 2)
  );
  console.log(`\nSaved 25-endpoint Bazaar indexing report to scripts/bazaar_25_seed_report.json`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
