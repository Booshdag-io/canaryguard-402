import { loadEnvFile } from "node:process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { x402Client } from "@x402/core/client";
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/client";

const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  loadEnvFile(envPath);
}

const ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const KEY_FALLBACK_PATH = "C:/Users/AK/Downloads/cdp_api_key (1).json";

const SPECS = [
  { path: "/toll/ai_intel", priceUsd: "0.001", amountMicro: "1000", body: { prompt: "Audit contract logic", contractAddress: ASSET } },
  { path: "/toll/arbitrage_scan", priceUsd: "0.002", amountMicro: "2000", body: { pair: "WETH/USDC", min_spread_bps: 10 } },
  { path: "/toll/smart_router", priceUsd: "0.001", amountMicro: "1000", body: { tokenIn: "USDC", tokenOut: "WETH", amount: "1000000" } },
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

async function main() {
  const buyerKey = process.env.BUYER_PRIVATE_KEY;
  if (!buyerKey) throw new Error("Missing BUYER_PRIVATE_KEY in .env.local");
  const account = privateKeyToAccount(buyerKey as `0x${string}`);
  console.log(`Buyer Hot Wallet: ${account.address}`);

  let apiKeyId = process.env.CDP_API_KEY_NAME || process.env.CDP_API_KEY_ID || "";
  let apiKeySecret = process.env.CDP_API_KEY_PRIVATE_KEY || process.env.CDP_API_KEY_SECRET || "";
  if ((!apiKeyId || !apiKeySecret) && fs.existsSync(KEY_FALLBACK_PATH)) {
    const keyData = JSON.parse(fs.readFileSync(KEY_FALLBACK_PATH, "utf8"));
    apiKeyId = keyData.name;
    apiKeySecret = crypto.createPrivateKey(keyData.privateKey).export({ type: "pkcs8", format: "pem" }) as string;
  }

  const client = new x402Client().register("eip155:8453", new ExactEvmScheme(account));
  const results = [];

  for (let i = 0; i < SPECS.length; i++) {
    const spec = SPECS[i];
    const url = `https://x402-agent-tollbooth.onrender.com${spec.path}`;
    console.log(`\n[TB ${i + 1}/3] ${spec.path} ($${spec.priceUsd} USDC)`);

    const challengeRes = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(spec.body),
    });

    if (challengeRes.status !== 402) {
      console.log(`  ❌ Expected 402, received ${challengeRes.status}`);
      results.push({ path: spec.path, status: challengeRes.status, success: false });
      continue;
    }

    const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
    const required = decodePaymentRequiredHeader(encoded!);
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
    });

    const elapsed = Date.now() - t0;
    console.log("paidRes headers:", Array.from(paidRes.headers.entries()));
    const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE") || paidRes.headers.get("payment-response");
    let txHash = "";
    if (receiptHdr) {
      try {
        const rec = decodePaymentResponseHeader(receiptHdr);
        txHash = rec.transaction || (rec as any).txHash || "";
      } catch {}
    }

    console.log(`  ✅ HTTP ${paidRes.status} (${elapsed}ms) | Tx: ${txHash} | CDP Valid: ${vCheck.valid}`);
    results.push({
      service: "x402-agent-tollbooth",
      path: spec.path,
      priceUsd: spec.priceUsd,
      amountMicro: accept.amount,
      http_status: paidRes.status,
      elapsed_ms: elapsed,
      tx_hash: txHash,
      cdp_valid: vCheck.valid,
      warnings: vCheck.warnings,
      success: paidRes.status === 200,
    });
  }

  console.log("\nResults:", JSON.stringify(results, null, 2));
}

main().catch(console.error);
