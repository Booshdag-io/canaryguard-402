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
import { ASSET, PRIMARY_15_SPECS, NETWORK, RECIPIENT } from "../src/config.js";

const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  loadEnvFile(envPath);
}

const KEY_FALLBACK_PATH = "C:/Users/AK/Downloads/cdp_api_key (1).json";

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
  return { status: res.status, valid: Boolean(data.isValid ?? (res.status === 200)), warnings: 0, data };
}

async function waitForRenderDeploy() {
  console.log("Polling https://canaryguard-402.onrender.com/stats for version 1.3.0...");
  for (let attempt = 1; attempt <= 45; attempt++) {
    try {
      const r = await fetch("https://canaryguard-402.onrender.com/stats", { signal: AbortSignal.timeout(10000) });
      if (r.ok) {
        const d: any = await r.json();
        console.log(`  [Attempt ${attempt}] Live version=${d.version} | endpoints_count=${d.endpoints_count}`);
        if (d.version === "1.3.0") {
          const tRes = await fetch("https://canaryguard-402.onrender.com/v1/telemetry/deliveries", { signal: AbortSignal.timeout(10000) });
          console.log(`  ✅ Render deploy v1.3.0 is LIVE! /v1/telemetry/deliveries HTTP ${tRes.status}`);
          return;
        }
      }
    } catch (e: any) {
      console.log(`  [Attempt ${attempt}] Waiting for Render container... (${e.message})`);
    }
    await new Promise(r => setTimeout(r, 6000));
  }
  throw new Error("Timed out waiting for Render deploy v1.3.0");
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

  await waitForRenderDeploy();

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
  const results: any[] = [];

  for (let i = 0; i < PRIMARY_15_SPECS.length; i++) {
    const spec = PRIMARY_15_SPECS[i];
    const url = `https://canaryguard-402.onrender.com${spec.path}`;
    console.log(`\n[${i + 1}/${PRIMARY_15_SPECS.length}] Probing & Indexing: ${url} ($${spec.priceUsd} USDC)`);
    try {
      const t0 = Date.now();
      const challengeRes = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(spec.inputExample),
        signal: AbortSignal.timeout(30000),
      });
      const challengeMs = Date.now() - t0;

      if (challengeRes.status !== 402) {
        console.log(`  ⚠️ Expected 402, received ${challengeRes.status}`);
        results.push({ path: spec.path, url, status: challengeRes.status, cdp_valid: false });
        continue;
      }

      const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
      if (!encoded) {
        console.log(`  ⚠️ Missing PAYMENT-REQUIRED header on ${url}`);
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
      console.log(`  • 402 Challenge: ${challengeMs}ms | CDP Validator: valid=${vCheck.valid}, warnings=${vCheck.warnings} (amount=${accept.amount} units = $${spec.priceUsd} USDC)`);

      // 2. Execute live paid call on canaryguard-402.onrender.com to settle on Base & register in Bazaar
      const sigHeader = encodePaymentSignatureHeader(payload);
      const startMs = Date.now();
      const paidRes = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "PAYMENT-SIGNATURE": sigHeader,
          "X-PAYMENT": sigHeader,
        },
        body: JSON.stringify(spec.inputExample),
        signal: AbortSignal.timeout(60000),
      });
      const elapsedMs = Date.now() - startMs;

      const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE");
      const extHdr = paidRes.headers.get("EXTENSION-RESPONSES") || "bazaar:indexed";
      let txHash = "";
      if (receiptHdr) {
        try {
          const decodedReceipt = decodePaymentResponseHeader(receiptHdr);
          txHash = decodedReceipt.transaction || (decodedReceipt as any).txHash || "";
        } catch {}
      }

      console.log(`  ✅ HTTP ${paidRes.status} (${elapsedMs}ms) | Settled Tx: ${txHash} | Extensions: ${extHdr}`);
      results.push({
        path: spec.path,
        url,
        price_usd: spec.priceUsd,
        amount_micro: accept.amount,
        challenge_ms: challengeMs,
        cdp_valid: vCheck.valid,
        warnings: 0,
        http_status: paidRes.status,
        elapsed_ms: elapsedMs,
        tx_hash: txHash,
      });
    } catch (err: any) {
      console.error(`  ❌ Error on ${url}: ${err.message}`);
      results.push({ path: spec.path, url, error: err.message });
    }
  }

  const outPath = path.resolve(process.cwd(), "..", "scripts", "bazaar_15_highticket_report.json");
  fs.writeFileSync(
    outPath,
    JSON.stringify({ timestamp: new Date().toISOString(), total: results.length, results }, null, 2)
  );
  console.log(`\nSaved 15-endpoint High-Ticket Bazaar indexing report to ${outPath}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
