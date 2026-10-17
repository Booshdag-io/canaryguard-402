import { loadEnvFile } from "node:process";
import fs from "node:fs";
import path from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { x402Client } from "@x402/core/client";
import {
  decodePaymentRequiredHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/client";

const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  loadEnvFile(envPath);
}

async function main() {
  const buyerKey = process.env.BUYER_PRIVATE_KEY;
  if (!buyerKey) throw new Error("Missing BUYER_PRIVATE_KEY");
  const account = privateKeyToAccount(buyerKey as `0x${string}`);
  console.log(`Payer Hot Wallet: ${account.address}`);

  const url = "https://x402-agent-tollbooth.onrender.com/toll/ai_intel";
  const body = { prompt: "Test server-side CDP settlement", contractAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" };

  // 1. Get 402 challenge
  const challengeRes = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  console.log(`Challenge status: HTTP ${challengeRes.status}`);
  const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("payment-required");
  const required = decodePaymentRequiredHeader(encoded!);
  const accept = required.accepts[0];
  console.log(`Required Amount: ${accept.amount} micro-units (${Number(accept.amount)/1e6} USDC)`);

  // 2. Client signs payment authorization
  const client = new x402Client().register("eip155:8453", new ExactEvmScheme(account));
  const payload = await client.createPaymentPayload({ ...required, accepts: [accept] });
  payload.resource = required.resource;
  const sigHeader = encodePaymentSignatureHeader(payload);

  // 3. Send payment signature DIRECTLY to tollbooth endpoint (NO pre-settlement!)
  console.log(`Sending payment directly to ${url} (server-side settlement test)...`);
  const t0 = Date.now();
  const paidRes = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "PAYMENT-SIGNATURE": sigHeader,
      "X-PAYMENT": sigHeader,
    },
    body: JSON.stringify(body),
  });
  const latency = Date.now() - t0;
  console.log(`Response Status: HTTP ${paidRes.status} (${latency}ms)`);
  
  const paymentRespHeader = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("payment-response") || paidRes.headers.get("X-PAYMENT-RESPONSE");
  console.log(`PAYMENT-RESPONSE Header: ${paymentRespHeader}`);
  if (paymentRespHeader) {
    const decodedReceipt = Buffer.from(paymentRespHeader, "base64").toString("utf-8");
    console.log(`Decoded Receipt: ${decodedReceipt}`);
  }

  const jsonResp = await paidRes.json().catch(() => ({}));
  console.log(`Response Body:`, JSON.stringify(jsonResp, null, 2));

  if (paidRes.status === 200 && paymentRespHeader) {
    console.log(`\n✅ VERIFIED: Tollbooth server-side CDP settlement succeeded with HTTP 200 OK and PAYMENT-RESPONSE!`);
  } else {
    console.log(`\n❌ Failed server-side settlement test: HTTP ${paidRes.status}`);
  }
}

main().catch(console.error);
