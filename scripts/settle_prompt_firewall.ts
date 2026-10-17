import { loadEnvFile } from "node:process";
import fs from "node:fs";
import path from "node:path";
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

async function main() {
  const buyerKey = process.env.BUYER_PRIVATE_KEY;
  if (!buyerKey) throw new Error("Missing BUYER_PRIVATE_KEY in .env.local");
  const account = privateKeyToAccount(buyerKey as `0x${string}`);
  console.log(`Buyer: ${account.address}`);

  const client = new x402Client().register("eip155:8453", new ExactEvmScheme(account));

  const url = "https://stealthguard-402.onrender.com/v1/security/prompt-firewall";
  const body = { text: "Verify prompt safety and drainer checks" };

  console.log(`Fetching 402 challenge from ${url}...`);
  const r1 = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });

  console.log(`Status: ${r1.status}`);
  if (r1.status !== 402) {
    console.error("Expected 402, got", r1.status, await r1.text());
    return;
  }

  const encoded = r1.headers.get("PAYMENT-REQUIRED") || r1.headers.get("X-PAYMENT-REQUIRED");
  const required = decodePaymentRequiredHeader(encoded!);
  const accept = required.accepts[0];
  console.log(`Accepted requirements: ${accept.amount} microUSDC to ${accept.payTo}`);

  const payload = await client.createPaymentPayload({ ...required, accepts: [accept] });
  payload.resource = required.resource;
  if (required.extensions?.bazaar) {
    payload.extensions = { ...payload.extensions, bazaar: required.extensions.bazaar };
  }

  const sigHeader = encodePaymentSignatureHeader(payload);
  console.log(`Submitting payment signature...`);
  const t0 = Date.now();
  const r2 = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "PAYMENT-SIGNATURE": sigHeader,
      "X-PAYMENT": sigHeader,
    },
    body: JSON.stringify(body),
  });

  const elapsed = Date.now() - t0;
  console.log(`HTTP ${r2.status} (${elapsed}ms)`);
  const respBody = await r2.text();
  console.log(`Response body: ${respBody.slice(0, 300)}`);
  const receiptHdr = r2.headers.get("PAYMENT-RESPONSE") || r2.headers.get("X-PAYMENT-RESPONSE");
  if (receiptHdr) {
    try {
      const rec = decodePaymentResponseHeader(receiptHdr);
      const tx = rec.transaction || (rec as any).txHash || "";
      console.log(`🎉 SUCCESS! BaseScan Tx: https://basescan.org/tx/${tx}`);
    } catch (e: any) {
      console.log(`Receipt decode: ${e.message}`);
    }
  }
}

main().catch(console.error);
