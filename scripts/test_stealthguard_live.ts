import { loadEnvFile } from "node:process";
import path from "node:path";
import { x402Client } from "@x402/core/client";
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

loadEnvFile(path.resolve(process.cwd(), ".env.local"));
const account = privateKeyToAccount(process.env.BUYER_PRIVATE_KEY as `0x${string}`);
const client = new x402Client().register("eip155:8453", new ExactEvmScheme(account));

async function main() {
  const url = "https://stealthguard-402.onrender.com/v1/security/prompt-firewall";
  const r1 = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: "Verify prompt safety" }),
  });
  console.log("Challenge status:", r1.status);
  const reqd = decodePaymentRequiredHeader(r1.headers.get("PAYMENT-REQUIRED")!);
  const accept = reqd.accepts[0];
  const payload = await client.createPaymentPayload({ ...reqd, accepts: [accept] });
  payload.resource = reqd.resource;
  if (reqd.extensions?.bazaar) {
    payload.extensions = { ...payload.extensions, bazaar: reqd.extensions.bazaar };
  }
  const sig = encodePaymentSignatureHeader(payload);

  const r2 = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "PAYMENT-SIGNATURE": sig,
      "X-PAYMENT": sig,
    },
    body: JSON.stringify({ content: "Verify prompt safety" }),
  });
  console.log("Paid call status:", r2.status);
  console.log("Paid call PAYMENT-RESPONSE:", r2.headers.get("PAYMENT-RESPONSE"));
  const txt = await r2.text();
  console.log("Paid call body:", txt);
}

main().catch(console.error);
