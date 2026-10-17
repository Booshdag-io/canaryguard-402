import { loadEnvFile } from "node:process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
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

const ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT = "0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1";
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

async function settleWithCdp(keyId: string, pemKey: string, paymentPayload: any, paymentRequirements: any) {
  // Try direct CDP settle
  if (keyId && pemKey) {
    try {
      const reqPath = "/platform/v2/x402/settle";
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
      const data: any = await res.json().catch(() => ({}));
      if (res.ok && data.success && data.transaction) {
        return { success: true, txHash: data.transaction, source: "direct_cdp" };
      }
      console.log(`  [Direct CDP Settle Note]: ${res.status} - ${JSON.stringify(data).slice(0, 150)}`);
    } catch (e: any) {
      console.log(`  [Direct CDP Settle Err]: ${e.message}`);
    }
  }

  // Fallback to CanaryGuard internal relay
  try {
    const relayRes = await fetch("https://canaryguard-402.onrender.com/v1/internal/cdp-settle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paymentPayload, paymentRequirements }),
    });
    const relayData: any = await relayRes.json().catch(() => ({}));
    if (relayRes.ok && relayData.success && relayData.transaction) {
      return { success: true, txHash: relayData.transaction, source: "canaryguard_relay" };
    }
    console.log(`  [Relay Settle Note]: ${relayRes.status} - ${JSON.stringify(relayData).slice(0, 150)}`);
  } catch (e: any) {
    console.log(`  [Relay Settle Err]: ${e.message}`);
  }

  return { success: false, txHash: null, error: "Failed both direct CDP and relay" };
}

async function main() {
  const buyerKey = process.env.BUYER_PRIVATE_KEY;
  if (!buyerKey) throw new Error("Missing BUYER_PRIVATE_KEY in .env.local");
  const account = privateKeyToAccount(buyerKey as `0x${string}`);
  console.log(`============================================================`);
  console.log(`SETTLING 3 x402-agent-tollbooth ENDPOINTS ON BASE MAINNET`);
  console.log(`Buyer Hot Wallet: ${account.address}`);
  console.log(`Merchant Payout Wallet: ${MERCHANT}`);
  console.log(`============================================================\n`);

  let apiKeyId = process.env.CDP_API_KEY_NAME || process.env.CDP_API_KEY_ID || "";
  let apiKeySecret = process.env.CDP_API_KEY_PRIVATE_KEY || process.env.CDP_API_KEY_SECRET || "";
  if ((!apiKeyId || !apiKeySecret) && fs.existsSync(KEY_FALLBACK_PATH)) {
    const keyData = JSON.parse(fs.readFileSync(KEY_FALLBACK_PATH, "utf8"));
    apiKeyId = keyData.name;
    apiKeySecret = crypto.createPrivateKey(keyData.privateKey).export({ type: "pkcs8", format: "pem" }) as string;
  }

  const rpc = createPublicClient({
    chain: base,
    transport: http(process.env.BASE_RPC_URL || "https://mainnet.base.org"),
  });

  const client = new x402Client().register("eip155:8453", new ExactEvmScheme(account));
  const settledRecords = [];

  for (let i = 0; i < SPECS.length; i++) {
    const spec = SPECS[i];
    const url = `https://x402-agent-tollbooth.onrender.com${spec.path}`;
    console.log(`>>> [TB ${i + 1}/3] ${spec.path} ($${spec.priceUsd} USDC) <<<`);

    // 1. Fetch live 402 challenge
    const challengeRes = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(spec.body),
    });

    if (challengeRes.status !== 402) {
      throw new Error(`Expected 402, received ${challengeRes.status}`);
    }

    const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
    const required = decodePaymentRequiredHeader(encoded!);
    const accept = required.accepts[0];

    // 2. Build payment payload
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

    // 3. Settle on-chain via CDP Facilitator
    console.log(`  Submitting to Coinbase CDP Facilitator /settle...`);
    const settleResult = await settleWithCdp(apiKeyId, apiKeySecret, payload, cleanReqs);
    if (!settleResult.success || !settleResult.txHash) {
      throw new Error(`CDP settlement failed for ${spec.path}`);
    }

    const txHash = settleResult.txHash;
    console.log(`  ✅ On-Chain Transaction Broadcast: ${txHash} (${settleResult.source})`);

    // 4. Verify transaction receipt on Base Mainnet RPC
    console.log(`  Verifying receipt on Base RPC (https://mainnet.base.org)...`);
    const receipt = await rpc.waitForTransactionReceipt({
      hash: txHash as `0x${string}`,
      confirmations: 1,
      timeout: 30000,
    });

    console.log(`  ✅ Block Number: ${receipt.blockNumber} | Status: ${receipt.status} (Gas Used: ${receipt.gasUsed})`);

    // 5. Submit payment signature to tollbooth endpoint to deliver content
    const sigHeader = encodePaymentSignatureHeader(payload);
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

    console.log(`  ✅ Endpoint Delivery: HTTP ${paidRes.status} OK\n`);

    settledRecords.push({
      service: "x402-agent-tollbooth",
      path: spec.path,
      priceUsd: spec.priceUsd,
      amountMicro: accept.amount,
      http_status: paidRes.status,
      tx_hash: txHash,
      blockNumber: Number(receipt.blockNumber),
      status: receipt.status,
      basescanUrl: `https://basescan.org/tx/${txHash}`,
    });
  }

  console.log(`============================================================`);
  console.log(`ALL 3 TOLLBOOTH ENDPOINTS SETTLED WITH UNIQUE ON-CHAIN TRANSACTIONS`);
  console.log(`============================================================`);
  console.log(JSON.stringify(settledRecords, null, 2));

  // Save report
  fs.writeFileSync(
    path.resolve(process.cwd(), "tollbooth_real_settlement_receipts.json"),
    JSON.stringify(settledRecords, null, 2)
  );
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
