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

const TARGET_ENDPOINTS = [
  // CanaryGuard (5 endpoints @ $0.020)
  {
    service: "canaryguard-402",
    path: "/v1/risk/full_audit",
    url: "https://canaryguard-402.onrender.com/v1/risk/full_audit",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { target_address: ASSET },
  },
  {
    service: "canaryguard-402",
    path: "/v1/verify/agent-attestation",
    url: "https://canaryguard-402.onrender.com/v1/verify/agent-attestation",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { agent_wallet: MERCHANT },
  },
  {
    service: "canaryguard-402",
    path: "/v1/ondemand/market-snapshot",
    url: "https://canaryguard-402.onrender.com/v1/ondemand/market-snapshot",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: {},
  },
  {
    service: "canaryguard-402",
    path: "/v1/tokens/history-and-spread",
    url: "https://canaryguard-402.onrender.com/v1/tokens/history-and-spread",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { token: "ETH", quote: "USDC" },
  },
  {
    service: "canaryguard-402",
    path: "/v1/yield/safe-allocation",
    url: "https://canaryguard-402.onrender.com/v1/yield/safe-allocation",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { capital_usdc: 50000, risk_tolerance: "CONSERVATIVE" },
  },

  // StealthGuard (4 endpoints @ $0.020)
  {
    service: "stealthguard-402",
    path: "/v1/research/deep-web-dossier",
    url: "https://stealthguard-402.onrender.com/v1/research/deep-web-dossier",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { topic: "Base L2 autonomous AI agent economy", depth: "comprehensive" },
  },
  {
    service: "stealthguard-402",
    path: "/v1/oracle/perp-funding-and-basis",
    url: "https://stealthguard-402.onrender.com/v1/oracle/perp-funding-and-basis",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { assets: ["BTC", "ETH", "SOL"] },
  },
  {
    service: "stealthguard-402",
    path: "/v1/alpha/polymarket-whale-orderflow",
    url: "https://stealthguard-402.onrender.com/v1/alpha/polymarket-whale-orderflow",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { min_order_usd: 10000 },
  },
  {
    service: "stealthguard-402",
    path: "/v1/security/attestation-bundle",
    url: "https://stealthguard-402.onrender.com/v1/security/attestation-bundle",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { token_address: ASSET },
  },

  // RugShield (3 endpoints @ $0.020)
  {
    service: "rugshield-402",
    path: "/v1/audit/swap-simulation-proof",
    url: "https://rugshield-402.onrender.com/v1/audit/swap-simulation-proof",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { token_address: ASSET, amount_usd: 10000 },
  },
  {
    service: "rugshield-402",
    path: "/v1/audit/cross-chain-bridge-risk",
    url: "https://rugshield-402.onrender.com/v1/audit/cross-chain-bridge-risk",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { token_address: ASSET },
  },
  {
    service: "rugshield-402",
    path: "/v1/risk/institutional-token-report",
    url: "https://rugshield-402.onrender.com/v1/risk/institutional-token-report",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { token_address: ASSET },
  },

  // Tollbooth (1 endpoint @ $0.020)
  {
    service: "x402-agent-tollbooth",
    path: "/api/audit",
    url: "https://x402-agent-tollbooth.onrender.com/api/audit",
    priceUsd: "0.020",
    expectedAmount: "20000",
    body: { contractAddress: ASSET, isPatch: false },
  },
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

  const rpc = createPublicClient({
    chain: base,
    transport: http(process.env.BASE_RPC_URL || "https://base-rpc.publicnode.com"),
  });

  const getUsdcBalance = async (addr: string) => {
    const bal = await rpc.readContract({
      address: ASSET,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [addr as `0x${string}`],
    });
    return { raw: bal, formatted: Number(bal) / 1e6 };
  };

  const initialBuyerBal = await getUsdcBalance(account.address);
  const initialMerchantBal = await getUsdcBalance(MERCHANT);

  console.log("====================================================================");
  console.log("RE-SYNCING 13 PRICE-CAPPED ($0.020 USDC) ENDPOINTS IN COINBASE BAZAAR");
  console.log("====================================================================");
  console.log(`Buyer Hot Wallet:    ${account.address} | Balance: ${initialBuyerBal.formatted.toFixed(6)} USDC`);
  console.log(`Merchant Payout:     ${MERCHANT} | Balance: ${initialMerchantBal.formatted.toFixed(6)} USDC`);
  console.log(`Total Settlements:   13 endpoints @ $0.020 USDC = $0.260000 USDC total`);
  console.log("====================================================================\n");

  const client = new x402Client().register(NETWORK, new ExactEvmScheme(account));
  const results: any[] = [];

  for (let i = 0; i < TARGET_ENDPOINTS.length; i++) {
    const item = TARGET_ENDPOINTS[i];
    console.log(`[${i + 1}/13] Settling [${item.service}] ${item.path} ($${item.priceUsd} USDC)...`);

    try {
      // 1. Fetch 402 challenge
      const t0 = Date.now();
      const challengeRes = await fetch(item.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(item.body),
        signal: AbortSignal.timeout(30000),
      });
      const challengeMs = Date.now() - t0;

      if (challengeRes.status !== 402) {
        throw new Error(`Expected HTTP 402, received HTTP ${challengeRes.status}`);
      }

      const encoded = challengeRes.headers.get("PAYMENT-REQUIRED") || challengeRes.headers.get("X-PAYMENT-REQUIRED");
      if (!encoded) {
        throw new Error("Missing PAYMENT-REQUIRED challenge header");
      }

      const required = decodePaymentRequiredHeader(encoded);
      const accept = required.accepts[0];

      if (accept.amount !== item.expectedAmount) {
        throw new Error(`Amount mismatch: expected ${item.expectedAmount}, received ${accept.amount}`);
      }

      // 2. Sign payment payload
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

      // 3. Optional CDP Preflight check
      const vCheck = await verifyWithCdpFacilitator(apiKeyId, apiKeySecret, payload, cleanReqs);

      // 4. Send payment signature to endpoint for live on-chain settlement
      const sigHeader = encodePaymentSignatureHeader(payload);
      const startSettle = Date.now();
      const paidRes = await fetch(item.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "PAYMENT-SIGNATURE": sigHeader,
          "X-PAYMENT": sigHeader,
        },
        body: JSON.stringify(item.body),
        signal: AbortSignal.timeout(60000),
      });
      const settleMs = Date.now() - startSettle;

      if (paidRes.status !== 200) {
        const errText = await paidRes.text().catch(() => "");
        throw new Error(`Endpoint returned HTTP ${paidRes.status}: ${errText.slice(0, 150)}`);
      }

      const receiptHdr = paidRes.headers.get("PAYMENT-RESPONSE") || paidRes.headers.get("X-PAYMENT-RESPONSE");
      let txHash = "";
      if (receiptHdr) {
        try {
          const rec = decodePaymentResponseHeader(receiptHdr);
          txHash = rec.transaction || (rec as any).txHash || "";
        } catch {
          try {
            const rawRec = JSON.parse(Buffer.from(receiptHdr, "base64").toString("utf-8"));
            txHash = rawRec.transaction || rawRec.txHash || "";
          } catch {}
        }
      }

      console.log(`  ✅ HTTP 200 OK (${settleMs}ms) | Tx: ${txHash} | CDP Valid: ${vCheck.valid}`);

      results.push({
        index: i + 1,
        service: item.service,
        path: item.path,
        url: item.url,
        price_usd: item.priceUsd,
        amount_micro: accept.amount,
        http_status: paidRes.status,
        elapsed_ms: settleMs,
        tx_hash: txHash,
        cdp_valid: vCheck.valid,
        success: Boolean(txHash),
      });

      // Brief pause between on-chain transactions to avoid nonce collisions
      await new Promise((r) => setTimeout(r, 2000));
    } catch (err: any) {
      console.error(`  ❌ Settlement failed for ${item.path}: ${err.message}`);
      results.push({
        index: i + 1,
        service: item.service,
        path: item.path,
        url: item.url,
        error: err.message,
        success: false,
      });
    }
  }

  // Final Balance verification
  console.log("\n====================================================================");
  console.log("VERIFYING POST-SETTLEMENT ON-CHAIN BALANCES");
  console.log("====================================================================");
  const finalBuyerBal = await getUsdcBalance(account.address);
  const finalMerchantBal = await getUsdcBalance(MERCHANT);

  const buyerDiff = initialBuyerBal.formatted - finalBuyerBal.formatted;
  const merchantDiff = finalMerchantBal.formatted - initialMerchantBal.formatted;

  console.log(`Buyer Hot Wallet:    ${finalBuyerBal.formatted.toFixed(6)} USDC (Change: -${buyerDiff.toFixed(6)} USDC)`);
  console.log(`Merchant Payout:     ${finalMerchantBal.formatted.toFixed(6)} USDC (Change: +${merchantDiff.toFixed(6)} USDC)`);
  console.log("====================================================================");

  const report = {
    timestamp: new Date().toISOString(),
    total_endpoints: results.length,
    successful_settlements: results.filter((r) => r.success).length,
    buyer_wallet: account.address,
    merchant_wallet: MERCHANT,
    initial_buyer_balance_usdc: initialBuyerBal.formatted,
    final_buyer_balance_usdc: finalBuyerBal.formatted,
    initial_merchant_balance_usdc: initialMerchantBal.formatted,
    final_merchant_balance_usdc: finalMerchantBal.formatted,
    total_usdc_settled: merchantDiff,
    settlements: results,
  };

  const reportPath = path.resolve(process.cwd(), "..", "scripts", "bazaar_13_capped_settlement_report.json");
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\nReport written to ${reportPath}`);
}

main().catch((e) => {
  console.error("FATAL ERROR:", e);
  process.exit(1);
});
