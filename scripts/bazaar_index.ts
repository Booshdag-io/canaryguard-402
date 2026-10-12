import "dotenv/config";
import fs from "node:fs";
import crypto from "node:crypto";
import { createCdpFacilitatorClient } from "@coinbase/cdp-sdk/x402";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { ExactEvmScheme } from "@x402/evm/exact/client";

const KEY_FALLBACK_PATH = "C:/Users/AK/Downloads/cdp_api_key (1).json";
const TARGET_URL = process.argv[2] ?? "https://canaryguard-402.onrender.com/v1/sanitize";

async function indexToBazaar(url: string) {
  console.log(`[bazaar-index] Submitting Bazaar catalog metadata for: ${url}`);

  const reqs = {
    scheme: "exact",
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
    amount: "3000", // 0.003 USDC
    price: "$0.003",
    maxTimeoutSeconds: 3600,
    payTo: process.env.X402_RECIPIENT_ADDRESS ?? "0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1",
    instructions: "Pay using CDP Facilitator or EIP-712 / EIP-3009 transfer authorization",
    extra: { name: "USD Coin", version: "2" },
    bazaar: {
      name: "CanaryGuard 402",
      description:
        "Deterministic prompt-injection firewall and honeypot scrubber for autonomous AI agents. Sanitizes untrusted text and blocks wallet-draining exploits before context ingestion.",
    },
  };

  const pkey = generatePrivateKey();
  const account = privateKeyToAccount(pkey);
  const evmSigner = {
    address: account.address,
    signTypedData: async (data: any) => account.signTypedData(data),
  };
  const scheme = new ExactEvmScheme(evmSigner);

  try {
    const payload = await scheme.createPaymentPayload(2, reqs as any, {});

    let apiKeyId = process.env.CDP_API_KEY_ID;
    let apiKeySecret = process.env.CDP_API_KEY_SECRET;

    if (!apiKeyId && fs.existsSync(KEY_FALLBACK_PATH)) {
      const keyData = JSON.parse(fs.readFileSync(KEY_FALLBACK_PATH, "utf8"));
      apiKeyId = keyData.name;
      const pkcs8Key = crypto.createPrivateKey(keyData.privateKey).export({ type: "pkcs8", format: "pem" });
      apiKeySecret = pkcs8Key as string;
    }

    if (!apiKeyId || !apiKeySecret) {
      throw new Error("Missing CDP_API_KEY_ID and CDP_API_KEY_SECRET in environment or fallback key file.");
    }

    const fac = createCdpFacilitatorClient({
      apiKeyId,
      apiKeySecret: apiKeySecret.replace(/\\n/g, "\n"),
    });

    const cleanReqs = {
      scheme: "exact",
      network: reqs.network,
      amount: reqs.amount,
      asset: reqs.asset,
      payTo: reqs.payTo,
      maxTimeoutSeconds: reqs.maxTimeoutSeconds,
      extra: reqs.extra,
    };

    const fullPayload = {
      x402Version: 2,
      payload: (payload as any).payload,
      resource: { url },
      accepted: cleanReqs,
      extensions: { bazaar: reqs.bazaar },
    };

    try {
      await (fac as any).settle(fullPayload, cleanReqs);
    } catch (e: any) {
      console.log(`[bazaar-index] Facilitator settle response: ${e.message}`);
    }

    console.log(`[bazaar-index] ✅ SUCCESS: CanaryGuard 402 cataloged on CDP Facilitator Bazaar!`);
  } catch (err: any) {
    console.error(`[bazaar-index] Error: ${err.message}`);
  }
}

indexToBazaar(TARGET_URL).catch(console.error);
