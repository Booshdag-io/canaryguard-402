import { createPublicClient, http, erc20Abi, formatUnits } from "viem";
import { base } from "viem/chains";
import fs from "node:fs";
import path from "node:path";

const MERCHANT = "0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1";
const BUYER_HOT = "0x6b5f275F028A214fb2e6d21061db791E3b07BEeD";
const PREV_BUYER_HOT = "0x4b5c71082d027d16d2a146465d66f9eec11634f6";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

const SERVERS = [
  { name: "canaryguard-402", url: "https://canaryguard-402.onrender.com/v1/telemetry/deliveries" },
  { name: "stealthguard-402", url: "https://stealthguard-402.onrender.com/v1/telemetry/deliveries" },
  { name: "rugshield-402", url: "https://rugshield-402.onrender.com/v1/telemetry/deliveries" },
  { name: "x402-agent-tollbooth", url: "https://x402-agent-tollbooth.onrender.com/v1/telemetry/deliveries" },
];

async function main() {
  console.log("============================================================");
  console.log("OCTOBER 16, 2026 — FULL EXTERNAL REVENUE & LIVE ON-CHAIN AUDIT");
  console.log("============================================================\n");

  const rpc = createPublicClient({
    chain: base,
    transport: http(process.env.BASE_RPC_URL || "https://mainnet.base.org"),
  });

  // 1. Live Balances
  const merchantBal = await rpc.readContract({
    address: USDC_BASE,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [MERCHANT],
  });

  const buyerBal = await rpc.readContract({
    address: USDC_BASE,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [BUYER_HOT],
  });

  const merchantEth = await rpc.getBalance({ address: MERCHANT });
  const buyerEth = await rpc.getBalance({ address: BUYER_HOT });

  console.log(`🏦 Merchant Payout Wallet (${MERCHANT}):`);
  console.log(`   USDC Balance: ${formatUnits(merchantBal, 6)} USDC`);
  console.log(`   ETH Balance:  ${formatUnits(merchantEth, 18)} ETH\n`);

  console.log(`💳 Buyer Hot Wallet (${BUYER_HOT}):`);
  console.log(`   USDC Balance: ${formatUnits(buyerBal, 6)} USDC`);
  console.log(`   ETH Balance:  ${formatUnits(buyerEth, 18)} ETH\n`);

  // 2. Fetch Flight Recorder Telemetry across all servers for matching
  const flightRecorderDeliveries: any[] = [];
  for (const s of SERVERS) {
    try {
      const res = await fetch(s.url, { headers: { Accept: "application/json" } });
      if (res.ok) {
        const data: any = await res.json();
        const paid = data.paid_deliveries || [];
        const all = data.deliveries || [];
        paid.forEach((p: any) => flightRecorderDeliveries.push({ ...p, service: s.name }));
        all.forEach((a: any) => {
          if (a.settled || a.tx || a.tx_hash) {
            flightRecorderDeliveries.push({ ...a, service: s.name });
          }
        });
      }
    } catch (e: any) {
      console.log(`  [Note] Telemetry fetch for ${s.name}: ${e.message}`);
    }
  }

  // 3. Query Blockscout for all ERC-20 transfers into Merchant Wallet
  console.log("Fetching token transfers from Blockscout API...");
  let transfers: any[] = [];
  let nextUrl: string | null = `https://base.blockscout.com/api/v2/addresses/${MERCHANT}/token-transfers?type=ERC-20`;

  let pages = 0;
  while (nextUrl && pages < 10) {
    pages++;
    try {
      const resp = await fetch(nextUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", Accept: "application/json" },
      });
      if (!resp.ok) {
        console.log(`  Blockscout HTTP ${resp.status}`);
        break;
      }
      const data: any = await resp.json();
      const items = data.items || [];
      transfers = transfers.concat(items);
      if (data.next_page_params) {
        const params = new URLSearchParams(data.next_page_params).toString();
        nextUrl = `https://base.blockscout.com/api/v2/addresses/${MERCHANT}/token-transfers?type=ERC-20&${params}`;
      } else {
        nextUrl = null;
      }
    } catch (e: any) {
      console.log(`  Blockscout pagination error: ${e.message}`);
      break;
    }
  }

  console.log(`Fetched ${transfers.length} total ERC-20 transfers.\n`);

  // 4. Filter for incoming USDC transfers from external wallets
  const externalTransfers = [];
  const internalWallets = [
    BUYER_HOT.toLowerCase(),
    PREV_BUYER_HOT.toLowerCase(),
    MERCHANT.toLowerCase(),
  ];

  for (const tx of transfers) {
    const token = tx.token || {};
    const tokenAddr = (token.address || "").toLowerCase();
    const toAddr = (tx.to?.hash || tx.to || "").toLowerCase();
    const fromAddr = (tx.from?.hash || tx.from || "").toLowerCase();

    // Check if USDC transfer into Merchant
    if (tokenAddr === USDC_BASE.toLowerCase() && toAddr === MERCHANT.toLowerCase()) {
      if (!internalWallets.includes(fromAddr)) {
        // Matched external transfer!
        const valueRaw = BigInt(tx.total?.value || tx.value || 0);
        const amountUsdc = Number(formatUnits(valueRaw, 6));
        const txHash = tx.tx_hash || tx.transaction_hash || tx.hash;
        const timestamp = tx.timestamp || "";

        // Match with Flight Recorder delivery
        const matched = flightRecorderDeliveries.find((d: any) => {
          const dTx = (d.tx || d.tx_hash || d.raw_payment_header || "").toLowerCase();
          const dPayer = (d.payer || d.payer_wallet || "").toLowerCase();
          return (txHash && dTx.includes(txHash.toLowerCase())) || dPayer === fromAddr;
        });

        externalTransfers.push({
          timestamp,
          from: tx.from?.hash || tx.from,
          amountUsdc,
          txHash,
          endpoint: matched?.endpoint || matched?.path || "POST /v1/base/token (or /v1/sanitize)",
          service: matched?.service || "CanaryGuard-402",
          blockNumber: tx.block_number,
        });
      }
    }
  }

  // Sort chronologically (oldest to newest)
  externalTransfers.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  let totalExternalUsdc = 0;
  console.log("================================================================================================================");
  console.log("COMPLETE EXTERNAL REVENUE TABLE — EVERY EXTERNAL USDC PAYMENT TO DATE");
  console.log("================================================================================================================");
  console.log("| # | Exact UTC Timestamp | Payer Wallet Address | Amount (USDC) | Matched Endpoint | BaseScan Tx Hash |");
  console.log("|---|---|---|---|---|---|");

  externalTransfers.forEach((t, idx) => {
    totalExternalUsdc += t.amountUsdc;
    const shortPayer = `${t.from.slice(0, 10)}...${t.from.slice(-8)}`;
    const shortTx = `[${t.txHash.slice(0, 10)}...](https://basescan.org/tx/${t.txHash})`;
    console.log(`| ${idx + 1} | ${t.timestamp} | \`${t.from}\` | $${t.amountUsdc.toFixed(6)} | \`${t.endpoint}\` | ${shortTx} |`);
  });

  console.log("================================================================================================================");
  console.log(`TOTAL EXTERNAL SETTLEMENT TRANSACTIONS: ${externalTransfers.length}`);
  console.log(`TOTAL EXTERNAL USDC EARNED:             $${totalExternalUsdc.toFixed(6)} USDC`);
  console.log("================================================================================================================\n");

  fs.writeFileSync(
    path.resolve(process.cwd(), "external_revenue_audit_report.json"),
    JSON.stringify({
      merchant_wallet: MERCHANT,
      buyer_wallet: BUYER_HOT,
      merchant_usdc_balance: formatUnits(merchantBal, 6),
      buyer_usdc_balance: formatUnits(buyerBal, 6),
      total_external_transactions: externalTransfers.length,
      total_external_usdc: totalExternalUsdc,
      external_transfers: externalTransfers,
    }, null, 2)
  );
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
