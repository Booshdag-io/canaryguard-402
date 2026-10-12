/**
 * Real-time sales and caller telemetry tracker for CanaryGuard 402 on Base.
 */
const RECIPIENT = '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const BASE_RPC = 'https://mainnet.base.org';
const CDP_API = 'https://api.cdp.coinbase.com/platform/v2/x402/discovery/search?urlSubstring=canaryguard-402';

async function main() {
  console.log('\n==========================================================');
  console.log('       CANARYGUARD 402 - REVENUE & TELEMETRY TRACKER      ');
  console.log('==========================================================\n');

  // 1. Fetch live on-chain USDC balance
  let usdcBalance = 'Unknown';
  try {
    const data = '0x70a0823100000000000000000000000073279fa4bada7cac888c62cda4f5c8104765f6f1';
    const res = await fetch(BASE_RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_call',
        params: [{ to: USDC_BASE, data }, 'latest'],
      }),
    }).then(r => r.json());
    if (res.result) {
      usdcBalance = (parseInt(res.result, 16) / 1e6).toFixed(6);
    }
  } catch (err: any) {
    usdcBalance = `Error: ${err.message}`;
  }

  // 2. Fetch CDP Facilitator Telemetry
  let cdpData: any = null;
  try {
    const res = await fetch(CDP_API).then(r => r.json());
    if (res.resources && res.resources[0]) {
      cdpData = res.resources[0];
    }
  } catch (err: any) {
    console.error('CDP fetch error:', err.message);
  }

  console.log(`[Merchant Wallet]: ${RECIPIENT}`);
  console.log(`[Live Balance]:    ${usdcBalance} USDC`);
  console.log(`[Network]:         Base Mainnet (Chain ID 8453)`);
  console.log(`[Price Per Call]:  0.003 USDC (3000 micro-units)\n`);

  if (cdpData && cdpData.quality) {
    console.log('--- COINBASE CDP BAZAAR METRICS ---');
    console.log(`[30-Day Calls]:    ${cdpData.quality.l30DaysTotalCalls}`);
    console.log(`[Unique Payers]:   ${cdpData.quality.l30DaysUniquePayers}`);
    console.log(`[Last Called]:     ${cdpData.quality.lastCalledAt}`);
    console.log(`[Indexed Status]:  ${cdpData.x402Version === 2 ? 'ACTIVE & INDEXED' : 'UNINDEXED'}\n`);
  }

  console.log('--- ONCHAIN EXPLORER LINKS ---');
  console.log(`BaseScan Token Transfers: https://basescan.org/token/${USDC_BASE}?a=${RECIPIENT}`);
  console.log(`BaseScan Merchant Wallet:  https://basescan.org/address/${RECIPIENT}\n`);
  console.log('==========================================================\n');
}

main().catch(console.error);
