
async function verifyAll() {
  console.log("============================================================");
  console.log("PROBING REPUTATION & TRUST ON x402-TRUST, VET402 & LUMIERE");
  console.log("============================================================\n");

  const endpoints = [
    { service: "CanaryGuard-402", url: "https://canaryguard-402.onrender.com/v1/sanitize" },
    { service: "StealthGuard-402", url: "https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize" },
    { service: "RugShield-402", url: "https://rugshield-402.onrender.com/v1/scan" },
    { service: "x402-Agent-Tollbooth", url: "https://x402-agent-tollbooth.onrender.com/toll/ai_intel" },
  ];

  console.log(">>> 1. x402-trust.com Preview Status <<<");
  for (const ep of endpoints) {
    try {
      const res = await fetch(`https://x402-trust.com/v1/x402-trust-preview?url=${encodeURIComponent(ep.url)}`, {
        signal: AbortSignal.timeout(6000),
      });
      const text = await res.text();
      let parsed: any = null;
      try { parsed = JSON.parse(text); } catch {}
      console.log(`  [x402-trust] ${ep.service}: HTTP ${res.status} | Trust Score: ${parsed?.trustScore ?? parsed?.score ?? "Valid"} | Title: ${parsed?.title || ep.service}`);
    } catch (e: any) {
      console.log(`  [x402-trust] ${ep.service}: Error -> ${e.message}`);
    }
  }

  console.log("\n>>> 2. vet402.com Payee Verification Status <<<");
  try {
    const res = await fetch("https://vet402.com/payee/0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1", {
      headers: { "User-Agent": "Mozilla/5.0", Accept: "application/json" },
      signal: AbortSignal.timeout(6000),
    });
    console.log(`  [vet402] Payee 0x7327...f6f1 status: HTTP ${res.status}`);
  } catch (e: any) {
    console.log(`  [vet402] Payee probe: ${e.message}`);
  }

  console.log("\n>>> 3. Flight Recorder Telemetry Deliveries <<<");
  const telemetryUrls = [
    { name: "CanaryGuard-402", url: "https://canaryguard-402.onrender.com/v1/telemetry/deliveries" },
    { name: "StealthGuard-402", url: "https://stealthguard-402.onrender.com/v1/telemetry/deliveries" },
    { name: "RugShield-402", url: "https://rugshield-402.onrender.com/v1/telemetry/deliveries" },
  ];

  for (const t of telemetryUrls) {
    try {
      const res = await fetch(t.url, { signal: AbortSignal.timeout(8000) });
      if (res.ok) {
        const data: any = await res.json();
        const paidCount = data.paid_deliveries_count ?? (data.deliveries?.filter((d: any) => d.settled || d.txHash || d.tx).length);
        const total = data.total_deliveries ?? data.deliveries?.length ?? 0;
        console.log(`  [Flight Recorder] ${t.name}: HTTP 200 | Total logged: ${total} | Paid deliveries: ${paidCount}`);
      } else {
        console.log(`  [Flight Recorder] ${t.name}: HTTP ${res.status}`);
      }
    } catch (e: any) {
      console.log(`  [Flight Recorder] ${t.name}: Error -> ${e.message}`);
    }
  }
}

verifyAll().catch(console.error);
