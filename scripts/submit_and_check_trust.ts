async function testTrustAndLumiere() {
  console.log("=== 1. Checking x402-trust.com OpenAPI & endpoints ===");
  try {
    const r = await fetch("https://x402-trust.com/openapi.json");
    if (r.ok) {
      const openapi: any = await r.json();
      console.log("x402-trust openapi paths:", Object.keys(openapi.paths || {}));
    } else {
      console.log("x402-trust openapi status:", r.status);
    }
  } catch (e: any) {
    console.log("x402-trust openapi error:", e.message);
  }

  console.log("\n=== 2. Testing x402-trust.com search & preview APIs ===");
  const testUrls = [
    "https://canaryguard-402.onrender.com/v1/sanitize",
    "https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize",
    "https://rugshield-402.onrender.com/v1/scan",
    "https://x402-agent-tollbooth.onrender.com/toll/ai_intel"
  ];

  for (const ep of testUrls) {
    try {
      const res = await fetch(`https://x402-trust.com/v1/x402-trust-preview?url=${encodeURIComponent(ep)}`);
      const body = await res.text();
      console.log(`[x402-trust preview] ${ep} (HTTP ${res.status}): ${body.slice(0, 150)}`);
    } catch (e: any) {
      console.log(`[x402-trust preview err] ${ep}: ${e.message}`);
    }
  }

  console.log("\n=== 3. Testing lumierepaycheck.org ===");
  for (const ep of testUrls) {
    try {
      const res = await fetch(`https://lumierepaycheck.org/v1/score?url=${encodeURIComponent(ep)}`, {
        signal: AbortSignal.timeout(5000),
      });
      const body = await res.text();
      console.log(`[lumiere score] ${ep} (HTTP ${res.status}): ${body.slice(0, 150)}`);
    } catch (e: any) {
      console.log(`[lumiere score err] ${ep}: ${e.message}`);
    }
  }
}

testTrustAndLumiere();
