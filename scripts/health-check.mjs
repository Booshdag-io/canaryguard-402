// One free HTTP request. Schedule externally only after deployment is verified.
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node scripts/health-check.mjs [--url HTTPS_ORIGIN]');
  process.exit(0);
}
try {
  if (args.length && (args.length !== 2 || args[0] !== '--url')) throw new Error('Expected --url HTTPS_ORIGIN');
  const target = new URL(args[1] || 'https://canaryguard-402.onrender.com');
  if (target.protocol !== 'https:' || target.username || target.password || target.search || target.hash || target.pathname !== '/') {
    throw new Error('--url must be an HTTPS origin without credentials, path or query');
  }
  const response = await fetch(new URL('/health', target), { redirect: 'error', signal: AbortSignal.timeout(90000) });
  if (response.status !== 200) throw new Error(`Health check returned HTTP ${response.status}`);
  const body = await response.text();
  if (Buffer.byteLength(body) > 4096) throw new Error('Unexpected health response size');
  const health = JSON.parse(body);
  if (health.status !== 'ok' || health.service !== 'canaryguard-402' || Object.keys(health).length !== 2) {
    throw new Error('Unexpected health response');
  }
  console.log(JSON.stringify({ checked_at: new Date().toISOString(), url: new URL('/health', target).href,
    status: 'ok', service: 'canaryguard-402', paid_request_sent: false }));
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Health check failed');
  process.exitCode = 1;
}
