/**
 * Public, read-only Bazaar validation and visibility check. No signing,
 * wallet/environment-secret reads, settlement, or registry registration.
 */
const API_ORIGIN = 'https://api.cdp.coinbase.com';
const DEFAULT_ORIGIN = 'https://canaryguard-402.onrender.com';
const RECIPIENT = '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1';
const ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NETWORK = 'eip155:8453';

type JsonObject = Record<string, unknown>;
function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : undefined;
}
function rows(value: unknown): JsonObject[] {
  return Array.isArray(value) ? value.map(object).filter((row): row is JsonObject => Boolean(row)) : [];
}
function lower(value: unknown): string { return typeof value === 'string' ? value.toLowerCase() : ''; }

function argumentsFor(argv: string[]) {
  let origin = DEFAULT_ORIGIN;
  let requireIndexed = false;
  for (let index = 0; index < argv.length; index++) {
    const option = argv[index];
    if (option === '--require-indexed') requireIndexed = true;
    else if (option === '--url') {
      const value = argv[++index];
      if (!value) throw new Error('--url requires an HTTPS origin');
      origin = value;
    } else throw new Error(`Unknown option: ${option}`);
  }
  const parsed = new URL(origin);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
    throw new Error('--url must be an HTTPS origin without credentials, path or query');
  }
  return { origin: parsed.origin, requireIndexed };
}

async function requestJson(url: URL | string, init?: RequestInit): Promise<JsonObject> {
  const response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(45000) });
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${new URL(url).hostname}${new URL(url).pathname}`);
  const contentLength = Number(response.headers.get('content-length') || 0);
  if (contentLength > 1024 * 1024) throw new Error('Registry response exceeds 1 MiB limit');
  const source = await response.text();
  if (Buffer.byteLength(source, 'utf8') > 1024 * 1024) throw new Error('Registry response exceeds 1 MiB limit');
  const data = object(JSON.parse(source));
  if (!data) throw new Error('Expected a JSON object response');
  return data;
}

function safeError(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown registry check failure';
}

async function main() {
  if (process.argv.slice(2).includes('--help')) {
    console.log('Usage: node --import tsx scripts/registry.ts [--url HTTPS_ORIGIN] [--require-indexed]');
    console.log('Checks public health, CDP validation and Bazaar search; never signs, pays or registers.');
    return;
  }
  const { origin, requireIndexed } = argumentsFor(process.argv.slice(2));
  const resource = `${origin}/v1/sanitize`;
  const health = await requestJson(`${origin}/health`);
  if (health.status !== 'ok' || health.service !== 'canaryguard-402') throw new Error('Unexpected public health response');

  const searchUrl = new URL('/platform/v2/x402/discovery/search', API_ORIGIN);
  // Narrow by hostname remotely, then verify the exact URL and payment fields
  // locally. Combined full-URL/recipient/network filters can miss a new listing.
  searchUrl.search = new URLSearchParams({ urlSubstring: new URL(origin).hostname, limit: '20' }).toString();
  const [validation, search] = await Promise.allSettled([
    requestJson(new URL('/platform/v2/x402/validate', API_ORIGIN), {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ resource, method: 'POST' }),
    }),
    requestJson(searchUrl, { headers: { Accept: 'application/json' } }),
  ]);

  let indexed = false;
  const report: JsonObject = { checked_at: new Date().toISOString(), resource, health: 'ok', paid_request_sent: false };
  if (validation.status === 'fulfilled') {
    const data = validation.value;
    report.validation = { valid: data.valid, statusCode: data.statusCode, x402Version: data.x402Version,
      preflight: data.preflight, simulation: data.simulation, index: data.index };
  } else report.validation = { error: safeError(validation.reason) };

  if (search.status === 'fulfilled') {
    const data = search.value;
    if (!Array.isArray(data.resources)) throw new Error('Unexpected Bazaar search response: resources array is missing');
    const matching = rows(data.resources).filter(row => row.resource === resource && row.x402Version === 2 &&
      rows(row.accepts).some(accept => accept.network === NETWORK && accept.amount === '3000' &&
        lower(accept.payTo) === RECIPIENT.toLowerCase() && lower(accept.asset) === ASSET.toLowerCase()));
    indexed = matching.length > 0;
    report.discovery = { visibility_confirmed: indexed, partialResults: data.partialResults,
      matches: matching.map(row => ({ resource: row.resource, lastUpdated: row.lastUpdated, quality: row.quality, curated: row.curated })) };
  } else report.discovery = { visibility_confirmed: false, error: safeError(search.reason) };

  console.log(JSON.stringify(report, null, 2));
  if (validation.status === 'rejected' || search.status === 'rejected') process.exitCode = 1;
  else if (requireIndexed && !indexed) process.exitCode = 2;
}

main().catch(error => { console.error(safeError(error)); process.exitCode = 1; });
