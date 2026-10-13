import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'node:path';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { rateLimit } from 'express-rate-limit';
import type { createPayments } from './payments.js';
import { ASSET, DESCRIPTION, Input, inputJsonSchema, NETWORK, SERVICE_VERSION } from './config.js';
import { sanitizeContent } from './sanitize.js';
import { receiptRetries } from './retries.js';
import { mcpHandler } from './mcp.js';
import { sendRevenueAlert } from './alerts.js';

export async function createApp(payments: Awaited<ReturnType<typeof createPayments>>) {
  const app = express(); app.disable('x-powered-by'); app.set('case sensitive routing', true); app.set('strict routing', true);
  if (process.env.RENDER) app.set('trust proxy', 1);
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept', 'X-PAYMENT', 'PAYMENT-SIGNATURE', 'MCP-Protocol-Version', 'Mcp-Session-Id'],
    exposedHeaders: ['WWW-Authenticate', 'X-PAYMENT', 'PAYMENT-SIGNATURE', 'X-402-Version', 'Location', 'PAYMENT-REQUIRED', 'PAYMENT-RESPONSE', 'EXTENSION-RESPONSES', 'Idempotency-Replayed',
      'X-402-Payment-To', 'X-402-Amount', 'X-402-Amount-Units', 'X-402-Asset', 'X-402-Network', 'X-402-Chain-Id', 'X-Request-Id'] }));
  app.use((req, res, next) => {
    const start = Date.now();
    const reqId = randomUUID().slice(0, 8);
    res.setHeader('X-Request-Id', reqId);
    res.on('finish', () => {
      if (req.path === '/health') return;
      const payHeader = res.getHeader('PAYMENT-RESPONSE') || res.getHeader('X-PAYMENT-RESPONSE');
      let settled = false;
      let payer: string | null = null;
      let tx: string | null = null;
      if (typeof payHeader === 'string') {
        try {
          const parsed = JSON.parse(Buffer.from(payHeader, 'base64').toString('utf8'));
          if (parsed.success === true) {
            settled = true;
            payer = parsed.payer || null;
            tx = parsed.transaction || parsed.txHash || null;
          }
        } catch {}
      }
      const isReplayed = res.getHeader('Idempotency-Replayed') === 'true';
      const sanitized = res.locals.sanitized === true && !isReplayed && res.statusCode === 200;
      console.log(JSON.stringify({
        ts: new Date().toISOString(),
        reqId,
        endpoint: `${req.method} ${req.path}`,
        status: res.statusCode,
        durationMs: Date.now() - start,
        settled,
        replayed: isReplayed,
        sanitized,
        payer,
        tx,
      }));
    });
    next();
  });
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store').set('X-402-Version', '2');
    const origWriteHead = res.writeHead.bind(res);
    res.writeHead = function (statusCode: number, ...args: any[]) {
      if (statusCode === 402 || res.statusCode === 402) {
        res.setHeader('X-402-Payment-To', payments.config.payTo);
        res.setHeader('X-402-Amount', '0.003');
        res.setHeader('X-402-Amount-Units', '3000');
        res.setHeader('X-402-Asset', ASSET);
        res.setHeader('X-402-Network', 'base');
        res.setHeader('X-402-Chain-Id', '8453');
      }
      return (origWriteHead as any)(statusCode, ...args);
    } as any;
    next();
  });
  app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'canaryguard-402' }));
  app.get('/stats', (_req, res) => res.json({
    service: 'canaryguard-402',
    version: SERVICE_VERSION,
    network: NETWORK,
    pricing: { amount: '3000', price: '0.003 USDC', asset: ASSET, chainId: 8453 },
    payTo: payments.config.payTo,
    limits: { content_characters: 50000, body_bytes: 262144, idempotency: 'volatile, single instance, 10 minutes' },
  }));
  const publicDir = path.join(process.cwd(), 'public');
  if (fs.existsSync(publicDir)) {
    app.use(express.static(publicDir));
  }
  app.get('/llms.txt', (_req, res) => {
    const p = path.join(publicDir, 'llms.txt');
    if (fs.existsSync(p)) return res.sendFile(p);
    res.type('text/plain').send('# CanaryGuard 402\nPrompt injection firewall on Base. Paid 0.003 USDC.');
  });
  app.get('/', (req, res) => {
    if (req.accepts('html') && !req.accepts('json')) {
      const p = path.join(publicDir, 'index.html');
      if (fs.existsSync(p)) return res.sendFile(p);
    }
    res.json({
      service: 'CanaryGuard 402',
      version: SERVICE_VERSION,
      manifest: payments.config.publicUrl + '/.well-known/x402.json',
      health: payments.config.publicUrl + '/health',
      stats: payments.config.publicUrl + '/stats',
      paid_endpoint: `POST ${payments.config.publicUrl}/v1/sanitize`,
    });
  });
  app.post('/v1/demo-sanitize', express.json({ limit: '64kb' }), (req, res) => {
    const input = Input.safeParse(req.body);
    if (!input.success) return res.status(400).json({ error: 'invalid_input' });
    res.json(sanitizeContent(input.data.content.slice(0, 10000), input.data.strict_mode));
  });
  const x402Manifest = {
    name: 'CanaryGuard 402',
    description: DESCRIPTION,
    version: SERVICE_VERSION,
    x402Version: 2,
    facilitator: 'https://api.cdp.coinbase.com/platform/mobile/x402',
    payment_recipient: payments.config.payTo,
    accepted_tokens: [ASSET],
    pricing: { amount: '3000', price: '0.003 USDC', asset: ASSET, network: NETWORK, chainId: 8453, payTo: payments.config.payTo },
    endpoints: [{ method: 'POST', url: payments.config.publicUrl + '/v1/sanitize', inputSchema: inputJsonSchema, extensions: payments.discovery }],
    mcp: { url: payments.config.publicUrl + '/mcp', tool: 'canary_sanitize', transport: 'streamable-http' },
    limits: { content_characters: 50000, body_bytes: 262144, idempotency: 'volatile, single instance, 10 minutes' },
    disclaimer: 'Rule-based inspection has incomplete coverage. The receipt is a processing marker, not a safety guarantee.',
  };
  app.get(['/.well-known/x402', '/.well-known/x402.json'], (_req, res) => res.json(x402Manifest));
  app.get(['/openapi.json', '/.well-known/openapi.json'], (_req, res) => res.json({
    openapi: '3.0.3',
    info: {
      title: 'CanaryGuard 402',
      version: SERVICE_VERSION,
      description: DESCRIPTION,
    },
    servers: [{ url: payments.config.publicUrl }],
    paths: {
      '/v1/sanitize': {
        post: {
          summary: 'Deterministic prompt-injection firewall and wallet drain guard',
          description: 'Sanitizes untrusted text and checks for prompt injection attacks and wallet drain destinations. Requires 0.003 USDC micropayment on Base.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: inputJsonSchema,
              },
            },
          },
          responses: {
            '200': {
              description: 'Text inspected and sanitized successfully',
            },
            '402': {
              description: 'Payment Required: 0.003 USDC on Base mainnet (EIP-155:8453)',
            },
          },
          'x-payment-required': true,
          'x-price': '0.003',
          'x-currency': 'USDC',
          'x-network': 'base',
        },
      },
    },
  }));
  app.get('/.well-known/mcp/server-card.json', (_req, res) => res.json({ serverInfo: { name: 'canaryguard-402', version: SERVICE_VERSION },
    description: DESCRIPTION, transport: { type: 'streamable-http', url: payments.config.publicUrl + '/mcp' },
    capabilities: { tools: {} }, tools: [{ name: 'canary_sanitize', description: DESCRIPTION, inputSchema: inputJsonSchema }] }));
  app.use(rateLimit({ windowMs: 60000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'rate_limit_exceeded' }, skip: req => req.path === '/health' || req.path === '/openapi.json' || req.path.startsWith('/.well-known') }));
  app.use(express.json({ limit: '256kb', strict: true }));
  // HEAD must not fall through Express's automatic GET handler.
  app.use((req, res, next) => {
    if (req.path === '/v1/sanitize' && !['GET', 'POST'].includes(req.method)) { res.status(405).set('Allow', 'POST, GET').json({ error: 'method_not_allowed' }); return; }
    if (req.path === '/v1/sanitize') req.headers.accept = 'application/json';
    // The v2 core parser reads PAYMENT-SIGNATURE; accept the requested legacy
    // header as an alias without changing the v2 payload or signature.
    if (!req.headers['payment-signature'] && req.headers['x-payment']) req.headers['payment-signature'] = req.headers['x-payment'];
    next();
  });
  app.use(receiptRetries());
  app.use((req, res, next) => payments.gate(req, res, next).catch(() => { if (!res.headersSent) res.status(503).json({ error: 'payment_service_unavailable' }); }));
  app.post('/v1/sanitize', (req, res) => {
    const input = Input.safeParse(req.body);
    if (!input.success) { res.status(400).json({ error: 'invalid_input', max_content_characters: 50000 }); return; }
    res.on('finish', () => {
      if (res.getHeader('Idempotency-Replayed')) return;
      if (res.statusCode !== 200) return;
      const payHeader = res.getHeader('PAYMENT-RESPONSE') || res.getHeader('X-PAYMENT-RESPONSE');
      if (payHeader && typeof payHeader === 'string') {
        try {
          const parsed = JSON.parse(Buffer.from(payHeader, 'base64').toString('utf8'));
          if (parsed.success === true && (parsed.transaction || parsed.txHash)) {
            const tx = parsed.transaction || parsed.txHash;
            const payer = parsed.payer || 'client';
            console.log(`[canaryguard] 💰 0.003 USDC SETTLED! Payer: ${payer} | Tx: https://basescan.org/tx/${tx}`);
            sendRevenueAlert(payer, tx);
          }
        } catch {}
      }
    });
    res.locals.sanitized = true;
    res.json(sanitizeContent(input.data.content, input.data.strict_mode));
  });
  app.get('/v1/sanitize', (_req, res) => res.status(405).set('Allow', 'POST').json({ error: 'use_post' }));
  app.post('/mcp', await mcpHandler(payments.server, payments.config.publicUrl, payments.config.payTo));
  app.all('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').json({ error: 'method_not_allowed' }));
  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use((error: { type?: string; status?: number }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = error.type === 'entity.too.large' ? 413 : error.status === 400 ? 400 : 500;
    if (!res.headersSent) res.status(status).json({ error: status === 413 ? 'payload_too_large' : status === 400 ? 'invalid_json' : 'internal_error' });
  });
  return app;
}
