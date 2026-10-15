import { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';

export interface DeliveryRecord {
  timestamp_utc: string;
  payer_wallet: string;
  amount_usdc: number;
  endpoint: string;
  method: string;
  user_agent: string;
  client_ip: string;
  referer: string;
  request_input: any;
  http_status: number;
  latency_ms: number;
  response_preview: string;
}

const MAX_MEMORY_RECORDS = 200;
const memoryStore: DeliveryRecord[] = [];
const logFilePath = path.join(process.cwd(), 'deliveries.jsonl');

function decodePayerFromHeader(rawHeader?: string): { payer: string; amount: number } {
  if (!rawHeader) return { payer: 'unpaid_probe', amount: 0.0 };
  try {
    let jsonStr = rawHeader;
    if (!rawHeader.trim().startsWith('{')) {
      jsonStr = Buffer.from(rawHeader, 'base64').toString('utf8');
    }
    const parsed = JSON.parse(jsonStr);
    
    // Check EIP-3009 structure
    if (parsed.authorization && parsed.authorization.from) {
      const amt = parsed.authorization.value ? Number(parsed.authorization.value) / 1e6 : 0.005;
      return { payer: parsed.authorization.from.toLowerCase(), amount: amt };
    }
    if (parsed.from) {
      const amt = parsed.value ? Number(parsed.value) / 1e6 : 0.005;
      return { payer: parsed.from.toLowerCase(), amount: amt };
    }
    if (parsed.payer) {
      return { payer: parsed.payer.toLowerCase(), amount: Number(parsed.amount || 0.005) };
    }
  } catch {}
  return { payer: 'unknown_signer', amount: 0.005 };
}

export function recordDeliveryMiddleware(req: Request, res: Response, next: NextFunction) {
  // Skip internal health pings and static favicon
  if (req.path === '/health' || req.path === '/ping' || req.path === '/favicon.ico') {
    return next();
  }

  const startTime = Date.now();
  const rawPaymentHdr = (req.headers['payment-signature'] || req.headers['x-payment']) as string | undefined;
  const { payer, amount } = decodePayerFromHeader(rawPaymentHdr);

  // Capture response body preview
  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  let capturedBody = '';

  res.json = function (body: any) {
    try {
      capturedBody = typeof body === 'string' ? body : JSON.stringify(body);
    } catch {
      capturedBody = String(body);
    }
    return originalJson(body);
  };

  res.send = function (body: any) {
    if (!capturedBody) {
      try {
        capturedBody = typeof body === 'string' ? body : JSON.stringify(body);
      } catch {
        capturedBody = String(body);
      }
    }
    return originalSend(body);
  };

  res.on('finish', () => {
    const latency_ms = Date.now() - startTime;
    const client_ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || 'unknown';
    
    let resolvedPayer = payer;
    let resolvedAmount = amount;

    // Check payment-response header for confirmed settlement
    const payRespHeader = res.getHeader('PAYMENT-RESPONSE') || res.getHeader('X-PAYMENT-RESPONSE');
    if (payRespHeader && typeof payRespHeader === 'string') {
      try {
        const parsedResp = JSON.parse(Buffer.from(payRespHeader, 'base64').toString('utf8'));
        if (parsedResp.payer) resolvedPayer = parsedResp.payer.toLowerCase();
        if (parsedResp.amount) resolvedAmount = Number(parsedResp.amount) / 1e6;
      } catch {}
    }

    const record: DeliveryRecord = {
      timestamp_utc: new Date().toISOString(),
      payer_wallet: resolvedPayer,
      amount_usdc: res.statusCode === 200 ? (resolvedAmount || 0.005) : 0.0,
      endpoint: req.path,
      method: req.method,
      user_agent: req.get('user-agent') || 'none',
      client_ip,
      referer: req.get('referer') || 'direct',
      request_input: req.method === 'POST' ? req.body : req.query,
      http_status: res.statusCode,
      latency_ms,
      response_preview: (capturedBody || '').slice(0, 300)
    };

    memoryStore.unshift(record);
    if (memoryStore.length > MAX_MEMORY_RECORDS) {
      memoryStore.pop();
    }

    try {
      fs.appendFileSync(logFilePath, JSON.stringify(record) + '\n', 'utf8');
    } catch {}
  });

  next();
}

export function getRecentDeliveries(): DeliveryRecord[] {
  return [...memoryStore];
}
