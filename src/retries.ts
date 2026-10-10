import { createHash } from 'node:crypto';
import type { RequestHandler } from 'express';
import { decodePaymentResponseHeader } from '@x402/core/http';

export function fingerprint(value: unknown) {
  const canonical = JSON.stringify(value, (_key, item: unknown) => {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
    }
    return item;
  });
  return createHash('sha256').update(canonical ?? 'undefined').digest('hex');
}
type Receipt = { bodyHash: string; body: Buffer; headers: Record<string, string>; expires: number };

// Same authorization + different content is a conflict. Receipt cache is bounded,
// volatile and never authorizes a fresh payment; it only repeats completed output.
export function receiptRetries(limit = 256, maxBytes = 8 * 1024 * 1024, inFlightTimeoutMs = 4 * 60 * 1000): RequestHandler {
  const receipts = new Map<string, Receipt>();
  const inFlight = new Map<string, { bodyHash: string; done: Promise<void> }>();
  let bytes = 0;
  const remove = (key: string) => { const row = receipts.get(key); if (row) bytes -= row.body.length; receipts.delete(key); };
  return async (req, res, next) => {
    const header = req.get('PAYMENT-SIGNATURE') || req.get('X-PAYMENT');
    if (!header || req.method !== 'POST' || req.path !== '/v1/sanitize') return next();
    let payload: unknown;
    try { payload = JSON.parse(Buffer.from(header, 'base64').toString('utf8')); } catch { return next(); }
    const key = fingerprint(payload);
    const bodyHash = fingerprint(req.body);
    const previous = inFlight.get(key);
    if (previous) {
      if (previous.bodyHash !== bodyHash) { res.status(409).json({ error: 'payment_request_conflict' }); return; }
      await previous.done;
    }
    const cached = receipts.get(key);
    if (cached && cached.expires <= Date.now()) remove(key);
    else if (cached) {
      if (cached.bodyHash !== bodyHash) { res.status(409).json({ error: 'payment_request_conflict' }); return; }
      receipts.delete(key); receipts.set(key, cached);
      res.set(cached.headers).set('Idempotency-Replayed', 'true').status(200).end(cached.body); return;
    }
    // An unsuccessful concurrent attempt must not be independently settled again.
    if (previous) { res.status(503).json({ error: 'retry_original_payment_later' }); return; }
    if (inFlight.size >= 64) { res.status(429).json({ error: 'payment_capacity_exceeded' }); return; }
    let complete!: () => void;
    const done = new Promise<void>(resolve => { complete = resolve; });
    const row = { bodyHash, done };
    inFlight.set(key, row);
    const chunks: Buffer[] = [];
    let length = 0;
    const remember = (chunk: unknown, encoding?: unknown) => {
      if (chunk == null || typeof chunk === 'function') return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === 'string' ? encoding as BufferEncoding : 'utf8');
      length += buffer.length; if (length <= 1024 * 1024) chunks.push(buffer);
    };
    const write = res.write.bind(res); const end = res.end.bind(res);
    let finished = false;
    // Closing the client connection does not cancel a facilitator request. Keep
    // the authorization locked until the payment middleware flushes its settled
    // response. The bound exceeds verify + settle + the SDK's pending retry.
    let cleanup: NodeJS.Timeout;
    const release = () => {
      clearTimeout(cleanup);
      if (inFlight.get(key) === row) inFlight.delete(key);
      complete();
    };
    const finish = () => {
      if (finished) return; finished = true;
      const responseHeader = res.getHeader('PAYMENT-RESPONSE');
      let settled = false;
      try { settled = typeof responseHeader === 'string' && decodePaymentResponseHeader(responseHeader).success === true; } catch { /* An invalid receipt is never replayable. */ }
      if (res.statusCode === 200 && settled && length <= 1024 * 1024) {
        const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
        for (const name of ['PAYMENT-RESPONSE', 'EXTENSION-RESPONSES']) { const value = res.getHeader(name); if (typeof value === 'string') headers[name] = value; }
        const body = Buffer.concat(chunks);
        remove(key);
        receipts.set(key, { bodyHash, headers, body, expires: Date.now() + 10 * 60 * 1000 }); bytes += body.length;
        while (receipts.size > limit || bytes > maxBytes) remove(receipts.keys().next().value!);
      }
      release();
    };
    cleanup = setTimeout(release, inFlightTimeoutMs); cleanup.unref();
    res.write = ((chunk: unknown, ...args: unknown[]) => { remember(chunk, args[0]); return (write as Function)(chunk, ...args); }) as typeof res.write;
    res.end = ((chunk?: unknown, ...args: unknown[]) => {
      remember(chunk, args[0]);
      try { return (end as Function)(chunk, ...args); } finally { finish(); }
    }) as typeof res.end;
    res.once('finish', finish);
    res.once('close', () => { if (res.writableFinished) finish(); });
    next();
  };
}
