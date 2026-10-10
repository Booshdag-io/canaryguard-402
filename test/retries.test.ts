import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import test, { type TestContext } from 'node:test';
import type { FacilitatorClient } from '@x402/core/server';
import type { PaymentPayload, SettleResponse } from '@x402/core/types';
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from '@x402/core/http';
import { createApp } from '../src/app.js';
import { NETWORK, RECIPIENT } from '../src/config.js';
import { createPayments } from '../src/payments.js';
import { fingerprint } from '../src/retries.js';

const PAYER = '0x1111111111111111111111111111111111111111';
const TX = `0x${'cd'.repeat(32)}`;
const CONTENT = { content: 'Ordinary external text.', strict_mode: true };

async function fixture(t: TestContext, settle: () => Promise<SettleResponse>) {
  const calls = { verify: 0, settle: 0 };
  const facilitator: FacilitatorClient = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: 'exact', network: NETWORK }], extensions: ['bazaar'], signers: { [NETWORK]: [PAYER] } }),
    verify: async () => { calls.verify++; return { isValid: true, payer: PAYER }; },
    settle: async () => { calls.settle++; return settle(); },
  };
  // All signatures and settlements in this fixture are accepted by this mock;
  // the fixture never contacts a facilitator or blockchain.
  const payments = await createPayments({ PUBLIC_URL: 'https://canaryguard-retries.example', NETWORK: 'base' }, facilitator);
  const app = await createApp(payments);
  const server: Server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const url = `http://127.0.0.1:${address.port}/v1/sanitize`;
  const observe = (tag: string, event: 'request' | 'close' = 'request') => new Promise<void>(resolve => {
    const listener = (request: IncomingMessage, response: ServerResponse) => {
      if (request.headers['x-test-request'] !== tag) return;
      server.off('request', listener);
      if (event === 'close') response.once('close', resolve); else resolve();
    };
    server.on('request', listener);
  });
  const post = (body: unknown, payment?: PaymentPayload, tag = '', signal = AbortSignal.timeout(6000)) => fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Test-Request': tag,
      ...(payment ? { 'PAYMENT-SIGNATURE': encodePaymentSignatureHeader(payment) } : {}) }, body: JSON.stringify(body), signal,
  });
  const challenge = await post(CONTENT);
  const required = decodePaymentRequiredHeader(challenge.headers.get('PAYMENT-REQUIRED')!);
  await challenge.arrayBuffer();
  const payment: PaymentPayload = {
    x402Version: 2, accepted: required.accepts[0], resource: required.resource, extensions: required.extensions,
    payload: { signature: `0x${'22'.repeat(65)}`, authorization: { from: PAYER, to: RECIPIENT, value: '3000', validAfter: '0',
      validBefore: String(Math.floor(Date.now() / 1000) + 120), nonce: `0x${'03'.repeat(32)}` } },
  };
  return { calls, payment, post, observe };
}

const settled = (): SettleResponse => ({ success: true, payer: PAYER, transaction: TX, network: NETWORK, amount: '3000' });

function reverseObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reverseObjectKeys(item)]));
  return value;
}

test('fingerprints ignore object property order and support an absent parsed body', () => {
  assert.equal(fingerprint({ b: [{ z: 2, a: 1 }], a: true }), fingerprint({ a: true, b: [{ a: 1, z: 2 }] }));
  assert.equal(fingerprint(undefined), fingerprint(undefined));
  assert.notEqual(fingerprint(undefined), fingerprint(null));
  assert.notEqual(fingerprint([1, 2]), fingerprint([2, 1]));
});

test('a reordered JSON payment and body replay the completed receipt without another settlement', async t => {
  const h = await fixture(t, async () => settled());
  const first = await h.post(CONTENT, h.payment);
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  const second = await h.post(reverseObjectKeys(CONTENT), reverseObjectKeys(h.payment) as PaymentPayload);
  assert.equal(second.status, 200);
  assert.equal(second.headers.get('Idempotency-Replayed'), 'true');
  assert.deepEqual(await second.json(), firstBody);
  assert.deepEqual(h.calls, { verify: 1, settle: 1 });
});

test('a disconnected paid caller keeps its authorization locked and a retry receives the one settlement', { timeout: 20000 }, async t => {
  let release!: () => void;
  let started!: () => void;
  const barrier = new Promise<void>(resolve => { release = resolve; });
  const settlementStarted = new Promise<void>(resolve => { started = resolve; });
  t.after(() => release());
  const h = await fixture(t, async () => { started(); await barrier; return settled(); });
  const controller = new AbortController();
  const originalClosed = h.observe('original', 'close');
  const original = h.post(CONTENT, h.payment, 'original', controller.signal).then(
    () => { throw new Error('Aborted fetch unexpectedly completed'); },
    error => error,
  );
  await settlementStarted;
  controller.abort();
  assert.equal((await original).name, 'AbortError');
  await originalClosed;

  const retryArrived = h.observe('retry');
  const retry = h.post(CONTENT, h.payment, 'retry');
  await retryArrived;
  assert.deepEqual(h.calls, { verify: 1, settle: 1 });
  const conflict = await h.post({ content: 'A different request.', strict_mode: true }, h.payment);
  assert.equal(conflict.status, 409);
  assert.equal((await conflict.json()).error, 'payment_request_conflict');

  release();
  const response = await retry;
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Idempotency-Replayed'), 'true');
  assert.equal((await response.json()).sanitized_content, CONTENT.content);
  assert.deepEqual(h.calls, { verify: 1, settle: 1 });
});
