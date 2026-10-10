import { createFacilitatorConfig } from '@coinbase/x402';
import { HTTPFacilitatorClient, x402ResourceServer, x402HTTPResourceServer, type FacilitatorClient } from '@x402/core/server';
import { paymentMiddlewareFromHTTPServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { bazaarResourceServerExtension, declareDiscoveryExtension } from '@x402/extensions/bazaar';
import { configuration, DESCRIPTION, inputJsonSchema, NETWORK, paymentOption } from './config.js';
import { sanitizeContent } from './sanitize.js';

export async function createPayments(env = process.env, provided?: FacilitatorClient) {
  const config = configuration(env);
  if (!provided && (!env.CDP_API_KEY_ID || !env.CDP_API_KEY_SECRET)) throw new Error('CDP_API_KEY_ID and CDP_API_KEY_SECRET are required');
  const facilitator = provided || new HTTPFacilitatorClient({ ...createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET), timeoutMs: 60000 });
  const server = new x402ResourceServer(facilitator).register(NETWORK, new ExactEvmScheme()).registerExtension(bazaarResourceServerExtension);
  const discovery = declareDiscoveryExtension({ bodyType: 'json', input: { content: 'Example external text', strict_mode: true },
    inputSchema: inputJsonSchema, output: { example: sanitizeContent('Example external text') } });
  const route = { accepts: [paymentOption(config.payTo)], resource: config.publicUrl + '/v1/sanitize', description: DESCRIPTION,
    mimeType: 'application/json', serviceName: 'CanaryGuard 402', tags: ['ai-safety', 'prompt-injection', 'base'],
    unpaidResponseBody: () => ({ contentType: 'application/json', body: { error: 'payment_required' } }), extensions: discovery };
  const httpServer = new x402HTTPResourceServer(server, { 'POST /v1/sanitize': route,
    // GET supports the requested curl smoke check; only POST is discoverable.
    'GET /v1/sanitize': { ...route, extensions: undefined } });
  // Initialize exactly once, including route validation, before configuring MCP.
  // The middleware's background sync otherwise clears supported kinds while
  // MCP is building its requirements against a real network facilitator.
  await httpServer.initialize();
  const gate = paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, false);
  return { server, config, gate, discovery };
}
