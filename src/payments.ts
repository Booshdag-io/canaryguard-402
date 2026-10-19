import { createFacilitatorConfig } from '@coinbase/x402';
import { HTTPFacilitatorClient, x402ResourceServer, x402HTTPResourceServer, type FacilitatorClient } from '@x402/core/server';
import { paymentMiddlewareFromHTTPServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { bazaarResourceServerExtension, declareDiscoveryExtension } from '@x402/extensions/bazaar';
import { configuration, ENDPOINT_SPECS, NETWORK, paymentOption } from './config.js';
import { sanitizeContent } from './sanitize.js';

export async function createPayments(env = process.env, provided?: FacilitatorClient) {
  const config = configuration(env);
  if (!provided && (!env.CDP_API_KEY_ID || !env.CDP_API_KEY_SECRET)) {
    throw new Error('CDP_API_KEY_ID and CDP_API_KEY_SECRET are required');
  }
  const facilitator = provided || new HTTPFacilitatorClient({
    ...createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET),
    timeoutMs: 60000,
  });

  const server = new x402ResourceServer(facilitator)
    .register(NETWORK, new ExactEvmScheme())
    .registerExtension(bazaarResourceServerExtension);

  const routesConfig: Record<string, any> = {};
  let primaryDiscovery: any = undefined;

  for (const spec of ENDPOINT_SPECS) {
    const outputSample = spec.path === '/v1/sanitize'
      ? sanitizeContent('Example external text')
      : spec.outputExample;

    const discoveryPost = declareDiscoveryExtension({
      bodyType: 'json',
      input: spec.inputExample,
      inputSchema: spec.inputSchema,
      output: { example: outputSample },
    });

    const discoveryGet = declareDiscoveryExtension({
      input: spec.inputExample,
      inputSchema: spec.inputSchema,
      output: { example: outputSample },
    });

    if (spec.path === '/v1/sanitize') {
      primaryDiscovery = discoveryPost;
    }

    const baseRoute = {
      accepts: [paymentOption(config.payTo, spec.amountMicro)],
      resource: config.publicUrl + spec.path,
      description: spec.description.slice(0, 440),
      mimeType: 'application/json',
      serviceName: 'CanaryGuard 402',
      tags: spec.tags,
      unpaidResponseBody: () => ({ contentType: 'application/json', body: { error: 'payment_required' } }),
    };

    routesConfig[`POST ${spec.path}`] = { ...baseRoute, extensions: discoveryPost };
    routesConfig[`GET ${spec.path}`] = { ...baseRoute, extensions: discoveryGet };
  }

  const httpServer = new x402HTTPResourceServer(server, routesConfig);
  await httpServer.initialize();
  const gate = paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, false);
  return { server, facilitator, config, gate, discovery: primaryDiscovery };
}
