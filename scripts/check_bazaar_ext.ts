import { declareDiscoveryExtension } from '@x402/extensions/bazaar';
import { ENDPOINT_SPECS, paymentOption, configuration } from '../src/config.js';
import { sanitizeContent } from '../src/sanitize.js';

const spec = ENDPOINT_SPECS.find(s => s.path === '/v1/sanitize')!;
const outputSample = sanitizeContent('Example external text');

const discovery = declareDiscoveryExtension({
  bodyType: 'json',
  input: spec.inputExample,
  inputSchema: spec.inputSchema,
  output: { example: outputSample },
});

console.log('discovery object keys:', Object.keys(discovery));
console.log('discovery stringified:');
console.log(JSON.stringify(discovery, null, 2));
