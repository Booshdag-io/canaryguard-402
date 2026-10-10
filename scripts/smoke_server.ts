import { createPayments } from '../src/payments.js';
import { createApp } from '../src/app.js';
import { NETWORK } from '../src/config.js';

// Local transport validation only: no credentials or settlement capability.
// Production src/server.ts always requires the authenticated CDP facilitator.
const payments = await createPayments({ PUBLIC_URL: 'https://canaryguard-402.onrender.com', NETWORK: 'base' }, {
  getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: 'exact', network: NETWORK }], extensions: ['bazaar'], signers: {} }),
  verify: async () => { throw new Error('Local smoke server cannot verify payments'); },
  settle: async () => { throw new Error('Local smoke server cannot settle payments'); },
});
const app = await createApp(payments);
app.listen(4020, '127.0.0.1', () => console.log('Unpaid-only local smoke server listening on 127.0.0.1:4020'));
