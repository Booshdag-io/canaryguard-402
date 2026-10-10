import { createPayments } from './payments.js';
import { createApp } from './app.js';

const port = Number(process.env.PORT || 4020);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
const payments = await createPayments();
const app = await createApp(payments);
const server = app.listen(port, process.env.HOST || '127.0.0.1', () => console.log(JSON.stringify({ status: 'listening', service: 'canaryguard-402', port })));
server.requestTimeout = 90000; server.headersTimeout = 15000;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 10000).unref(); });
