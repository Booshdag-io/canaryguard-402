// If running in Apify Cloud Actor environment, execute the Apify PPE Actor runner directly
if (process.env.APIFY_IS_AT_HOME || process.env.APIFY_ACT_ID || process.env.APIFY_ACTOR_RUN_ID) {
  await import('./apify_entry.js');
} else {
  const { createPayments } = await import('./payments.js');
  const { createApp } = await import('./app.js');

  const port = Number(process.env.PORT || 4020);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
  const payments = await createPayments();
  const app = await createApp(payments);
  const server = app.listen(port, process.env.HOST || '127.0.0.1', () =>
    console.log(JSON.stringify({ status: 'listening', service: 'canaryguard-402', port }))
  );
  server.requestTimeout = 90000;
  server.headersTimeout = 15000;
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(1), 10000).unref();
    });
}
