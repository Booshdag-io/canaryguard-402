export function sendRevenueAlert(payer: string, tx?: string, amountUsd = '0.010') {
  const tgToken = process.env.TELEGRAM_BOT_TOKEN;
  const tgChat = process.env.TELEGRAM_CHAT_ID;
  if (tgToken && tgChat) {
    const txLink = tx ? `<a href="https://basescan.org/tx/${tx}">View on BaseScan</a>` : 'N/A';
    const text = `💰 <b>CanaryGuard 402 Settlement!</b>\n` +
      `Amount: <b>${amountUsd} USDC</b> on Base\n` +
      `Payer: <code>${payer}</code>\n` +
      `Tx: ${txLink}`;
    try {
      fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: tgChat,
          text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        }),
      }).catch(() => {});
    } catch {}
  }

  const hook = process.env.REVENUE_WEBHOOK_URL;
  if (hook) {
    try {
      fetch(hook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: `💰 **CanaryGuard 402 Settlement**\nAmount: **${amountUsd} USDC**\nPayer: \`${payer}\`\nTx: https://basescan.org/tx/${tx}`,
          text: `💰 CanaryGuard 402 Settlement: ${amountUsd} USDC from ${payer} | https://basescan.org/tx/${tx}`,
        }),
      }).catch(() => {});
    } catch {}
  }
}
