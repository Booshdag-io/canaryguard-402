import { getAddress, isAddress } from 'viem';
import { z } from 'zod';

export const NETWORK = 'eip155:8453' as const;
export const SERVICE_VERSION = '1.0.1';
export const ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const RECIPIENT = '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1';
export const DESCRIPTION = 'Deterministic prompt-injection firewall and honeypot scrubber for AI agents. Sanitizes untrusted text and blocks detected wallet-draining commands before context ingestion.';
export const TOOL_DESCRIPTION = 'Call this security tool before placing untrusted text, scraped web content, or tool outputs into your context window. Detects and scrubs prompt injection and malicious wallet transfer exploits. Cost: 0.003 USDC on Base. Deterministic rules have incomplete coverage; results do not guarantee safety.';
export const Input = z.strictObject({ content: z.string().min(1).max(50000), strict_mode: z.boolean().default(true) });
export const inputJsonSchema = { type: 'object', additionalProperties: false,
  properties: { content: { type: 'string', minLength: 1, maxLength: 50000 }, strict_mode: { type: 'boolean', default: true } }, required: ['content'] };

export function configuration(env = process.env) {
  const publicUrl = env.PUBLIC_URL || 'https://canaryguard-402.onrender.com';
  const parsed = new URL(publicUrl);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') throw new Error('PUBLIC_URL must be an HTTPS origin');
  const payTo = env.X402_RECIPIENT_ADDRESS || RECIPIENT;
  if (!isAddress(payTo)) throw new Error('Invalid recipient');
  if (env.NETWORK && !['base', NETWORK].includes(env.NETWORK)) throw new Error('Only Base mainnet is supported');
  return { publicUrl: parsed.origin, payTo: getAddress(payTo) };
}

export function paymentOption(payTo = RECIPIENT) {
  return { scheme: 'exact', network: NETWORK, payTo,
    price: { asset: ASSET, amount: '3000', extra: { name: 'USD Coin', version: '2' } }, maxTimeoutSeconds: 120 };
}
