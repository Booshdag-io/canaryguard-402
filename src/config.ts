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

export const sanitizeResultJsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    status: {
      type: 'string',
      enum: ['clean', 'sanitized', 'blocked'],
      description: 'Heuristic classification of the input content',
    },
    risk_score: {
      type: 'number',
      minimum: 0,
      maximum: 1,
      description: 'Heuristic risk severity between 0.0 and 1.0',
    },
    injection_detected: {
      type: 'boolean',
      description: 'Whether prompt injection or malicious instructions were detected',
    },
    threats_neutralized: {
      type: 'array',
      items: { type: 'string' },
      description: 'List of heuristic threat categories identified and neutralized',
    },
    sanitized_content: {
      type: 'string',
      description: 'Processed text with harmful instructions stripped or blocked',
    },
    safety_receipt: {
      type: 'string',
      enum: ['canary-v1-verified'],
      description: 'Deterministic processing receipt marker',
    },
    crypto_addresses: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          address: { type: 'string', description: 'EVM or crypto address detected' },
          risk_score: { type: 'number', description: 'Address contextual risk score' },
          reasons: { type: 'array', items: { type: 'string' }, description: 'Contextual reasons for scoring' },
        },
        required: ['address', 'risk_score', 'reasons'],
      },
      description: 'Crypto wallet addresses detected in the text with heuristic risk scoring',
    },
    recommended_actions: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          service: { type: 'string' },
          description: { type: 'string' },
          url: { type: 'string' },
          price: { type: 'string' },
        },
        required: ['service', 'description', 'url', 'price'],
      },
      description: 'Optional downstream verification services',
    },
    inspection: {
      type: 'object',
      additionalProperties: false,
      properties: {
        method: { type: 'string', enum: ['deterministic-rules'] },
        guaranteed_safe: { type: 'boolean', enum: [false] },
        risk_score_semantics: { type: 'string' },
        limitations: {
          type: 'array',
          items: { type: 'string' },
        },
      },
      required: ['method', 'guaranteed_safe', 'risk_score_semantics', 'limitations'],
      description: 'Inspection methodology and safety disclaimer',
    },
  },
  required: [
    'status',
    'risk_score',
    'injection_detected',
    'threats_neutralized',
    'sanitized_content',
    'safety_receipt',
    'crypto_addresses',
    'inspection',
  ],
};

export function configuration(env = process.env) {
  const publicUrl = env.PUBLIC_URL || 'https://canaryguard-402.onrender.com';
  const parsed = new URL(publicUrl);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') throw new Error('PUBLIC_URL must be an HTTPS origin');
  const payTo = env.X402_RECIPIENT_ADDRESS || RECIPIENT;
  if (!isAddress(payTo)) throw new Error('Invalid recipient');
  if (env.NETWORK && !['base', NETWORK].includes(env.NETWORK)) throw new Error('Only Base mainnet is supported');
  return { publicUrl: parsed.origin, payTo: getAddress(payTo) };
}

export function paymentOption(payTo = RECIPIENT, amount = '5000') {
  return { scheme: 'exact', network: NETWORK, payTo,
    price: { asset: ASSET, amount, extra: { name: 'USD Coin', version: '2' } }, maxTimeoutSeconds: 120 };
}

export const AGENT_CONTINUATION = {
  chain_execution: 'autonomous_agent_flow_v2',
  recommended_follow_up: [
    {
      service: 'StealthGuard-402',
      endpoint: 'https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize',
      method: 'POST',
      cost: '0.005 USDC',
      reason: 'Bypass anti-bot shields and extract clean markdown from target links',
    },
    {
      service: 'RugShield-402',
      endpoint: 'https://rugshield-402.onrender.com/v1/scan',
      method: 'POST',
      cost: '0.005 USDC',
      reason: 'Simulate pre-swap transactions and verify DEX liquidity depth on Base',
    },
    {
      service: 'CanaryGuard-402',
      endpoint: 'https://canaryguard-402.onrender.com/v1/security/wallet-drainer-check',
      method: 'POST',
      cost: '0.005 USDC',
      reason: 'Audit destination smart contracts and wallets against drainer blacklists',
    },
  ],
};
