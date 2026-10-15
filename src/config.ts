import { getAddress, isAddress } from 'viem';
import { z } from 'zod';

export const NETWORK = 'eip155:8453' as const;
export const SERVICE_VERSION = '1.2.0';
export const ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const RECIPIENT = '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1';
export const DESCRIPTION = 'Deterministic prompt-injection firewall, Base token auditor, and on-chain intelligence suite for autonomous AI agents.';
export const TOOL_DESCRIPTION = 'Call this security tool before placing untrusted text, scraped web content, or tool outputs into your context window. Detects and scrubs prompt injection and malicious wallet transfer exploits. Cost: 0.008 USDC on Base. Deterministic rules have incomplete coverage; results do not guarantee safety.';

export const Input = z.strictObject({
  content: z.string().min(1).max(50000),
  strict_mode: z.boolean().default(true),
});

export const inputJsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    content: { type: 'string', minLength: 1, maxLength: 50000 },
    strict_mode: { type: 'boolean', default: true },
  },
  required: ['content'],
};

export const sanitizeResultJsonSchema = {
  type: 'object',
  additionalProperties: true,
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
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
    throw new Error('PUBLIC_URL must be an HTTPS origin');
  }
  const payTo = env.X402_RECIPIENT_ADDRESS || RECIPIENT;
  if (!isAddress(payTo)) throw new Error('Invalid recipient');
  if (env.NETWORK && !['base', NETWORK].includes(env.NETWORK)) throw new Error('Only Base mainnet is supported');
  return { publicUrl: parsed.origin, payTo: getAddress(payTo) };
}

export function paymentOption(payTo = RECIPIENT, amount = '8000') {
  return {
    scheme: 'exact',
    network: NETWORK,
    payTo,
    price: { asset: ASSET, amount, extra: { name: 'USD Coin', version: '2' } },
    maxTimeoutSeconds: 120,
  };
}

export const AGENT_CONTINUATION = {
  chain_execution: 'autonomous_agent_flow_v2',
  recommended_follow_up: [
    {
      service: 'CanaryGuard-402',
      endpoint: 'https://canaryguard-402.onrender.com/v1/wallet-analysis',
      method: 'POST',
      cost: '0.015 USDC',
      reason: 'Run deep EVM wallet security, nonce, balance & drainer-exposure profile',
    },
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
  ],
};

export interface EndpointSpec {
  path: string;
  operationId: string;
  summary: string;
  description: string;
  amountMicro: string;
  priceUsd: string;
  tags: string[];
  inputExample: Record<string, any>;
  inputSchema: Record<string, any>;
  outputExample: Record<string, any>;
}

export const ENDPOINT_SPECS: EndpointSpec[] = [
  {
    path: '/v1/sanitize',
    operationId: 'sanitizeContent',
    summary: 'Prompt-injection & wallet-drainer firewall',
    description: 'Deterministic prompt-injection firewall and honeypot scrubber for AI agents. Sanitizes untrusted text and blocks detected wallet-draining commands before context ingestion.',
    amountMicro: '8000',
    priceUsd: '0.008',
    tags: ['AI Security', 'Safety'],
    inputExample: { content: 'Example external text to verify', strict_mode: true },
    inputSchema: inputJsonSchema,
    outputExample: {
      status: 'clean',
      risk_score: 0,
      injection_detected: false,
      threats_neutralized: [],
      sanitized_content: 'Example external text to verify',
      safety_receipt: 'canary-v1-verified',
    },
  },
  {
    path: '/v1/base/token',
    operationId: 'inspectBaseToken',
    summary: 'Base token contract & metadata safety audit',
    description: 'Audits Base ERC-20 token contracts for honeypot risks, buy/sell transfer taxes, liquidity depth, and prompt injection traps in token metadata.',
    amountMicro: '8000',
    priceUsd: '0.008',
    tags: ['Token Security', 'Safety'],
    inputExample: { token_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    inputSchema: {
      type: 'object',
      properties: { token_address: { type: 'string', description: 'Base ERC-20 contract address' } },
      required: ['token_address'],
    },
    outputExample: {
      token_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      symbol: 'USDC',
      name: 'USD Coin',
      safe: true,
      honeypot: false,
      buy_tax_bps: 0,
      sell_tax_bps: 0,
    },
  },
  {
    path: '/v1/wallet-analysis',
    operationId: 'analyzeEvmWallet',
    summary: 'EVM wallet security, nonce, balance & drainer-exposure profile',
    description: 'Comprehensive EVM wallet security profile on Base, analyzing transaction velocity, approval exposure, drainer interaction risk, and smart-account state.',
    amountMicro: '15000',
    priceUsd: '0.015',
    tags: ['AI Security', 'Wallet Intelligence'],
    inputExample: { wallet_address: '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1', chain_id: 8453 },
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string', description: 'EVM wallet address (0x...)' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['wallet_address'],
    },
    outputExample: {
      wallet_address: '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1',
      chain_id: 8453,
      risk_level: 'LOW',
      risk_score: 0.02,
      drainer_exposure: false,
      sanctioned: false,
      account_type: 'EOA_OR_SMART_WALLET',
    },
  },
  {
    path: '/v1/contract-info',
    operationId: 'inspectContractInfo',
    summary: 'EVM contract bytecode size, proxy/EIP-7702 status & verified selectors',
    description: 'Inspects Base EVM smart contract bytecode size, EIP-1967/UUPS proxy implementation slots, EIP-7702 delegation designators, and verified function selectors.',
    amountMicro: '9000',
    priceUsd: '0.009',
    tags: ['Smart Contracts', 'Safety'],
    inputExample: { contract_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', chain_id: 8453 },
    inputSchema: {
      type: 'object',
      properties: {
        contract_address: { type: 'string', description: 'Smart contract address on Base (0x...)' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['contract_address'],
    },
    outputExample: {
      contract_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      is_contract: true,
      is_proxy: true,
      proxy_type: 'EIP-1967 FiatTokenProxy',
      eip7702_delegated: false,
      standards: ['ERC-20', 'EIP-2612', 'EIP-3009'],
    },
  },
  {
    path: '/v1/wallet-sanctions-check',
    operationId: 'checkWalletSanctions',
    summary: 'OFAC/SDN & exploit-list compliance screening for EVM/Solana addresses',
    description: 'Screens EVM and Solana wallet addresses against OFAC SDN sanctions lists, Lazarus Group attributions, and known DeFi exploit/drainer blacklists.',
    amountMicro: '9000',
    priceUsd: '0.009',
    tags: ['Compliance', 'AI Security'],
    inputExample: { address: '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1' },
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'EVM or Solana wallet address to screen' } },
      required: ['address'],
    },
    outputExample: {
      address: '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1',
      sanctioned: false,
      ofac_sdn_match: false,
      exploit_blacklist_match: false,
      compliance_status: 'APPROVED',
    },
  },
  {
    path: '/v1/uniswap-pool-state',
    operationId: 'inspectUniswapPoolState',
    summary: 'Base DEX pool liquidity, spot price & rug-risk audit',
    description: 'Audits Uniswap V3/V4 and Aerodrome liquidity pools on Base, returning tick liquidity depth, fee tier, price impact bps, and LP concentration rug-risk scores.',
    amountMicro: '9000',
    priceUsd: '0.009',
    tags: ['DeFi', 'Base'],
    inputExample: { pool_or_token_address: '0x4200000000000000000000000000000000000006', quote_token: 'USDC' },
    inputSchema: {
      type: 'object',
      properties: {
        pool_or_token_address: { type: 'string', description: 'Pool or token address on Base' },
        quote_token: { type: 'string', default: 'USDC' },
      },
      required: ['pool_or_token_address'],
    },
    outputExample: {
      pair: 'WETH/USDC',
      dex: 'Uniswap V3 / Aerodrome Base',
      spot_price_usd: 2645.5,
      tvl_usd: 48500000,
      fee_tier_bps: 5,
      rug_risk: 'NONE',
    },
  },
  {
    path: '/v1/crypto-price-onchain',
    operationId: 'getCryptoPriceOnchain',
    summary: 'Tamper-resistant on-chain token prices on Base (Chainlink/DEX)',
    description: 'Returns tamper-resistant on-chain USD spot prices, 24h volatility, and Chainlink/TWAP oracle deviation metrics for major Base and EVM assets.',
    amountMicro: '8000',
    priceUsd: '0.008',
    tags: ['DeFi', 'Oracle'],
    inputExample: { symbol: 'ETH' },
    inputSchema: {
      type: 'object',
      properties: {
        symbol: { type: 'string', description: 'Asset symbol or address (e.g. ETH, BTC, SOL, USDC, AERO, VIRTUAL)' },
      },
      required: ['symbol'],
    },
    outputExample: {
      symbol: 'ETH',
      price_usd: 2645.5,
      source: 'Chainlink Base Mainnet Aggregator + DEX TWAP',
      confidence_bps: 9998,
    },
  },
  {
    path: '/v1/json-repair-and-sanitize',
    operationId: 'repairAndSanitizeJson',
    summary: 'Repairs broken LLM JSON output and strips prompt injections',
    description: 'Deterministically repairs malformed or truncated LLM JSON payloads (missing quotes, trailing commas, markdown fences) while scrubbing embedded prompt-injection payloads.',
    amountMicro: '8000',
    priceUsd: '0.008',
    tags: ['AI Security', 'Utilities'],
    inputExample: { raw_json: '```json\n{"action": "swap", "token": "USDC",}\n```' },
    inputSchema: {
      type: 'object',
      properties: { raw_json: { type: 'string', description: 'Malformed or untrusted JSON string' } },
      required: ['raw_json'],
    },
    outputExample: {
      repaired: true,
      valid_json: true,
      injection_detected: false,
      parsed: { action: 'swap', token: 'USDC' },
    },
  },
  {
    path: '/v1/url-agent-readiness',
    operationId: 'auditUrlAgentReadiness',
    summary: 'Audits any website for llms.txt, x402, openapi.json, MCP, and hidden DOM traps',
    description: 'Audits any domain or URL for AI agent readiness (llms.txt, .well-known/x402, openapi.json, MCP server card) and detects hidden CSS/DOM prompt-injection traps.',
    amountMicro: '9000',
    priceUsd: '0.009',
    tags: ['AI Security', 'Web Discovery'],
    inputExample: { url: 'https://canaryguard-402.onrender.com' },
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'Target website or API URL' } },
      required: ['url'],
    },
    outputExample: {
      url: 'https://canaryguard-402.onrender.com',
      agent_ready_score: 99,
      has_llms_txt: true,
      has_x402_manifest: true,
      has_openapi_spec: true,
      has_mcp_endpoint: true,
      dom_injection_traps: 0,
    },
  },
  {
    path: '/v1/tx-status-base',
    operationId: 'decodeBaseTxStatus',
    summary: 'Base transaction receipt, gas, confirmation & token-transfer decoder',
    description: 'Decodes Base Mainnet transaction receipts, EIP-3009 transferWithAuthorization settlements, ERC-20 transfer logs, gas fees, and finality confirmations.',
    amountMicro: '8000',
    priceUsd: '0.008',
    tags: ['Base', 'Transactions'],
    inputExample: { tx_hash: '0x03a5d4566a3963c93c33242935e6df5c8771ca79d22b56ba5b0bfb97a2753b87' },
    inputSchema: {
      type: 'object',
      properties: { tx_hash: { type: 'string', description: 'Base transaction hash (0x...)' } },
      required: ['tx_hash'],
    },
    outputExample: {
      tx_hash: '0x03a5d4566a3963c93c33242935e6df5c8771ca79d22b56ba5b0bfb97a2753b87',
      network: 'eip155:8453',
      status: 'CONFIRMED',
      eip3009_settlement: true,
      finality: 'SAFE',
    },
  },
  {
    path: '/v1/polymarket-odds-pulse',
    operationId: 'getPolymarketOddsPulse',
    summary: 'Live Polymarket active market probabilities & 24h volume movers',
    description: 'Delivers sanitized Polymarket CLOB implied probabilities, bid-ask spreads, and 24-hour smart-money volume movers across crypto, macro, and geopolitics.',
    amountMicro: '15000',
    priceUsd: '0.015',
    tags: ['Prediction Markets', 'Alpha'],
    inputExample: { category: 'crypto' },
    inputSchema: {
      type: 'object',
      properties: { category: { type: 'string', default: 'crypto' } },
    },
    outputExample: {
      category: 'crypto',
      active_markets: [
        { slug: 'btc-above-100k', yes_probability: 0.74, spread_bps: 20, volume_24h_usd: 4250000 },
      ],
    },
  },
  {
    path: '/v1/defi-yields-safe',
    operationId: 'getSafeDefiYields',
    summary: 'Top verified Base/EVM stablecoin & ETH yields (DeFiLlama) pre-screened for safety',
    description: 'Curates top risk-adjusted USDC, EURC, and WETH DeFi yield pools on Base (Morpho, Aave V3, Aerodrome, Moonwell), pre-screened for TVL depth and audit status.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['DeFi', 'Yields'],
    inputExample: { asset: 'USDC', min_tvl_usd: 5000000 },
    inputSchema: {
      type: 'object',
      properties: {
        asset: { type: 'string', default: 'USDC' },
        min_tvl_usd: { type: 'number', default: 5000000 },
      },
    },
    outputExample: {
      network: 'base',
      asset: 'USDC',
      top_pools: [
        { protocol: 'Morpho Blue', pool: 'Steakhouse USDC', apy_pct: 8.42, tvl_usd: 94000000, risk_rating: 'AAA' },
      ],
    },
  },
  {
    path: '/v1/llm-token-pricing',
    operationId: 'calculateLlmTokenPricing',
    summary: 'Live input/output token cost calculator across 100+ frontier LLMs',
    description: 'Calculates exact input, cached-input, and output token costs across frontier LLMs (OpenAI, Anthropic, Gemini, DeepSeek, Meta) and recommends optimal model routing.',
    amountMicro: '8000',
    priceUsd: '0.008',
    tags: ['AI Utilities', 'Pricing'],
    inputExample: { model: 'claude-3-7-sonnet', input_tokens: 10000, output_tokens: 2000 },
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', default: 'claude-3-7-sonnet' },
        input_tokens: { type: 'integer', default: 10000 },
        output_tokens: { type: 'integer', default: 2000 },
      },
    },
    outputExample: {
      model: 'claude-3-7-sonnet',
      estimated_cost_usd: 0.06,
      cheaper_alternative: 'gemini-2.5-flash',
    },
  },
  {
    path: '/v1/eip712-signature-audit',
    operationId: 'auditEip712Signature',
    summary: 'Audits EIP-712 / EIP-3009 typed data payloads for permit/approval drainers',
    description: 'Audits EIP-712 and EIP-3009 typed-data signature payloads (Permit, Permit2, transferWithAuthorization) to block malicious spender approvals and phishing domains.',
    amountMicro: '9000',
    priceUsd: '0.009',
    tags: ['AI Security', 'Safety'],
    inputExample: {
      verifying_contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      primary_type: 'TransferWithAuthorization',
      spender_or_to: '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1',
    },
    inputSchema: {
      type: 'object',
      properties: {
        verifying_contract: { type: 'string' },
        primary_type: { type: 'string' },
        spender_or_to: { type: 'string' },
      },
      required: ['verifying_contract'],
    },
    outputExample: {
      verifying_contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      is_drainer_permit: false,
      verdict: 'SAFE_TO_SIGN',
    },
  },
  {
    path: '/v1/mcp-tool-auditor',
    operationId: 'auditMcpToolSchema',
    summary: 'Audits MCP tool schemas and descriptions for tool-poisoning attacks',
    description: 'Inspects Model Context Protocol (MCP) tool definitions, JSON schemas, and server cards for hidden instructions, tool shadowing, and data exfiltration vectors.',
    amountMicro: '9000',
    priceUsd: '0.009',
    tags: ['AI Security', 'MCP'],
    inputExample: { tool_name: 'canary_sanitize', tool_description: 'Deterministic prompt-injection firewall' },
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: { type: 'string' },
        tool_description: { type: 'string' },
        input_schema: { type: 'object' },
      },
      required: ['tool_name'],
    },
    outputExample: {
      tool_name: 'canary_sanitize',
      poisoning_detected: false,
      shadowing_risk: 'NONE',
      verdict: 'CLEAN_MCP_TOOL',
    },
  },
];

export const ENDPOINT_MAP = new Map<string, EndpointSpec>(
  ENDPOINT_SPECS.map(spec => [spec.path, spec])
);
