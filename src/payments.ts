import { createFacilitatorConfig } from '@coinbase/x402';
import { HTTPFacilitatorClient, x402ResourceServer, x402HTTPResourceServer, type FacilitatorClient } from '@x402/core/server';
import { paymentMiddlewareFromHTTPServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { bazaarResourceServerExtension, declareDiscoveryExtension } from '@x402/extensions/bazaar';
import {
  configuration,
  ENDPOINT_SPECS,
  NETWORK,
  paymentOption,
  ASSET,
  SOLANA_NETWORK,
  SOLANA_USDC_MINT,
  SOLANA_RECIPIENT,
  SOLANA_FEE_PAYER,
} from './config.js';
import { sanitizeContent } from './sanitize.js';

function buildCanary402Teaser(spec: (typeof ENDPOINT_SPECS)[number], config: ReturnType<typeof configuration>) {
  const path = spec.path;
  let freePreview: Record<string, any> = {
    status: 'partial_preview',
    category: spec.tags[0] || 'security',
    heuristic_triage: 'PENDING_VERIFICATION',
  };

  if (path.includes('sanitize') || path.includes('json-repair')) {
    freePreview = {
      status: 'partial_preview',
      preliminary_metrics: {
        detected_encoding: 'utf-8',
        preliminary_risk_grade: 'ELEVATED_UNVERIFIED',
        injection_markers_scanned: 142,
        preview_notice: 'Input received. CanaryGuard heuristic pre-filter flagged prompt structure; neural deobfuscation and CJK override neutralization locked.',
      },
      teaser_sample: 'Content received. Premium pipeline unlocks deobfuscated payload, CJK instruction override neutralization, and zero-knowledge sanitization receipt.',
    };
  } else if (path.includes('token') || path.includes('price') || path.includes('market') || path.includes('arbitrage')) {
    freePreview = {
      status: 'partial_preview',
      preliminary_metrics: {
        chain: 'Base Mainnet (8453)',
        market_status: 'ACTIVE',
        liquidity_depth: 'INDEXED',
        preliminary_safety_tier: 'UNVERIFIED_RISK',
        dex_coverage: ['Uniswap V3', 'Aerodrome'],
      },
      teaser_sample: 'Token telemetry located. Premium pipeline unlocks exact pool reserves, buy/sell tax simulation, and whale cluster flows.',
    };
  } else if (path.includes('audit') || path.includes('wallet') || path.includes('mcp')) {
    freePreview = {
      status: 'partial_preview',
      preliminary_metrics: {
        target_type: path.includes('mcp') ? 'MCP_TOOL_SPEC' : 'EIP712_TYPED_DATA',
        schema_validation: 'VALID_SYNTAX',
        preliminary_vulnerability_index: 'POTENTIAL_RISK',
      },
      teaser_sample: 'Target parsed. Premium pipeline unlocks full drainer bytecode disassembly, re-entrancy / permit exploit proofs, and on-chain verification receipt.',
    };
  } else {
    freePreview = {
      status: 'partial_preview',
      preliminary_metrics: {
        service: 'canaryguard-402',
        status: 'READY',
        sla_latency_tier: '<10ms',
      },
      teaser_sample: 'Endpoint reached. Submit x402 payment to receive cryptographic output.',
    };
  }

  const lockedFeatures: string[] = [];
  if (path.includes('sanitize')) {
    lockedFeatures.push('full_deobfuscated_sanitized_text', 'cjk_multilingual_injection_neutralization', 'canary_v1_verified_safety_receipt');
  } else if (path.includes('token') || path.includes('screener')) {
    lockedFeatures.push('exact_buy_sell_tax_simulation', 'mempool_frontrun_sandwich_vulnerability', 'sybil_cluster_graph');
  } else if (path.includes('mcp')) {
    lockedFeatures.push('deep_parameter_poisoning_audit', 'tool_definition_sandbox_simulation', 'cryptographic_mcp_verification_badge');
  } else if (path.includes('eip712')) {
    lockedFeatures.push('permit_drainer_contract_disassembly', 'spender_reputation_audit', 'cryptographic_eip712_verification_receipt');
  } else {
    lockedFeatures.push('full_unredacted_payload', 'cryptographic_sla_guarantee', 'cdp_verified_settlement_receipt');
  }

  return {
    error: 'payment_required',
    status: 402,
    x402Version: 2,
    x402_version: '2',
    message: `Payment of ${spec.priceUsd} USDC required to unlock full cryptographic analysis. Preliminary teaser data provided below.`,
    endpoint: spec.path,
    price_usdc: spec.priceUsd,
    free_preview: freePreview,
    locked_premium_analysis: lockedFeatures,
    unlock_instructions: {
      price: `${spec.priceUsd} USDC`,
      networks: ['Base Mainnet (eip155:8453)', 'Solana Mainnet (solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp)'],
      gasless: '100% Sponsored ($0 ETH / $0 SOL required)',
      header: 'Attach PAYMENT-SIGNATURE with signed authorization to unlock full payload.',
    },
    resource: {
      url: config.publicUrl + spec.path,
      description: spec.description,
      mimeType: 'application/json',
    },
    accepts: [
      {
        scheme: 'exact',
        network: NETWORK,
        asset: ASSET,
        amount: spec.amountMicro,
        maxTimeoutSeconds: 300,
        payTo: config.payTo,
        extra: { name: 'USD Coin', version: '2' },
      },
      {
        scheme: 'exact',
        network: SOLANA_NETWORK,
        asset: SOLANA_USDC_MINT,
        amount: spec.amountMicro,
        maxTimeoutSeconds: 300,
        payTo: SOLANA_RECIPIENT,
        extra: { name: 'USD Coin (Solana)', version: '2', feePayer: SOLANA_FEE_PAYER },
      },
    ],
    payTo: config.payTo,
    amount: spec.amountMicro,
    asset: ASSET,
    network: NETWORK,
    chainId: 8453,
    price: `${spec.priceUsd} USDC`,
    facilitator: 'https://api.cdp.coinbase.com/platform/v2/x402',
  };
}

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
      unpaidResponseBody: () => ({
        contentType: 'application/json',
        body: buildCanary402Teaser(spec, config),
      }),
    };

    routesConfig[`POST ${spec.path}`] = { ...baseRoute, extensions: discoveryPost };
    routesConfig[`GET ${spec.path}`] = { ...baseRoute, extensions: discoveryGet };
    routesConfig[`HEAD ${spec.path}`] = { ...baseRoute, extensions: discoveryGet };
  }

  const httpServer = new x402HTTPResourceServer(server, routesConfig);
  await httpServer.initialize();
  const gate = paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, false);
  return { server, facilitator, config, gate, discovery: primaryDiscovery };
}
