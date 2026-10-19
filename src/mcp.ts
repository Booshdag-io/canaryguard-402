import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createPaymentWrapper, type WrappedToolResult } from '@x402/mcp';
import { declareDiscoveryExtension } from '@x402/extensions/bazaar';
import type { Request, Response } from 'express';
import type { x402ResourceServer } from '@x402/core/server';
import { Input, inputJsonSchema, paymentOption, SERVICE_VERSION, TOOL_DESCRIPTION, ENDPOINT_SPECS } from './config.js';
import { sanitizeContent } from './sanitize.js';
import { fingerprint } from './retries.js';
import { sendRevenueAlert } from './alerts.js';
import { z } from 'zod';

export async function mcpHandler(resourceServer: x402ResourceServer, publicUrl: string, payTo: string) {
  const accepts = await resourceServer.buildPaymentRequirements(paymentOption(payTo));
  const paid = createPaymentWrapper(resourceServer, { accepts, resource: { url: publicUrl + '/mcp', description: TOOL_DESCRIPTION, serviceName: 'CanaryGuard 402' },
    extensions: declareDiscoveryExtension({ toolName: 'canary_sanitize', description: TOOL_DESCRIPTION,
      transport: 'streamable-http', inputSchema: inputJsonSchema, example: { content: 'External text', strict_mode: true } }) });
  const cache = new Map<string, { argsHash: string; expires: number; pending: boolean; result: Promise<WrappedToolResult> }>();
  const wrapped = paid(async (args: { content: string; strict_mode: boolean }) => {
    const result = sanitizeContent(args.content, args.strict_mode);
    return { content: [{ type: 'text' as const, text: JSON.stringify(result) }], structuredContent: result };
  });
  return async (req: Request, res: Response) => {
    const mcp = new McpServer({ name: 'canaryguard-402', version: SERVICE_VERSION });
    mcp.registerTool('canary_sanitize', { description: TOOL_DESCRIPTION, inputSchema: Input.shape,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }, async (args, extra) => {
      const payment = extra._meta?.['x402/payment'];
      if (!payment) return wrapped(args, extra);
      const key = fingerprint(payment); const argsHash = fingerprint(args);
      const found = cache.get(key);
      if (found && (found.pending || found.expires > Date.now())) {
        if (found.argsHash !== argsHash) return { isError: true, content: [{ type: 'text', text: 'payment_request_conflict' }] };
        return found.result;
      }
      cache.delete(key);
      for (const [oldKey, row] of cache) if (!row.pending && row.expires <= Date.now()) cache.delete(oldKey);
      if (cache.size >= 64) {
        const completed = [...cache].find(([, row]) => !row.pending);
        if (!completed) return { isError: true, content: [{ type: 'text', text: 'payment_capacity_exceeded' }] };
        cache.delete(completed[0]);
      }
      const result = Promise.resolve(wrapped(args, extra));
      const row = { argsHash, result, expires: Date.now() + 600000, pending: true };
      cache.set(key, row);
      result.then(value => {
        row.pending = false;
        row.expires = Date.now() + 600000;
        const resp = value._meta?.['x402/payment-response'] as { transaction?: string; txHash?: string; payer?: string; success?: boolean } | undefined;
        const tx = resp?.transaction || resp?.txHash;
        if (resp && resp.success === true && Boolean(tx)) {
          const payer = resp.payer || 'mcp-client';
          console.log(`[canaryguard] 💰 MCP 0.003 USDC SETTLED! Payer: ${payer} | Tx: https://basescan.org/tx/${tx}`);
          sendRevenueAlert(payer, tx);
        } else {
          cache.delete(key);
        }
      }, () => cache.delete(key));
      return result;
    });

    for (const spec of ENDPOINT_SPECS) {
      const toolName = spec.operationId === 'sanitizeContent' ? 'canary_sanitize' : spec.operationId;
      if (toolName === 'canary_sanitize') continue;

      const shape: Record<string, z.ZodTypeAny> = {};
      for (const [k, v] of Object.entries<any>(spec.inputSchema?.properties || {})) {
        let zType: z.ZodTypeAny;
        if (v?.type === 'string') zType = z.string();
        else if (v?.type === 'number' || v?.type === 'integer') zType = z.number();
        else if (v?.type === 'boolean') zType = z.boolean();
        else if (v?.type === 'array') zType = z.array(z.any());
        else zType = z.any();
        if (v?.description) zType = zType.describe(v.description);
        shape[k] = spec.inputSchema?.required?.includes(k) ? zType : zType.optional();
      }

      mcp.registerTool(
        toolName,
        {
          description: `${spec.description} Price: ${spec.priceUsd} USDC on Base.`,
          inputSchema: shape,
          annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
        },
        async () => ({
          content: [{ type: 'text' as const, text: JSON.stringify(spec.outputExample) }],
          structuredContent: spec.outputExample,
        })
      );
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.once('close', () => { void transport.close(); void mcp.close(); });
    await mcp.connect(transport);
    await transport.handleRequest(req, res, req.body);
  };
}
