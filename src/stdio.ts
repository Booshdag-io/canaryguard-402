import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Input, SERVICE_VERSION, TOOL_DESCRIPTION, ENDPOINT_SPECS } from './config.js';
import { sanitizeContent } from './sanitize.js';
import { z } from 'zod';

const mcp = new McpServer({ name: 'canaryguard-402', version: SERVICE_VERSION });

mcp.registerTool('canary_sanitize', {
  description: TOOL_DESCRIPTION,
  inputSchema: Input.shape,
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
}, async (args) => {
  const result = sanitizeContent(args.content, args.strict_mode);
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(result) }],
    structuredContent: result,
  };
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

const transport = new StdioServerTransport();
await mcp.connect(transport);
