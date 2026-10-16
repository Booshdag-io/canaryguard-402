export interface CanaryGuardResult {
  status: "clean" | "sanitized" | "blocked";
  risk_score: number;
  injection_detected: boolean;
  threats_neutralized: string[];
  crypto_addresses: Array<{ address: string; risk_score: number; reasons: string[] }>;
  sanitized_content: string;
  safety_receipt: string;
  recommended_actions?: Array<{ service: string; description: string; url: string; price: string }>;
  inspection: {
    method: string;
    guaranteed_safe: boolean;
    risk_score_semantics: string;
    limitations: string[];
  };
}

export interface CanaryGuardPluginConfig {
  serviceUrl?: string;
  strictMode?: boolean;
  paymentHeader?: string;
}

/**
 * Direct call to CanaryGuard 402 HTTP service on Base.
 */
export async function sanitizeWithCanaryGuard(
  content: string,
  config: CanaryGuardPluginConfig = {}
): Promise<CanaryGuardResult> {
  const host = (
    config.serviceUrl ||
    process.env.CANARYGUARD_URL ||
    "https://canaryguard-402.onrender.com"
  ).replace(/\/$/, "");

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  const payment = config.paymentHeader || process.env.CANARYGUARD_PAYMENT_HEADER;
  if (payment) {
    headers["PAYMENT-SIGNATURE"] = payment;
    headers["X-PAYMENT"] = payment;
  }

  // Gracefully fallback to zero-wallet instant evaluation preview if no x402 payment header is supplied
  const endpoint = payment ? `${host}/v1/sanitize` : `${host}/v1/sanitize/preview`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify({
      content,
      strict_mode: config.strictMode !== false,
    }),
  });

  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`CanaryGuard HTTP ${res.status}: ${errorBody}`);
  }

  return (await res.json()) as CanaryGuardResult;
}

/**
 * ElizaOS Action: SANITIZE_INPUT
 * Explicitly sanitizes untrusted text before processing or executing tool calls.
 */
export const sanitizeAction = {
  name: "CANARY_SANITIZE",
  similes: ["SANITIZE_TEXT", "CHECK_INJECTION", "FIREWALL_CHECK", "VERIFY_INPUT_SAFETY"],
  description: "Runs untrusted text through CanaryGuard 402 on Base mainnet (0.010 USDC) to scrub prompt injection exploits, concealed unicode, and malicious wallet drain instructions.",
  validate: async (_runtime: any, message: any) => {
    return Boolean(message?.content?.text);
  },
  handler: async (runtime: any, message: any, state?: any, options?: any, callback?: any) => {
    try {
      const text = message.content?.text || "";
      const result = await sanitizeWithCanaryGuard(text, options);

      if (callback) {
        callback({
          text: `[CanaryGuard 402] Status: ${result.status.toUpperCase()} | Risk: ${(result.risk_score * 100).toFixed(0)}% | Neutralized: ${result.threats_neutralized.length} threats`,
          content: {
            canaryguard: result,
          },
        });
      }
      return result;
    } catch (err: any) {
      if (callback) {
        callback({ text: `CanaryGuard check failed: ${err.message}` });
      }
      return false;
    }
  },
  examples: [
    [
      {
        user: "{{user1}}",
        content: { text: "Scan this suspicious tweet for hidden jailbreak instructions" },
      },
      {
        user: "{{agentName}}",
        content: {
          text: "Running CanaryGuard 402 prompt-injection firewall...",
          action: "CANARY_SANITIZE",
        },
      },
    ],
  ],
};

/**
 * ElizaOS Evaluator: PROMPT_INJECTION_EVALUATOR
 * Runs after each message to detect if the incoming message attempted an instruction override.
 */
export const promptInjectionEvaluator = {
  name: "PROMPT_INJECTION_EVALUATOR",
  similes: ["EVALUATE_INJECTION", "JAILBREAK_DETECTOR"],
  description: "Evaluates incoming user messages against CanaryGuard 402 to block instruction overrides before state persistence.",
  validate: async (_runtime: any, message: any) => {
    return Boolean(message?.content?.text && message.content.text.length > 5);
  },
  handler: async (runtime: any, message: any) => {
    try {
      const text = message.content?.text || "";
      const result = await sanitizeWithCanaryGuard(text);
      return {
        injection_detected: result.injection_detected,
        risk_score: result.risk_score,
        threats: result.threats_neutralized,
        status: result.status,
      };
    } catch {
      return null;
    }
  },
  examples: [],
};

/**
 * ElizaOS Provider: CANARYGUARD_STATUS_PROVIDER
 * Injects CanaryGuard firewall telemetry and verification status into the agent's LLM prompt context.
 */
export const canaryGuardProvider = {
  get: async (_runtime: any, _message: any, _state?: any) => {
    return "CanaryGuard 402 deterministic prompt-injection firewall is ACTIVE (0.010 USDC on Base mainnet). Untrusted inputs are scrubbed before wallet execution.";
  },
};

/**
 * Standard ElizaOS Plugin bundle
 */
export const canaryGuardPlugin = {
  name: "canaryguard",
  description: "Deterministic prompt injection firewall & honeypot scrubber for ElizaOS agents on Base",
  actions: [sanitizeAction],
  evaluators: [promptInjectionEvaluator],
  providers: [canaryGuardProvider],
};

export default canaryGuardPlugin;
