import { z } from "zod";

export const CanaryGuardSanitizeInputSchema = z.object({
  content: z
    .string()
    .min(1)
    .max(200_000)
    .describe("Untrusted text, scraped HTML, email, or third-party tool output to sanitize before placing into agent context"),
  strictMode: z
    .boolean()
    .optional()
    .default(true)
    .describe("When true, redacts high-risk crypto addresses and base64 blobs, and blocks wallet-draining commands"),
});

export type CanaryGuardSanitizeInput = z.infer<typeof CanaryGuardSanitizeInputSchema>;

export interface CanaryGuardSanitizeOutput {
  status: "clean" | "neutralized" | "blocked";
  riskScore: number;
  injectionDetected: boolean;
  threatsNeutralized: Array<{ type: string; detail: string; severity: number }>;
  cryptoAddresses: Array<{ address: string; chain: string; risk_score: number; reason: string }>;
  sanitizedContent: string;
  safetyReceipt: string;
}

/**
 * Execute prompt-injection inspection and sanitization via CanaryGuard 402 microservice on Base.
 */
export async function executeCanaryGuardSanitize(
  params: CanaryGuardSanitizeInput,
  options?: { hostUrl?: string; paymentHeader?: string }
): Promise<CanaryGuardSanitizeOutput> {
  const host = (
    options?.hostUrl ||
    process.env.CANARYGUARD_URL ||
    "https://canaryguard-402.onrender.com"
  ).replace(/\/$/, "");

  const url = `${host}/v1/sanitize`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (options?.paymentHeader) {
    headers["X-PAYMENT"] = options.paymentHeader;
  }

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      content: params.content,
      strict_mode: params.strictMode !== false,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`CanaryGuard 402 error (${res.status}): ${text}`);
  }

  const data = (await res.json()) as any;
  return {
    status: data.status,
    riskScore: data.risk_score,
    injectionDetected: data.injection_detected,
    threatsNeutralized: data.threats_neutralized || [],
    cryptoAddresses: data.crypto_addresses || [],
    sanitizedContent: data.sanitized_content,
    safetyReceipt: data.safety_receipt,
  };
}
