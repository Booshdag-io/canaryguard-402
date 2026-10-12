/**
 * CanaryGuard 402 - TypeScript / Node SDK
 *
 * Deterministic prompt-injection firewall and honeypot scrubber for AI agents.
 * 0.003 USDC per call on Base (eip155:8453) via x402.
 */

import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

export interface SanitizeOptions {
  content: string;
  strictMode?: boolean;
}

export interface Threat {
  type: string;
  detail: string;
  severity: number;
}

export interface ExtractedAddress {
  address: string;
  chain: "evm" | "bitcoin" | "solana";
  risk_score: number;
  reason: string;
}

export interface SanitizeResponse {
  status: "clean" | "neutralized" | "blocked";
  risk_score: number;
  injection_detected: boolean;
  threats_neutralized: Threat[];
  crypto_addresses: ExtractedAddress[];
  sanitized_content: string;
  stats: { input_chars: number; output_chars: number; zero_width_removed: number };
  safety_receipt: string;
}

export class CanaryGuardClient {
  private baseUrl: string;
  private payingFetch: typeof fetch;

  constructor(options?: {
    baseUrl?: string;
    privateKey?: `0x${string}`;
    customFetch?: typeof fetch;
  }) {
    this.baseUrl = (options?.baseUrl ?? "https://canaryguard-402.onrender.com").replace(/\/$/, "");

    if (options?.privateKey) {
      const account = privateKeyToAccount(options.privateKey);
      const client = new x402Client();
      registerExactEvmScheme(client, { signer: account });
      this.payingFetch = wrapFetchWithPayment(options.customFetch ?? fetch, client);
    } else {
      this.payingFetch = options?.customFetch ?? fetch;
    }
  }

  async sanitize(options: SanitizeOptions): Promise<SanitizeResponse> {
    const res = await this.payingFetch(`${this.baseUrl}/v1/sanitize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: options.content,
        strict_mode: options.strictMode ?? true,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`CanaryGuard HTTP ${res.status}: ${errText}`);
    }

    return (await res.json()) as SanitizeResponse;
  }

  async health(): Promise<{ status: string; service: string; version: string }> {
    const res = await fetch(`${this.baseUrl}/health`);
    return await res.json();
  }

  async stats(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/stats`);
    return await res.json();
  }
}
