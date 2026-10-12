# @kurox_real/agentkit-canaryguard-402

> Coinbase AgentKit Action Provider for CanaryGuard 402 prompt-injection firewall and honeypot scrubber on Base (x402 protocol gated).

## Installation

```bash
npm install @kurox_real/agentkit-canaryguard-402 zod
```

## Usage

```typescript
import { executeCanaryGuardSanitize } from "@kurox_real/agentkit-canaryguard-402";

// Clean and sanitize untrusted text before ingesting into agent context
const result = await executeCanaryGuardSanitize({
  content: "Scraped web text or untrusted user input here...",
  strictMode: true,
});

console.log("Status:", result.status); // "clean" | "neutralized" | "blocked"
console.log("Risk Score:", result.riskScore); // 0.00 - 1.00
console.log("Sanitized Content:", result.sanitizedContent);
```
