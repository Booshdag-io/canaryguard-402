import { Actor } from 'apify';
import { sanitizeContent } from './sanitize.js';

interface CanaryActorInput {
  content?: string;
  strict_mode?: boolean;
}

await Actor.init();

try {
  const input = (await Actor.getInput<CanaryActorInput>()) || {};
  const content = input.content || 'Test benign agent context prompt';
  const strictMode = input.strict_mode ?? true;

  console.log(`[canaryguard-apify] Processing content (length: ${content.length}, strict: ${strictMode})`);

  // Charge 1 Pay-Per-Event (PPE) event: sanitize_content ($0.003 USD)
  try {
    await Actor.charge({ eventName: 'sanitize_content', count: 1 });
    console.log('[canaryguard-apify] Charged 1 sanitize_content PPE event ($0.003)');
  } catch (chargeErr: any) {
    console.warn(`[canaryguard-apify] PPE charge notice: ${chargeErr?.message || chargeErr}`);
  }

  // Execute deterministic rule-based sanitization (no external network dependencies)
  const result = sanitizeContent(content, strictMode);

  await Actor.pushData(result);
  console.log('[canaryguard-apify] Sanitization output successfully pushed to dataset');
  await Actor.exit();
} catch (err: any) {
  console.error(`[canaryguard-apify] Error: ${err.message}`);
  await Actor.fail(`CanaryGuard Actor execution failed: ${err.message}`);
}
