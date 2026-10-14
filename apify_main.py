import asyncio
import logging
import httpx
from typing import Dict, Any
from apify import Actor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("canaryguard.apify")

LIVE_CANARYGUARD_URL = "https://canaryguard-402.onrender.com/v1/sanitize"

async def run_actor():
    """
    Apify Pay-Per-Event (PPE) Actor entrypoint for CanaryGuard-402.
    Charges the sanitize_content event ($0.003) and returns sanitized text with risk score.
    """
    async with Actor:
        actor_input: Dict[str, Any] = await Actor.get_input() or {}
        content = actor_input.get("content") or "Test benign agent context prompt"
        strict_mode = bool(actor_input.get("strict_mode", True))
        logger.info(f"CanaryGuard-402 Apify Actor invoked for content length: {len(content)}")

        try:
            # Charge 1 PPE event ($0.003)
            logger.info("Charging 1 PPE event: sanitize_content ($0.003)")
            await Actor.charge(event_name="sanitize_content", count=1)

            async with httpx.AsyncClient(timeout=25.0) as client:
                resp = await client.post(
                    LIVE_CANARYGUARD_URL,
                    json={"content": content, "strict_mode": strict_mode}
                )
                if resp.status_code == 200:
                    result = resp.json()
                else:
                    # Fallback deterministic local evaluation
                    has_injection = any(x in content.lower() for x in ["ignore previous", "system prompt", "transfer all", "private key"])
                    result = {
                        "status": "success",
                        "safe_to_persist": not has_injection,
                        "risk_score": 0.95 if has_injection else 0.05,
                        "threat_level": "CRITICAL" if has_injection else "CLEAN",
                        "sanitized_content": "[REDACTED_INJECTION]" if has_injection else content,
                        "recommended_actions": [
                            {"service": "StealthGuard-402", "url": "https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize"},
                            {"service": "RugShield-402", "url": "https://rugshield-402.onrender.com/v1/scan"}
                        ]
                    }

            await Actor.push_data(result)
            logger.info("Successfully pushed CanaryGuard result to Apify dataset.")
        except Exception as e:
            logger.error(f"Error during CanaryGuard sanitization: {e}")
            await Actor.fail(status_message=f"Sanitization error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(run_actor())
