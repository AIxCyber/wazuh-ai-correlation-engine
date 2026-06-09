
from typing import Any

import httpx

from src.ai.providers.base import AIProvider
from src.core.config import get_config
from src.core.logging import get_logger
from src.core.metrics import ai_processing_duration
from src.normalization.schema import AIAnalysisResponse

logger = get_logger(__name__)


class OllamaProvider(AIProvider):
    def __init__(self) -> None:
        self.cfg = get_config()

    def name(self) -> str:
        return "ollama"

    def analyze(self, incident: dict[str, Any]) -> AIAnalysisResponse | None:
        prompt = self._build_prompt(incident)
        import time
        start = time.time()

        try:
            resp = httpx.post(
                f"{self.cfg.ollama_url}/api/generate",
                json={
                    "model": self.cfg.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.3, "max_tokens": 1000},
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            response_text = data.get("response", "{}")

            ai_processing_duration.labels(provider="ollama").observe(time.time() - start)

            import json
            result = json.loads(response_text)
            return AIAnalysisResponse(
                root_cause=result.get("root_cause", "Local LLM analysis unavailable"),
                confidence=result.get("confidence", 0.7),
                summary=result.get("summary", ""),
                recommended_actions=result.get("recommended_actions", []),
                mitre_techniques=result.get("mitre_techniques", []),
                severity=result.get("severity", "medium"),
            )

        except Exception as e:
            ai_processing_duration.labels(provider="ollama").observe(time.time() - start)
            logger.error("ollama_analysis_failed", extra={"error": str(e)})
            return None

    def summarize_alerts(self, alerts: list[dict[str, Any]]) -> str:
        prompt = "Summarize these security alerts:\n"
        for a in alerts:
            prompt += f"- {a.get('event_type', 'unknown')} on {a.get('host', 'unknown')}\n"

        try:
            resp = httpx.post(
                f"{self.cfg.ollama_url}/api/generate",
                json={
                    "model": self.cfg.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("response", "Summary unavailable.")
        except Exception as e:
            logger.error("ollama_summarize_failed", extra={"error": str(e)})
            return "Summary unavailable."

    def _build_prompt(self, incident: dict[str, Any]) -> str:
        return (
            f"Analyze this security incident as a SOC analyst. Return ONLY valid JSON with these fields: "
            f"root_cause, confidence (0-1), summary, recommended_actions (list), "
            f"mitre_techniques (list), severity (low/medium/high/critical).\n\n"
            f"Incident: {incident.get('title', 'N/A')}\n"
            f"Alerts: {incident.get('alert_count', 0)}\n"
            f"Type: {', '.join(incident.get('event_types', []))}\n"
            f"Hosts: {', '.join(incident.get('affected_hosts', []))}\n"
            f"Source IPs: {', '.join(incident.get('source_ips', []))}"
        )
