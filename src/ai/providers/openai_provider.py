
from typing import Any

from openai import OpenAI

from src.ai.providers.base import AIProvider
from src.core.config import get_config
from src.core.logging import get_logger
from src.core.metrics import ai_processing_duration
from src.normalization.schema import AIAnalysisResponse

logger = get_logger(__name__)


class OpenAIProvider(AIProvider):
    def __init__(self) -> None:
        self.cfg = get_config()
        self._client: OpenAI | None = None

    @property
    def client(self) -> OpenAI:
        if self._client is None:
            self._client = OpenAI(api_key=self.cfg.openai_api_key)
        return self._client

    def name(self) -> str:
        return "openai"

    def analyze(self, incident: dict[str, Any]) -> AIAnalysisResponse | None:
        if not self.cfg.openai_api_key:
            logger.warning("openai_api_key_not_configured")
            return None

        prompt = self._build_analysis_prompt(incident)
        import time
        start = time.time()

        try:
            resp = self.client.chat.completions.create(
                model=self.cfg.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a SOC analyst AI assistant. Analyze the security incident "
                            "and provide root cause, confidence, summary, and recommended actions. "
                            "Respond in JSON format."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=1000,
                response_format={"type": "json_object"},
            )

            ai_processing_duration.labels(provider="openai").observe(time.time() - start)
            content = resp.choices[0].message.content

            import json
            data = json.loads(content)
            return AIAnalysisResponse(
                root_cause=data.get("root_cause", "Analysis unavailable"),
                confidence=data.get("confidence", 0.7),
                summary=data.get("summary", ""),
                recommended_actions=data.get("recommended_actions", []),
                mitre_techniques=data.get("mitre_techniques", []),
                severity=data.get("severity", "medium"),
            )

        except Exception as e:
            ai_processing_duration.labels(provider="openai").observe(time.time() - start)
            logger.error("openai_analysis_failed", extra={"error": str(e)})
            return None

    def summarize_alerts(self, alerts: list[dict[str, Any]]) -> str:
        if not self.cfg.openai_api_key:
            return "OpenAI not configured."

        prompt = "Summarize the following security alerts concisely:\n"
        for a in alerts:
            prompt += f"- [{a.get('timestamp', 'N/A')}] {a.get('event_type', 'unknown')} on {a.get('host', 'unknown')} - {a.get('rule_description', '')}\n"

        try:
            resp = self.client.chat.completions.create(
                model=self.cfg.openai_model,
                messages=[
                    {"role": "system", "content": "You are a SOC analyst. Summarize alerts briefly."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=300,
            )
            return resp.choices[0].message.content or "Summary unavailable."
        except Exception as e:
            logger.error("openai_summarize_failed", extra={"error": str(e)})
            return "Summary unavailable due to API error."

    def _build_analysis_prompt(self, incident: dict[str, Any]) -> str:
        return (
            f"Analyze this security incident:\n"
            f"- Title: {incident.get('title', 'N/A')}\n"
            f"- Severity: {incident.get('severity', 'N/A')}\n"
            f"- Risk Score: {incident.get('risk_score', 'N/A')}\n"
            f"- Alert Count: {incident.get('alert_count', 0)}\n"
            f"- Event Types: {', '.join(incident.get('event_types', []))}\n"
            f"- Affected Hosts: {', '.join(incident.get('affected_hosts', []))}\n"
            f"- Source IPs: {', '.join(incident.get('source_ips', []))}\n"
            f"- Affected Users: {', '.join(incident.get('affected_users', []))}\n"
            f"- MITRE Technique: {incident.get('mitre_technique', 'N/A')}\n"
            f"- Tactic: {incident.get('mitre_tactic', 'N/A')}\n\n"
            f"Provide: root_cause, confidence (0-1), summary, "
            f"recommended_actions (list), mitre_techniques (list), severity (low/medium/high/critical)."
        )
