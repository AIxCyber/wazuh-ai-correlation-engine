
from typing import Any

from src.ai.providers.base import AIProvider
from src.ai.providers.ollama_provider import OllamaProvider
from src.ai.providers.openai_provider import OpenAIProvider
from src.ai.providers.rule_based import RuleBasedProvider
from src.core.config import get_config
from src.core.logging import get_logger
from src.normalization.schema import AIAnalysisResponse

logger = get_logger(__name__)


class AIAnalysisEngine:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.providers: dict[str, AIProvider] = {
            "rule": RuleBasedProvider(),
            "openai": OpenAIProvider(),
            "local": OllamaProvider(),
        }

    def analyze(self, incident: dict[str, Any], provider: str | None = None) -> AIAnalysisResponse | None:
        provider_name = provider or self.cfg.ai_mode
        ai_provider = self.providers.get(provider_name)

        if ai_provider is None:
            logger.error("unknown_ai_provider", extra={"provider": provider_name})
            ai_provider = self.providers["rule"]

        logger.info(
            "ai_analysis_started",
            extra={"provider": ai_provider.name(), "incident_title": incident.get("title")},
        )

        result = ai_provider.analyze(incident)
        if result is None and provider_name != "rule":
            logger.warning(
                "ai_provider_fallback",
                extra={"failed_provider": provider_name},
            )
            result = self.providers["rule"].analyze(incident)

        if result:
            incident["root_cause"] = result.root_cause
            incident["ai_confidence"] = result.confidence
            incident["ai_summary"] = result.summary
            incident["recommended_actions"] = result.recommended_actions
            incident["ai_provider"] = provider_name

        return result

    def summarize(self, alerts: list[dict[str, Any]]) -> str:
        provider_name = self.cfg.ai_mode
        ai_provider = self.providers.get(provider_name, self.providers["rule"])
        return ai_provider.summarize_alerts(alerts)
