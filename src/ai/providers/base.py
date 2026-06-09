
from abc import ABC, abstractmethod
from typing import Any

from src.normalization.schema import AIAnalysisResponse


class AIProvider(ABC):
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def analyze(self, incident: dict[str, Any]) -> AIAnalysisResponse | None: ...

    @abstractmethod
    def summarize_alerts(self, alerts: list[dict[str, Any]]) -> str: ...
