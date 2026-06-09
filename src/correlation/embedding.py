from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
from fastembed import TextEmbedding

from src.core.config import get_config
from src.core.logging import get_logger

logger = get_logger(__name__)

_embedder: EmbeddingService | None = None


DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class EmbeddingService:
    def __init__(self, model_name: str | None = None) -> None:
        self.cfg = get_config()
        self.model_name = model_name or getattr(self.cfg, "embedding_model", DEFAULT_MODEL)
        self.dim = getattr(self.cfg, "embedding_dim", 384)
        self._model: TextEmbedding | None = None

    def _get_model(self) -> TextEmbedding | None:
        if self._model is None:
            try:
                self._model = TextEmbedding(model_name=self.model_name)
                logger.info("embedding_model_loaded", extra={"model": self.model_name, "dim": self.dim})
            except Exception as e:
                logger.error("embedding_model_load_failed", extra={"error": str(e)})
        return self._model

    def encode(self, text: str) -> np.ndarray:
        model = self._get_model()
        if model is not None:
            embeddings = list(model.embed([text]))
            if embeddings:
                vec = embeddings[0]
                if isinstance(vec, list):
                    vec = np.array(vec, dtype=np.float32)
                norm = np.linalg.norm(vec)
                if norm > 0:
                    vec = vec / norm
                return vec
        return self._fallback_encode(text)

    def encode_alert(self, alert: Any) -> np.ndarray:
        text = self._alert_to_text(alert)
        return self.encode(text)

    def _alert_to_text(self, alert: Any) -> str:
        if isinstance(alert, dict):
            desc = alert.get("rule_description", "")
            etype = alert.get("event_type", "")
            src = alert.get("source_ip", "")
            dst = alert.get("destination_ip", "")
            host = alert.get("host", "")
            user = alert.get("user", "")
        else:
            desc = getattr(alert, "rule_description", "")
            etype = getattr(alert, "event_type", "")
            src = getattr(alert, "source_ip", "")
            dst = getattr(alert, "destination_ip", "")
            host = getattr(alert, "host", "")
            user = getattr(alert, "user", "")

        parts = [desc, etype, src, dst, host, user]
        text = " | ".join(p for p in parts if p and p != "unknown")
        return text if text else "unknown_alert"

    def _fallback_encode(self, text: str) -> np.ndarray:
        h = hashlib.sha256(text.encode()).hexdigest()
        seed = int(h[:16], 16)
        rng = np.random.default_rng(seed)
        arr = rng.uniform(-1.0, 1.0, self.dim).astype(np.float32)
        norm = np.linalg.norm(arr)
        if norm > 0:
            arr = arr / norm
        return arr


def get_embedder() -> EmbeddingService:
    global _embedder
    if _embedder is None:
        _embedder = EmbeddingService()
    return _embedder
