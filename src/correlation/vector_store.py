
import time
from typing import Any

import numpy as np

from src.core.logging import get_logger

logger = get_logger(__name__)


class VectorStore:
    def __init__(self) -> None:
        self._vectors: dict[str, np.ndarray] = {}
        self._timestamps: dict[str, float] = {}

    def add(self, alert_id: str, embedding: np.ndarray) -> None:
        self._vectors[alert_id] = embedding
        self._timestamps[alert_id] = time.time()

    def remove(self, alert_id: str) -> None:
        self._vectors.pop(alert_id, None)
        self._timestamps.pop(alert_id, None)

    def get(self, alert_id: str) -> np.ndarray | None:
        return self._vectors.get(alert_id)

    def search(
        self, embedding: np.ndarray, threshold: float = 0.85, k: int = 10
    ) -> list[tuple[str, float]]:
        if not self._vectors:
            return []

        ids = list(self._vectors.keys())
        stored = np.array(list(self._vectors.values()))

        similarities = stored @ embedding
        above_mask = similarities >= threshold
        above_indices = np.where(above_mask)[0]

        if len(above_indices) == 0:
            return []

        candidates = sorted(
            [(ids[i], float(similarities[i])) for i in above_indices],
            key=lambda x: x[1],
            reverse=True,
        )
        return candidates[:k]

    def remove_expired(self, window_seconds: int = 300) -> int:
        now = time.time()
        expired = [aid for aid, ts in self._timestamps.items() if now - ts > window_seconds]
        for aid in expired:
            self.remove(aid)
        return len(expired)

    def clear(self) -> None:
        self._vectors.clear()
        self._timestamps.clear()

    @property
    def size(self) -> int:
        return len(self._vectors)
