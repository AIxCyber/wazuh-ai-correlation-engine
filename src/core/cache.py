
import time
from typing import Any


class CacheEntry:
    def __init__(self, data: Any, timestamp: float) -> None:
        self.data = data
        self.timestamp = timestamp


class TTLCache:
    def __init__(self, ttl: int = 3600) -> None:
        self._cache: dict[str, CacheEntry] = {}
        self.ttl = ttl

    def get(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is not None:
            if time.time() - entry.timestamp < self.ttl:
                return entry.data
            del self._cache[key]
        return None

    def set(self, key: str, data: Any) -> None:
        self._cache[key] = CacheEntry(data=data, timestamp=time.time())

    def delete(self, key: str) -> None:
        self._cache.pop(key, None)

    def clear(self) -> None:
        self._cache.clear()

    def clear_expired(self) -> int:
        now = time.time()
        expired = [k for k, v in self._cache.items() if now - v.timestamp >= self.ttl]
        for k in expired:
            del self._cache[k]
        return len(expired)

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_ratio(self) -> float:
        return getattr(self, "_hits", 0) / max(getattr(self, "_lookups", 1), 1)

    def get_with_metrics(self, key: str) -> Any | None:
        self._lookups = getattr(self, "_lookups", 0) + 1
        result = self.get(key)
        if result is not None:
            self._hits = getattr(self, "_hits", 0) + 1
        return result


_cache: TTLCache | None = None


def get_cache() -> TTLCache:
    global _cache
    if _cache is None:
        from src.core.config import get_config

        cfg = get_config()
        _cache = TTLCache(ttl=cfg.cache_ttl_seconds)
    return _cache
