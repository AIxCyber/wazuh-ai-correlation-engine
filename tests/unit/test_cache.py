import time

from src.core.cache import TTLCache


def test_cache_set_and_get():
    cache = TTLCache(ttl=60)
    cache.set("key1", "value1")
    assert cache.get("key1") == "value1"


def test_cache_miss():
    cache = TTLCache(ttl=60)
    assert cache.get("nonexistent") is None


def test_cache_expiry():
    cache = TTLCache(ttl=1)  # 1 second TTL
    cache.set("key1", "value1")
    time.sleep(1.1)
    assert cache.get("key1") is None


def test_cache_delete():
    cache = TTLCache(ttl=60)
    cache.set("key1", "value1")
    cache.delete("key1")
    assert cache.get("key1") is None


def test_cache_clear():
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.clear()
    assert cache.size == 0


def test_cache_clear_expired():
    cache = TTLCache(ttl=0)  # Immediate expiry
    cache.set("a", 1)
    time.sleep(0.1)
    cleared = cache.clear_expired()
    assert cleared == 1


def test_cache_size():
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.size == 2


def test_cache_get_with_metrics():
    cache = TTLCache(ttl=60)
    cache.set("k", "v")
    result = cache.get_with_metrics("k")
    assert result == "v"


def test_db_cache_instance():
    from src.core.cache import get_cache
    cache = get_cache()
    assert cache is not None
    assert cache.ttl > 0
