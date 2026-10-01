"""
A tiny cache interface for the intel lookups.

Anything with these two methods works (it is duck-typed, not an ABC check):

    get(key: str) -> value | None       # None means "miss"
    set(key: str, value, ttl_seconds: int) -> None

`MemoryCache` is the default for development and tests. The site can pass a
SQLite-backed object with the same two methods; values stored here are plain
JSON-able dicts, so they serialize cleanly.

Callers in this package only cache *answers* ("listed", "clean", "ok"). A
"unknown" (timeout, API error) or "disabled" result is never cached, so a
transient outage doesn't get remembered for a day.
"""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable, Optional


class Cache:
    """Interface: get(key) -> value or None; set(key, value, ttl_seconds)."""

    def get(self, key: str) -> Optional[Any]:  # pragma: no cover - interface
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:  # pragma: no cover
        raise NotImplementedError


class MemoryCache(Cache):
    """In-process dict cache with per-key expiry. Thread-safe; clock injectable for tests."""

    def __init__(self, clock: Callable[[], float] = time.time, max_items: int = 5000):
        self._clock = clock
        self._max = max_items
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires, value = item
            if expires <= self._clock():
                self._data.pop(key, None)
                return None
            return copy.deepcopy(value)

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                # Crude eviction: drop the entry closest to expiry.
                oldest = min(self._data, key=lambda k: self._data[k][0])
                self._data.pop(oldest, None)
            self._data[key] = (self._clock() + max(0, int(ttl_seconds)), copy.deepcopy(value))

    def __len__(self) -> int:
        return len(self._data)


class NullCache(Cache):
    """Never stores anything. Used when a caller passes cache=None."""

    def get(self, key: str) -> Optional[Any]:
        return None

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        return None


DAY = 86400
NO_CACHE_STATUSES = frozenset({"unknown", "disabled"})


def cached(cache: Optional[Cache], key: str, ttl_seconds: int, compute: Callable[[], dict]) -> dict:
    """Return cache[key] if present, else compute(), storing it unless it's unknown/disabled."""
    cache = cache if cache is not None else NullCache()
    try:
        hit = cache.get(key)
    except Exception:
        hit = None
    if isinstance(hit, dict):
        out = dict(hit)
        out["cached"] = True
        return out
    result = compute()
    if isinstance(result, dict) and result.get("status") not in NO_CACHE_STATUSES:
        try:
            cache.set(key, result, ttl_seconds)
        except Exception:
            pass  # a broken cache must never break a lookup
    return result
