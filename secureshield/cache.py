"""Small cache abstraction with in-memory fallback and Redis metadata."""

from __future__ import annotations

import time
from typing import Any

from secureshield.config import REDIS_URL


class CacheStore:
    """Simple process-local cache with optional Redis metadata reporting."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[float | None, Any]] = {}
        self.backend = "redis" if REDIS_URL else "memory"

    def set(self, key: str, value: Any, *, ttl_seconds: int = 300) -> None:
        expires_at = time.time() + ttl_seconds if ttl_seconds > 0 else None
        self._items[key] = (expires_at, value)

    def get(self, key: str) -> Any | None:
        item = self._items.get(key)
        if not item:
            return None
        expires_at, value = item
        if expires_at is not None and expires_at < time.time():
            self._items.pop(key, None)
            return None
        return value

    def info(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "configured_url": bool(REDIS_URL),
            "items": len(self._items),
        }


cache_store = CacheStore()
