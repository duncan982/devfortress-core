"""Shared bounded LRU map. Mirrors the Node SDK's ``BoundedMap``
(internal-closed-loop-engine.ts) used by several agent-security modules
for process-local, size-capped state.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Generic, Iterator, Optional, Tuple, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class BoundedMap(Generic[K, V]):
    """Insertion/access-ordered map capped at ``max_size``; evicts the oldest entry."""

    def __init__(self, max_size: int):
        self._max_size = max_size
        self._map: "OrderedDict[K, V]" = OrderedDict()

    def get(self, key: K) -> Optional[V]:
        if key not in self._map:
            return None
        value = self._map.pop(key)
        self._map[key] = value  # move to end (most recently used)
        return value

    def set(self, key: K, value: V) -> None:
        if key in self._map:
            del self._map[key]
        elif len(self._map) >= self._max_size:
            self._map.popitem(last=False)  # evict oldest
        self._map[key] = value

    def has(self, key: K) -> bool:
        return key in self._map

    def delete(self, key: K) -> bool:
        if key in self._map:
            del self._map[key]
            return True
        return False

    def entries(self) -> Iterator[Tuple[K, V]]:
        return iter(self._map.items())

    def clear(self) -> None:
        self._map.clear()

    @property
    def size(self) -> int:
        return len(self._map)
