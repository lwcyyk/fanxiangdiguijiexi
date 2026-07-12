from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from uuid import uuid4


@dataclass
class RequestJournal:
    max_entries: int = 10_000
    entries: OrderedDict[str, dict] = field(default_factory=OrderedDict)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def create(self, query: bytes) -> str:
        request_id = str(uuid4())
        with self._lock:
            self.entries[request_id] = {"query_size": len(query), "events": []}
            while len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)
        return request_id

    def add(self, request_id: str, event: dict) -> None:
        with self._lock:
            self.entries.setdefault(request_id, {"events": []})["events"].append(event)

    def get(self, request_id: str) -> dict | None:
        with self._lock:
            return self.entries.get(request_id)
