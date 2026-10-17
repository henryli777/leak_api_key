from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SearchHit:
    source: str
    query: str
    url: str
    title: str = ""
    snippet: str = ""
    content: str = ""
    fetched_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SourceStats:
    source: str
    queries: int = 0
    hits: int = 0
    errors: int = 0
    skipped: bool = False
    message: str = ""
    planned_queries: int | None = None
    completed_queries: int = 0
    failed_queries: int = 0
    deferred_queries: int = 0
    successful_searches: int = 0
    requests: int = 0
    failed_requests: int = 0
    retries: int = 0
    retry_wait_seconds: float = 0.0

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        if self.planned_queries is None:
            return "unknown"
        if self.planned_queries == 0:
            return "no_queries"
        if self.completed_queries == self.planned_queries and self.failed_requests == 0:
            return "complete"
        if self.successful_searches:
            return "partial"
        return "failed"
