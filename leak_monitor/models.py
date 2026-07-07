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
