from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo


DEFAULT_TIMEZONE = "Asia/Shanghai"


def timezone_for(name: str | None = None) -> ZoneInfo:
    try:
        return ZoneInfo(name or DEFAULT_TIMEZONE)
    except Exception:
        return ZoneInfo(DEFAULT_TIMEZONE)


def now_iso(timezone_name: str | None = None) -> str:
    return datetime.now(timezone_for(timezone_name)).replace(microsecond=0).isoformat()


def to_timezone_iso(value: str | None, timezone_name: str | None = None) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone_for(timezone_name))
    return parsed.astimezone(timezone_for(timezone_name)).replace(microsecond=0).isoformat()
