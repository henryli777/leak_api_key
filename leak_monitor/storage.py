from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def read_json(path: str | os.PathLike[str], default: Any) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path: str | os.PathLike[str], data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, p)


def merge_findings(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_id = {item.get("id"): item for item in existing if item.get("id")}
    new_items: list[dict[str, Any]] = []

    for item in incoming:
        item_id = item.get("id")
        if not item_id:
            continue
        if item_id not in by_id:
            by_id[item_id] = item
            new_items.append(item)
            continue

        current = by_id[item_id]
        current["last_seen_at"] = item.get("last_seen_at") or current.get("last_seen_at")
        current["seen_count"] = int(current.get("seen_count") or 0) + int(item.get("seen_count") or 1)
        current["severity"] = _max_severity(current.get("severity"), item.get("severity"))
        current["models"] = _merge_list(current.get("models", []), item.get("models", []), 25)
        current["base_urls_redacted"] = _merge_list(current.get("base_urls_redacted", []), item.get("base_urls_redacted", []), 25)
        current["base_url_sha256"] = _merge_list(current.get("base_url_sha256", []), item.get("base_url_sha256", []), 50)
        current["sources"] = _merge_sources(current.get("sources", []), item.get("sources", []))
        current["base_url_sources"] = _merge_sources(current.get("base_url_sources", []), item.get("base_url_sources", []))
        for field in ("key_redacted", "key_sha256", "base_url_redacted", "raw_value", "raw_base_url"):
            if item.get(field) and not current.get(field):
                current[field] = item[field]
        if item.get("raw_base_urls") and not current.get("raw_base_urls"):
            current["raw_base_urls"] = item["raw_base_urls"]
        current["validation_candidate"] = bool(current.get("validation_candidate") or item.get("validation_candidate"))
        current["has_raw_validation_material"] = bool(
            current.get("has_raw_validation_material") or item.get("has_raw_validation_material")
        )
        if _base_url_source_rank(item.get("base_url_source")) > _base_url_source_rank(current.get("base_url_source")):
            current["base_url_source"] = item.get("base_url_source")
            current["is_fallback_base_url"] = bool(item.get("is_fallback_base_url"))

    merged = sorted(by_id.values(), key=finding_sort_key, reverse=True)
    return merged, new_items


def finding_sort_key(item: dict[str, Any]) -> tuple[str, str, int]:
    return (
        str(item.get("first_seen_at") or item.get("last_seen_at") or ""),
        str(item.get("last_seen_at") or ""),
        severity_rank(item.get("severity")),
    )


def severity_rank(value: str | None) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value or "").lower(), 0)


def _max_severity(left: str | None, right: str | None) -> str:
    return left if severity_rank(left) >= severity_rank(right) else str(right or left or "low")


def _merge_list(left: list[Any], right: list[Any], limit: int) -> list[Any]:
    return list(dict.fromkeys([*(left or []), *(right or [])]))[:limit]


def _merge_sources(left: list[dict[str, Any]], right: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    seen = set()
    merged: list[dict[str, Any]] = []
    for item in [*(right or []), *(left or [])]:
        key = (item.get("source"), item.get("url"), item.get("query"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= limit:
            break
    return merged


def _base_url_source_rank(value: str | None) -> int:
    return {"historical_fallback": 1, "same_hit": 2}.get(str(value or ""), 0)
