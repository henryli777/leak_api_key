from __future__ import annotations

import json
import os
import hashlib
import re
from pathlib import Path
from typing import Any

from .detectors import mask_sensitive_text
from .safety import RAW_SECRET_RE, sanitize_source_url


HISTORY_SHARD_BYTES = 4 * 1024 * 1024
HISTORY_FIELDS = frozenset("""id type provider provider_name endpoint_path severity value_kind value_redacted value_sha256
key_redacted key_sha256 base_url_redacted base_url_hash base_url_source is_fallback_base_url
public_evidence_level public_evidence_label first_seen_at last_seen_at seen_count
validation_candidate live_validation_status live_validation_reason
""".split())


def _safe_text(value: str, limit: int = 2048) -> str:
    text = RAW_SECRET_RE.sub("[redacted]", mask_sensitive_text(value))
    text = re.sub(r"https?://[^\s\"'<>]+", lambda match: sanitize_source_url(match.group()), text, flags=re.I)
    return text[:limit]


def redact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep redacted evidence and stable IDs; raw/unknown fields never enter Git or public exports."""
    result = []
    for item in findings:
        record = {key: _safe_text(value) if isinstance(value, str) else value
                  for key, value in item.items() if key in HISTORY_FIELDS and isinstance(value, (str, int, bool))}
        for field, limit in (("models", 100), ("base_urls_redacted", 100), ("base_url_sha256", 200)):
            if field in item:
                record[field] = [_safe_text(str(value)) for value in (item.get(field) or [])[:limit]]
        for field in ("sources", "base_url_sources"):
            if field in item:
                record[field] = [
                    {key: _safe_text(str(value), 360 if key == "excerpt" else 2048)
                     for key, value in source.items()
                     if key in {"source", "url", "title", "excerpt", "query", "fetched_at"}}
                    for source in (item.get(field) or [])[:25]
                ]
        record["has_raw_validation_material"] = False
        result.append(record)
    return result


def read_history(data_dir: str | Path) -> list[dict[str, Any]]:
    root = Path(data_dir)
    manifest = root / "history" / "index.json"
    # Strict parsing prevents a damaged shard from silently erasing dedup state.
    if manifest.exists():
        index = json.loads(manifest.read_text(encoding="utf-8"))
        if index.get("version") != 1 or not isinstance(index.get("shards"), list):
            raise ValueError("unsupported history manifest")
        result = []
        for name in index["shards"]:
            if not re.fullmatch(r"findings-[a-f0-9]{64}\.json", name):
                raise ValueError("invalid history shard name")
            payload = (manifest.parent / name).read_bytes()
            if hashlib.sha256(payload).hexdigest() != name[9:-5]:
                raise ValueError("history shard checksum mismatch")
            result.extend(json.loads(payload))
        return result
    legacy = root / "findings.json"
    if legacy.exists():
        records = json.loads(legacy.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("legacy history must be a list")
        return records
    return []


def write_history(data_dir: str | Path, findings: list[dict[str, Any]], *, max_shard_bytes: int = HISTORY_SHARD_BYTES) -> None:
    root = Path(data_dir)
    directory = root / "history"
    directory.mkdir(parents=True, exist_ok=True)
    shards = []
    rows: list[bytes] = []
    size = 3

    def flush() -> None:
        if not rows:
            return
        payload = b"[" + b",".join(rows) + b"]\n"
        name = f"findings-{hashlib.sha256(payload).hexdigest()}.json"
        destination = directory / name
        if not destination.exists():
            temporary = destination.with_suffix(".tmp")
            temporary.write_bytes(payload)
            os.replace(temporary, destination)
        shards.append(name)

    for item in sorted(redact_findings(findings), key=lambda row: str(row.get("id") or "")):
        row = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(row) + 3 > max_shard_bytes:
            raise ValueError("single history record exceeds shard size limit")
        if size + len(row) + bool(rows) > max_shard_bytes:
            flush()
            rows, size = [], 3
        size += len(row) + bool(rows)
        rows.append(row)
    flush()
    # Content-addressed shards become authoritative only after the atomic manifest switch.
    write_json(directory / "index.json", {"version": 1, "shards": shards})
    for path in directory.glob("findings-*.json"):
        if path.name not in shards:
            path.unlink()
    (root / "findings.json").unlink(missing_ok=True)


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
    return {"historical_fallback": 1, "same_hit": 2, "provider_config": 3}.get(str(value or ""), 0)
