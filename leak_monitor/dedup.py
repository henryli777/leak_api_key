from __future__ import annotations

from typing import Any

from .storage import finding_sort_key, severity_rank


EVIDENCE_RANK = {
    "unknown": 0,
    "base_url_only": 1,
    "base_url_with_model": 2,
    "credential_only": 3,
    "candidate": 4,
    "provider_config_reference": 5,
    "same_response": 6,
    "strong": 5,
    "strong_provider_config": 7,
}

BASE_URL_SOURCE_RANK = {"historical_fallback": 1, "same_hit": 2, "provider_config": 3}


def dedupe_findings_for_export(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in findings:
        key = export_group_key(item)
        if key not in groups:
            groups[key] = _new_group(item)
            order.append(key)
            continue
        _merge_group(groups[key], item)

    return sorted((groups[key] for key in order), key=finding_sort_key, reverse=True)


def export_group_key(item: dict[str, Any]) -> str:
    item_type = str(item.get("type") or "")
    key_hash = str(item.get("key_sha256") or item.get("value_sha256") or "")
    if item_type != "base_url" and key_hash:
        return f"key:{key_hash}"

    base_hashes = item.get("base_url_sha256") or []
    if item_type == "base_url":
        base_hash = str(item.get("value_sha256") or (base_hashes[0] if base_hashes else ""))
        if base_hash:
            return f"base_url:{base_hash}"

    return f"id:{item.get('id') or id(item)}"


def _new_group(item: dict[str, Any]) -> dict[str, Any]:
    group = dict(item)
    group["deduped_finding_ids"] = _dedup_values([str(item.get("id") or "")])
    group["deduped_finding_count"] = 1
    group["sources"] = _merge_sources([], item.get("sources") or [], limit=25)
    group["base_url_sources"] = _merge_sources([], item.get("base_url_sources") or [], limit=25)
    group["base_urls_redacted"] = _dedup_values(_item_redacted_base_urls(item), limit=100)
    group["base_url_sha256"] = _dedup_values(_item_base_url_hashes(item), limit=200)
    group["raw_base_urls"] = _dedup_values(_item_raw_base_urls(item), limit=100)
    if group.get("raw_base_urls"):
        group["raw_base_url"] = group["raw_base_urls"][0]
    return group


def _merge_group(group: dict[str, Any], item: dict[str, Any]) -> None:
    group["deduped_finding_ids"] = _dedup_values(
        [*(group.get("deduped_finding_ids") or []), str(item.get("id") or "")],
        limit=200,
    )
    group["deduped_finding_count"] = int(group.get("deduped_finding_count") or 1) + 1
    group["last_seen_at"] = max(str(group.get("last_seen_at") or ""), str(item.get("last_seen_at") or ""))
    first_seen_values = [str(v) for v in (group.get("first_seen_at"), item.get("first_seen_at")) if v]
    if first_seen_values:
        group["first_seen_at"] = min(first_seen_values)
    group["seen_count"] = int(group.get("seen_count") or 0) + int(item.get("seen_count") or 1)
    group["severity"] = _max_severity(group.get("severity"), item.get("severity"))
    group["models"] = _dedup_values([*(group.get("models") or []), *(item.get("models") or [])], limit=100)
    group["base_urls_redacted"] = _dedup_values(
        [*(group.get("base_urls_redacted") or []), *_item_redacted_base_urls(item)],
        limit=100,
    )
    group["base_url_sha256"] = _dedup_values(
        [*(group.get("base_url_sha256") or []), *_item_base_url_hashes(item)],
        limit=200,
    )
    group["raw_base_urls"] = _dedup_values([*(group.get("raw_base_urls") or []), *_item_raw_base_urls(item)], limit=100)
    if group.get("raw_base_urls"):
        group["raw_base_url"] = group["raw_base_urls"][0]
    group["sources"] = _merge_sources(group.get("sources") or [], item.get("sources") or [], limit=25)
    group["base_url_sources"] = _merge_sources(
        group.get("base_url_sources") or [],
        item.get("base_url_sources") or [],
        limit=25,
    )
    if _evidence_rank(item.get("public_evidence_level")) > _evidence_rank(group.get("public_evidence_level")):
        group["public_evidence_level"] = item.get("public_evidence_level")
        group["public_evidence_label"] = item.get("public_evidence_label")
    if _base_url_source_rank(item.get("base_url_source")) > _base_url_source_rank(group.get("base_url_source")):
        group["base_url_source"] = item.get("base_url_source")
        group["is_fallback_base_url"] = bool(item.get("is_fallback_base_url"))
    for field in ("key_redacted", "key_sha256", "raw_value"):
        if item.get(field) and not group.get(field):
            group[field] = item[field]


def _item_redacted_base_urls(item: dict[str, Any]) -> list[str]:
    values = [str(v).strip() for v in item.get("base_urls_redacted") or [] if str(v).strip()]
    if item.get("base_url_redacted"):
        values.insert(0, str(item["base_url_redacted"]).strip())
    if item.get("type") == "base_url" and item.get("value_redacted"):
        values.insert(0, str(item["value_redacted"]).strip())
    return _dedup_values(values, limit=100)


def _item_base_url_hashes(item: dict[str, Any]) -> list[str]:
    values = [str(v).strip() for v in item.get("base_url_sha256") or [] if str(v).strip()]
    if item.get("base_url_hash"):
        values.insert(0, str(item["base_url_hash"]).strip())
    if item.get("type") == "base_url" and item.get("value_sha256"):
        values.insert(0, str(item["value_sha256"]).strip())
    return _dedup_values(values, limit=200)


def _item_raw_base_urls(item: dict[str, Any]) -> list[str]:
    values = [str(v).strip() for v in item.get("raw_base_urls") or [] if str(v).strip()]
    if item.get("raw_base_url"):
        values.insert(0, str(item["raw_base_url"]).strip())
    if item.get("type") == "base_url" and item.get("raw_value"):
        values.insert(0, str(item["raw_value"]).strip())
    return _dedup_values(values, limit=100)


def _dedup_values(values: list[Any], limit: int = 100) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _merge_sources(left: list[dict[str, Any]], right: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
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


def _max_severity(left: str | None, right: str | None) -> str:
    return str(left or right or "low") if severity_rank(left) >= severity_rank(right) else str(right or left or "low")


def _evidence_rank(value: str | None) -> int:
    return EVIDENCE_RANK.get(str(value or "unknown"), 0)


def _base_url_source_rank(value: str | None) -> int:
    return BASE_URL_SOURCE_RANK.get(str(value or ""), 0)
