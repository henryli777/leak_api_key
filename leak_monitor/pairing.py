from __future__ import annotations

from typing import Any

from .detectors import redact_url, sha256_text
from .timeutils import to_timezone_iso


FALLBACK_SOURCE = "historical_fallback"
SAME_HIT_SOURCE = "same_hit"
SUPPORTED_AI_KEY_PREFIXES = ("sk-", "gsk_", "AIza")


def prepare_findings(findings: list[dict[str, Any]], timezone_name: str) -> list[dict[str, Any]]:
    normalized = normalize_finding_timezones(findings, timezone_name)
    return pair_credential_findings(normalized)


def normalize_finding_timezones(findings: list[dict[str, Any]], timezone_name: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in findings:
        copied = dict(item)
        for field in ("first_seen_at", "last_seen_at"):
            if copied.get(field):
                copied[field] = to_timezone_iso(copied.get(field), timezone_name)
        sources = []
        for source in copied.get("sources") or []:
            source_copy = dict(source)
            if source_copy.get("fetched_at"):
                source_copy["fetched_at"] = to_timezone_iso(source_copy.get("fetched_at"), timezone_name)
            sources.append(source_copy)
        copied["sources"] = sources
        out.append(copied)
    return out


def pair_credential_findings(
    findings: list[dict[str, Any]],
    fallback_candidates: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    candidates = fallback_candidates or collect_base_url_candidates(findings)
    out: list[dict[str, Any]] = []
    for item in findings:
        item_type = str(item.get("type") or "")
        if item_type in {"credential", "credential_pair"} and not has_supported_ai_key(item):
            continue
        if item_type == "credential_pair":
            out.append(item)
            continue
        if item_type != "credential":
            out.append(item)
            continue

        own_candidates = collect_item_base_url_candidates(item)
        source = SAME_HIT_SOURCE
        use_candidates = own_candidates
        if not use_candidates:
            source = FALLBACK_SOURCE
            use_candidates = candidates

        if not use_candidates:
            out.append(item)
            continue

        for candidate in use_candidates:
            out.append(build_credential_pair(item, candidate, source))
    return annotate_public_evidence(_dedup_by_id(out))


def has_supported_ai_key(item: dict[str, Any]) -> bool:
    for field in ("raw_value", "key_redacted", "value_redacted"):
        value = str(item.get(field) or "").strip()
        if value.startswith(SUPPORTED_AI_KEY_PREFIXES):
            return True
    return False


def annotate_public_evidence(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in findings:
        copied = dict(item)
        copied.setdefault("live_validation_status", "not_live_tested")
        copied.setdefault("live_validation_reason", "public_leaked_key_not_used_without_authorization")
        copied["public_evidence_level"] = public_evidence_level(copied)
        copied["public_evidence_label"] = public_evidence_label(copied["public_evidence_level"])
        out.append(copied)
    return out


def public_evidence_level(item: dict[str, Any]) -> str:
    if item.get("type") == "credential_pair" and item.get("base_url_source") == SAME_HIT_SOURCE:
        return "strong"
    if item.get("type") == "credential_pair" and item.get("base_url_source") == FALLBACK_SOURCE:
        return "candidate"
    if item.get("type") == "credential":
        return "credential_only"
    if item.get("type") == "base_url" and item.get("models"):
        return "base_url_with_model"
    if item.get("type") == "base_url":
        return "base_url_only"
    return "unknown"


def public_evidence_label(level: str) -> str:
    return {
        "strong": "公开证据强：同一线索包含密钥和 base_url",
        "candidate": "候选证据：密钥使用历史 base_url 备选",
        "credential_only": "密钥证据：缺少 base_url",
        "base_url_with_model": "base_url 证据：同线索包含模型",
        "base_url_only": "base_url 证据",
    }.get(level, "公开证据")


def collect_base_url_candidates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in findings:
        candidates.extend(collect_item_base_url_candidates(item))
    return _dedup_candidates(candidates)


def collect_item_base_url_candidates(item: dict[str, Any]) -> list[dict[str, Any]]:
    raw_urls = [str(v).strip() for v in item.get("raw_base_urls") or [] if str(v).strip()]
    if item.get("raw_base_url"):
        raw_urls.insert(0, str(item["raw_base_url"]).strip())
    if item.get("type") == "base_url" and item.get("raw_value"):
        raw_urls.insert(0, str(item["raw_value"]).strip())

    redacted_urls = [str(v).strip() for v in item.get("base_urls_redacted") or [] if str(v).strip()]
    hashes = [str(v).strip() for v in item.get("base_url_sha256") or [] if str(v).strip()]
    if item.get("base_url_redacted"):
        redacted_urls.insert(0, str(item["base_url_redacted"]).strip())
    if item.get("base_url_hash"):
        hashes.insert(0, str(item["base_url_hash"]).strip())
    if item.get("type") == "base_url":
        if item.get("value_redacted"):
            redacted_urls.insert(0, str(item["value_redacted"]).strip())
        if item.get("value_sha256"):
            hashes.insert(0, str(item["value_sha256"]).strip())

    max_len = max(len(raw_urls), len(redacted_urls), len(hashes))
    candidates: list[dict[str, Any]] = []
    for idx in range(max_len):
        raw = raw_urls[idx] if idx < len(raw_urls) else ""
        redacted = redacted_urls[idx] if idx < len(redacted_urls) else (redact_url(raw) if raw else "")
        value_hash = hashes[idx] if idx < len(hashes) else (sha256_text(raw) if raw else "")
        if not raw and not redacted and not value_hash:
            continue
        candidates.append(
            {
                "raw": raw,
                "redacted": redacted,
                "sha256": value_hash,
                "sources": item.get("sources") or [],
            }
        )
    return _dedup_candidates(candidates)


def build_credential_pair(
    credential: dict[str, Any],
    base_url: dict[str, Any],
    base_url_source: str,
) -> dict[str, Any]:
    key_hash = str(credential.get("key_sha256") or credential.get("value_sha256") or "")
    key_redacted = str(credential.get("key_redacted") or credential.get("value_redacted") or "")
    url_hash = str(base_url.get("sha256") or "")
    url_redacted = str(base_url.get("redacted") or "")
    pair_id_key = url_hash or url_redacted or str(base_url.get("raw") or "")
    pair = dict(credential)
    pair.update(
        {
            "id": sha256_text(f"credential_pair:{credential.get('provider')}:{key_hash}:{pair_id_key}")[:20],
            "type": "credential_pair",
            "key_redacted": key_redacted,
            "key_sha256": key_hash,
            "base_url_redacted": url_redacted,
            "base_url_sha256": [url_hash] if url_hash else [],
            "base_urls_redacted": [url_redacted] if url_redacted else [],
            "base_url_source": base_url_source,
            "is_fallback_base_url": base_url_source == FALLBACK_SOURCE,
            "validation_candidate": bool(key_hash and (url_hash or base_url.get("raw") or url_redacted)),
            "has_raw_validation_material": bool(credential.get("raw_value") and base_url.get("raw")),
            "base_url_sources": base_url.get("sources") or [],
        }
    )
    raw_key = credential.get("raw_value")
    raw_url = base_url.get("raw")
    if raw_key:
        pair["raw_value"] = raw_key
    if raw_url:
        pair["raw_base_url"] = raw_url
        pair["raw_base_urls"] = [raw_url]
    else:
        pair.pop("raw_base_url", None)
        pair.pop("raw_base_urls", None)
    return pair


def _dedup_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.get("sha256") or candidate.get("raw") or candidate.get("redacted") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def _dedup_by_id(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in findings:
        item_id = str(item.get("id") or "")
        if item_id and item_id in seen:
            continue
        if item_id:
            seen.add(item_id)
        out.append(item)
    return out
