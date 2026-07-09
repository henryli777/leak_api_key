from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .dedup import dedupe_findings_for_export
from .safety import sanitize_source_url


CSV_FIELDS = [
    "id",
    "type",
    "provider",
    "severity",
    "key_redacted",
    "key_sha256",
    "base_url_redacted",
    "base_url_sha256",
    "base_url_source",
    "public_evidence_level",
    "public_evidence_label",
    "models",
    "first_seen_at",
    "last_seen_at",
    "seen_count",
    "deduped_finding_count",
    "source",
    "source_url",
    "source_title",
    "query",
]

PROVIDER_PAIR_FIELDS = [
    "id",
    "type",
    "provider",
    "provider_name",
    "endpoint_path",
    "severity",
    "value_kind",
    "key_redacted",
    "key_sha256",
    "base_url_redacted",
    "base_url_sha256",
    "base_url_source",
    "public_evidence_level",
    "public_evidence_label",
    "models",
    "first_seen_at",
    "last_seen_at",
    "seen_count",
    "source",
    "source_url",
    "source_title",
    "query",
]


def emit_findings_csv(output_dir: str | Path, findings: list[dict[str, Any]]) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "findings.csv"
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(build_csv_rows(findings))
    pair_path = out / "provider_pairs.csv"
    with open(pair_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=PROVIDER_PAIR_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(build_provider_pair_rows(findings))


def build_csv_rows(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [build_csv_row(item) for item in dedupe_findings_for_export(findings)]


def build_csv_row(item: dict[str, Any]) -> dict[str, str]:
    source = (item.get("sources") or [{}])[0]
    row = {
        "id": item.get("id"),
        "type": item.get("type"),
        "provider": item.get("provider"),
        "severity": item.get("severity"),
        "key_redacted": item.get("key_redacted") or (item.get("value_redacted") if item.get("type") != "base_url" else ""),
        "key_sha256": item.get("key_sha256") or (item.get("value_sha256") if item.get("type") != "base_url" else ""),
        "base_url_redacted": "\n".join(item.get("base_urls_redacted") or []) or item.get("base_url_redacted") or (item.get("value_redacted") if item.get("type") == "base_url" else ""),
        "base_url_sha256": ", ".join(item.get("base_url_sha256") or []) or (item.get("value_sha256") if item.get("type") == "base_url" else ""),
        "base_url_source": item.get("base_url_source"),
        "public_evidence_level": item.get("public_evidence_level"),
        "public_evidence_label": item.get("public_evidence_label"),
        "models": ", ".join(item.get("models") or []),
        "first_seen_at": item.get("first_seen_at"),
        "last_seen_at": item.get("last_seen_at"),
        "seen_count": item.get("seen_count"),
        "deduped_finding_count": item.get("deduped_finding_count") or 1,
        "source": source.get("source"),
        "source_url": sanitize_source_url(source.get("url") or ""),
        "source_title": source.get("title"),
        "query": source.get("query"),
    }
    return {key: csv_safe(value) for key, value in row.items()}


def build_provider_pair_rows(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in findings:
        if item.get("type") not in {"provider_config", "credential_pair"}:
            continue
        source = (item.get("sources") or [{}])[0]
        source_url = sanitize_source_url(source.get("url") or "")
        base_hashes = [str(v).strip() for v in item.get("base_url_sha256") or [] if str(v).strip()]
        if not base_hashes and item.get("base_url_hash"):
            base_hashes = [str(item["base_url_hash"])]
        key_hash = str(item.get("key_sha256") or item.get("value_sha256") or "")
        provider_name = str(item.get("provider_name") or item.get("provider") or "")
        for base_hash in base_hashes or [""]:
            dedupe_key = (key_hash, base_hash, source_url, provider_name)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            rows.append(build_provider_pair_row(item, source, source_url, base_hash))
    return rows


def build_provider_pair_row(
    item: dict[str, Any],
    source: dict[str, Any],
    source_url: str,
    base_hash: str,
) -> dict[str, str]:
    row = {
        "id": item.get("id"),
        "type": item.get("type"),
        "provider": item.get("provider"),
        "provider_name": item.get("provider_name") or item.get("provider"),
        "endpoint_path": item.get("endpoint_path") or "",
        "severity": item.get("severity"),
        "value_kind": item.get("value_kind") or ("literal" if item.get("key_sha256") else ""),
        "key_redacted": item.get("key_redacted") or (item.get("value_redacted") if item.get("type") != "base_url" else ""),
        "key_sha256": item.get("key_sha256") or (item.get("value_sha256") if item.get("type") != "base_url" else ""),
        "base_url_redacted": "\n".join(item.get("base_urls_redacted") or []) or item.get("base_url_redacted") or "",
        "base_url_sha256": base_hash or ", ".join(item.get("base_url_sha256") or []),
        "base_url_source": item.get("base_url_source"),
        "public_evidence_level": item.get("public_evidence_level"),
        "public_evidence_label": item.get("public_evidence_label"),
        "models": ", ".join(item.get("models") or []),
        "first_seen_at": item.get("first_seen_at"),
        "last_seen_at": item.get("last_seen_at"),
        "seen_count": item.get("seen_count"),
        "source": source.get("source"),
        "source_url": source_url,
        "source_title": source.get("title"),
        "query": source.get("query"),
    }
    return {key: csv_safe(value) for key, value in row.items()}


def csv_safe(value: Any) -> str:
    text = str(value if value is not None else "")
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
