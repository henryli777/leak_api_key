from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


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
        for item in findings:
            writer.writerow(build_csv_row(item))


def build_csv_row(item: dict[str, Any]) -> dict[str, str]:
    source = (item.get("sources") or [{}])[0]
    row = {
        "id": item.get("id"),
        "type": item.get("type"),
        "provider": item.get("provider"),
        "severity": item.get("severity"),
        "key_redacted": item.get("key_redacted") or (item.get("value_redacted") if item.get("type") != "base_url" else ""),
        "key_sha256": item.get("key_sha256") or (item.get("value_sha256") if item.get("type") != "base_url" else ""),
        "base_url_redacted": item.get("base_url_redacted") or ", ".join(item.get("base_urls_redacted") or []) or (item.get("value_redacted") if item.get("type") == "base_url" else ""),
        "base_url_sha256": ", ".join(item.get("base_url_sha256") or []) or (item.get("value_sha256") if item.get("type") == "base_url" else ""),
        "base_url_source": item.get("base_url_source"),
        "public_evidence_level": item.get("public_evidence_level"),
        "public_evidence_label": item.get("public_evidence_label"),
        "models": ", ".join(item.get("models") or []),
        "first_seen_at": item.get("first_seen_at"),
        "last_seen_at": item.get("last_seen_at"),
        "seen_count": item.get("seen_count"),
        "source": source.get("source"),
        "source_url": source.get("url"),
        "source_title": source.get("title"),
        "query": source.get("query"),
    }
    return {key: csv_safe(value) for key, value in row.items()}


def csv_safe(value: Any) -> str:
    text = str(value if value is not None else "")
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
