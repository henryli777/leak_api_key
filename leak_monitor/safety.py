from __future__ import annotations

import re
import csv
from pathlib import Path
from urllib.parse import urlparse, urlunparse


RAW_SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,})\b")


def sanitize_source_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return str(url or "").split("?", 1)[0]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def verify_public_exports(output_dir: str | Path) -> None:
    out = Path(output_dir)
    checked = []
    for name in ("findings.csv", "provider_pairs.csv", "index.html", "findings.json", "health.json"):
        path = out / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        checked.append(name)
        match = RAW_SECRET_RE.search(text)
        if match:
            raise ValueError(f"raw secret-like value found in public export {name}: {match.group(0)[:8]}...")
        if re.search(r"https?://[^\s\"'<>]+\?(?:[^\s\"'<>]*(?:token|key|secret|apikey|api_key)=)", text, re.I):
            raise ValueError(f"sensitive query parameter found in public export {name}")
        if path.suffix.lower() == ".csv":
            verify_csv_key_prefixes(path)
    if not checked:
        raise ValueError(f"no public exports found under {out}")


def verify_csv_key_prefixes(path: Path) -> None:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            key_redacted = str(row.get("key_redacted") or "").strip()
            if not key_redacted:
                continue
            key_hash = str(row.get("key_sha256") or "").strip()
            value_kind = str(row.get("value_kind") or "").strip()
            if not key_hash and value_kind != "literal":
                continue
            if value_kind and value_kind != "literal":
                continue
            if not key_redacted.startswith("sk-"):
                raise ValueError(f"non-sk key_redacted found in public export {path.name}: {key_redacted[:8]}...")
