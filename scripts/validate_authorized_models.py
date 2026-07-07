#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from leak_monitor.authorized_validator import ValidationTarget, validate_target  # noqa: E402
from leak_monitor.detectors import redact_secret, sha256_text  # noqa: E402
from leak_monitor.timeutils import now_iso  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run real backend model validation for explicitly authorized findings.csv rows."
    )
    parser.add_argument("findings_csv", help="Downloaded findings.csv from the report page.")
    parser.add_argument(
        "--secrets-csv",
        required=True,
        help=(
            "Local CSV with authorized raw api_key values. Columns: api_key; optional key_sha256, "
            "base_url, base_url_sha256, name, models, max_models, timeout_seconds."
        ),
    )
    parser.add_argument(
        "--base-url-library",
        default="base-url-library.csv",
        help="Local base_url library CSV/TXT. CSV columns may include base_url and optional name. One URL per line is also accepted.",
    )
    parser.add_argument("--history-json", default="validation-history.json", help="Local validation history used to skip repeats.")
    parser.add_argument("--output-json", default="validation-results.json")
    parser.add_argument("--output-csv", default="validation-results.csv")
    parser.add_argument("--output-available-csv", default="validation-available.csv")
    parser.add_argument("--revalidate-all", action="store_true", help="Ignore local history and validate every candidate again.")
    parser.add_argument("--max-candidates", type=int, default=0, help="Optional cap for this run; 0 means no cap.")
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Required confirmation that every api_key/base_url candidate is authorized for this validation.",
    )
    args = parser.parse_args()

    if not args.i_am_authorized:
        print(
            "Refusing to run: pass --i-am-authorized only for credentials and base_urls you are authorized to test.",
            file=sys.stderr,
        )
        return 2

    findings = read_csv(Path(args.findings_csv))
    secrets = load_secrets(Path(args.secrets_csv))
    base_url_library_path = Path(args.base_url_library)
    base_urls = merge_base_url_library(load_base_url_library(base_url_library_path), collect_secret_base_urls(secrets))
    write_base_url_library(base_url_library_path, base_urls)
    candidates = build_candidates(findings, secrets, base_urls)
    if args.max_candidates > 0:
        candidates = candidates[: args.max_candidates]

    history_path = Path(args.history_json)
    history = read_json(history_path, {"version": 1, "items": {}})
    report = validate_candidates(candidates, history, revalidate_all=args.revalidate_all)
    write_json(history_path, history)
    write_json(Path(args.output_json), report)
    write_summary_csv(Path(args.output_csv), report)
    write_available_csv(Path(args.output_available_csv), report)
    print(
        f"candidates={report.get('candidate_count', 0)} "
        f"validated={report.get('validated_count', 0)} "
        f"skipped={report.get('skipped_count', 0)} "
        f"ok_candidates={report.get('ok_candidates', 0)} "
        f"ok_models={report.get('ok_models', 0)}"
    )
    return 0


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return [{str(k or "").strip(): str(v or "").strip() for k, v in row.items()} for row in csv.DictReader(f)]


def load_secrets(path: Path) -> dict[str, list[dict[str, str]]]:
    by_hash: dict[str, list[dict[str, str]]] = {}
    for row in read_csv(path):
        api_key = (row.get("api_key") or "").strip()
        key_hash = (row.get("key_sha256") or "").strip() or (sha256_text(api_key) if api_key else "")
        if not api_key or not key_hash:
            continue
        base_urls = split_base_urls(row.get("base_url") or "")
        base_url_hashes = split_hashes(row.get("base_url_sha256") or "")
        if not base_urls:
            base_urls = [""]
        for idx, base_url in enumerate(base_urls):
            copied = dict(row)
            copied["key_sha256"] = key_hash
            copied["api_key_redacted"] = redact_secret(api_key)
            copied["base_url"] = base_url
            if base_url:
                copied["base_url_sha256"] = (
                    base_url_hashes[idx]
                    if idx < len(base_url_hashes)
                    else sha256_text(normalize_base_url_for_hash(base_url))
                )
            by_hash.setdefault(key_hash, []).append(copied)
    return by_hash


def load_base_url_library(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    if path.suffix.lower() == ".csv":
        rows = read_csv(path)
        out = []
        for idx, row in enumerate(rows, 1):
            base_url = (row.get("base_url") or row.get("url") or "").strip()
            if not base_url:
                continue
            out.append(
                {
                    "name": row.get("name") or f"base-url-{idx}",
                    "base_url": base_url,
                    "base_url_sha256": row.get("base_url_sha256") or sha256_text(normalize_base_url_for_hash(base_url)),
                }
            )
        return dedup_base_urls(out)

    out = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        base_url = line.strip()
        if not base_url or base_url.startswith("#"):
            continue
        out.append(
            {
                "name": f"base-url-{idx}",
                "base_url": base_url,
                "base_url_sha256": sha256_text(normalize_base_url_for_hash(base_url)),
            }
        )
    return dedup_base_urls(out)


def collect_secret_base_urls(secrets_by_hash: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    out = []
    for rows in secrets_by_hash.values():
        for row in rows:
            base_url = (row.get("base_url") or "").strip()
            if not base_url:
                continue
            out.append(
                {
                    "name": row.get("name") or "secret-base-url",
                    "base_url": base_url,
                    "base_url_sha256": row.get("base_url_sha256") or sha256_text(normalize_base_url_for_hash(base_url)),
                }
            )
    return dedup_base_urls(out)


def merge_base_url_library(left: list[dict[str, str]], right: list[dict[str, str]]) -> list[dict[str, str]]:
    return dedup_base_urls([*left, *right])


def write_base_url_library(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "base_url", "base_url_sha256"])
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "name": row.get("name", ""),
                    "base_url": row.get("base_url", ""),
                    "base_url_sha256": row.get("base_url_sha256", ""),
                }
            )


def build_candidates(
    findings: list[dict[str, str]],
    secrets_by_hash: dict[str, list[dict[str, str]]],
    base_url_library: list[dict[str, str]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    base_urls_by_hash = {row["base_url_sha256"]: row for row in base_url_library if row.get("base_url_sha256")}
    for row in findings:
        key_hash = (row.get("key_sha256") or "").strip()
        if not key_hash or key_hash not in secrets_by_hash:
            continue
        for secret in secrets_by_hash[key_hash]:
            matched_base_urls = resolve_base_urls_for_finding(row, secret, base_urls_by_hash, base_url_library)
            for base_url in matched_base_urls:
                candidates.append(build_candidate(row, secret, base_url))
    return dedup_candidates(candidates)


def resolve_base_urls_for_finding(
    finding: dict[str, str],
    secret: dict[str, str],
    base_urls_by_hash: dict[str, dict[str, str]],
    base_url_library: list[dict[str, str]],
) -> list[dict[str, str]]:
    secret_base_url = (secret.get("base_url") or "").strip()
    if secret_base_url:
        return [
            {
                "name": secret.get("name") or "secret-base-url",
                "base_url": secret_base_url,
                "base_url_sha256": secret.get("base_url_sha256") or sha256_text(normalize_base_url_for_hash(secret_base_url)),
            }
        ]

    finding_hashes = split_hashes(finding.get("base_url_sha256") or "")
    matched = [base_urls_by_hash[h] for h in finding_hashes if h in base_urls_by_hash]
    if matched:
        return dedup_base_urls(matched)

    return base_url_library


def build_candidate(finding: dict[str, str], secret: dict[str, str], base_url: dict[str, str]) -> dict[str, Any]:
    key_hash = secret["key_sha256"]
    base_url_hash = base_url.get("base_url_sha256") or sha256_text(normalize_base_url_for_hash(base_url["base_url"]))
    models = split_models(secret.get("models") or finding.get("models") or "")
    candidate_id = sha256_text(f"{key_hash}:{base_url_hash}:{','.join(models)}")
    return {
        "candidate_id": candidate_id,
        "finding_id": finding.get("id", ""),
        "source_url": finding.get("source_url", ""),
        "public_evidence_level": finding.get("public_evidence_level", ""),
        "key_sha256": key_hash,
        "api_key": secret["api_key"],
        "api_key_redacted": secret.get("api_key_redacted") or redact_secret(secret["api_key"]),
        "base_url": base_url["base_url"],
        "base_url_sha256": base_url_hash,
        "models": models,
        "max_models": to_int(secret.get("max_models"), 12),
        "timeout_seconds": to_int(secret.get("timeout_seconds"), 20),
        "name": secret.get("name") or base_url.get("name") or finding.get("id") or "candidate",
    }


def validate_candidates(candidates: list[dict[str, Any]], history: dict[str, Any], revalidate_all: bool) -> dict[str, Any]:
    started_at = now_iso()
    history_items = history.setdefault("items", {})
    results = []
    skipped_count = 0
    validated_count = 0
    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        if not revalidate_all and candidate_id in history_items:
            skipped_count += 1
            previous = dict(history_items[candidate_id])
            previous["skipped"] = True
            results.append(previous)
            continue

        target = ValidationTarget(
            name=candidate["name"],
            base_url=candidate["base_url"],
            api_key=candidate["api_key"],
            models=candidate["models"],
            timeout_seconds=candidate["timeout_seconds"],
            max_models=candidate["max_models"],
        )
        result = validate_target(target)
        result.update(
            {
                "candidate_id": candidate_id,
                "finding_id": candidate["finding_id"],
                "source_url": candidate["source_url"],
                "public_evidence_level": candidate["public_evidence_level"],
                "key_sha256": candidate["key_sha256"],
                "api_key_redacted": candidate["api_key_redacted"],
                "base_url_sha256": candidate["base_url_sha256"],
                "skipped": False,
            }
        )
        history_items[candidate_id] = sanitize_history_item(result)
        results.append(history_items[candidate_id])
        validated_count += 1

    ok_models_total = sum(len(item.get("ok_models") or []) for item in results)
    tested_models_total = sum(int(item.get("tested_models") or 0) for item in results)
    return {
        "validation_mode": "local_authorized_live_test",
        "started_at": started_at,
        "finished_at": now_iso(),
        "candidate_count": len(candidates),
        "validated_count": validated_count,
        "skipped_count": skipped_count,
        "ok_candidates": sum(1 for item in results if item.get("ok")),
        "tested_models": tested_models_total,
        "ok_models": ok_models_total,
        "failed_models": max(tested_models_total - ok_models_total, 0),
        "results": results,
    }


def sanitize_history_item(item: dict[str, Any]) -> dict[str, Any]:
    copied = dict(item)
    copied.pop("api_key", None)
    return copied


def split_models(value: str) -> list[str]:
    normalized = value.replace("\n", ",").replace(";", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()]


def split_hashes(value: str) -> list[str]:
    return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]


def split_base_urls(value: str) -> list[str]:
    normalized = (value or "").replace("\r\n", "\n").replace("\r", "\n").replace(";", "\n")
    parts = [part.strip() for part in normalized.split("\n") if part.strip()]
    if len(parts) == 1 and parts[0].count("http") > 1:
        parts = [part.strip() for part in re.split(r"\s*,\s*(?=https?://)", parts[0]) if part.strip()]
    return list(dict.fromkeys(parts))


def normalize_base_url_for_hash(base_url: str) -> str:
    return base_url.strip().rstrip("/") + "/"


def dedup_base_urls(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out = []
    seen = set()
    for row in rows:
        key = row.get("base_url_sha256") or row.get("base_url")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def dedup_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    seen = set()
    for candidate in candidates:
        key = candidate["candidate_id"]
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def to_int(value: str | None, default: int) -> int:
    try:
        return int(str(value or "").strip() or default)
    except ValueError:
        return default


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_summary_csv(path: Path, report: dict) -> None:
    fields = [
        "candidate_id",
        "finding_id",
        "validated_at",
        "validation_finished_at",
        "skipped",
        "api_key_redacted",
        "key_sha256",
        "base_url",
        "base_url_sha256",
        "name",
        "ok",
        "tested_models",
        "ok_models",
        "failed_models",
        "model_source",
        "validation_started_at",
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for item in report.get("results", []):
            writer.writerow(
                {
                    "name": item.get("name", ""),
                    "candidate_id": item.get("candidate_id", ""),
                    "finding_id": item.get("finding_id", ""),
                    "validated_at": item.get("validation_finished_at", ""),
                    "validation_finished_at": item.get("validation_finished_at", ""),
                    "skipped": item.get("skipped", False),
                    "api_key_redacted": item.get("api_key_redacted", ""),
                    "key_sha256": item.get("key_sha256", ""),
                    "base_url": item.get("base_url", ""),
                    "base_url_sha256": item.get("base_url_sha256", ""),
                    "ok": item.get("ok", False),
                    "tested_models": item.get("tested_models", 0),
                    "ok_models": ", ".join(item.get("ok_models") or []),
                    "failed_models": ", ".join(item.get("failed_models") or []),
                    "model_source": item.get("model_source", ""),
                    "validation_started_at": item.get("validation_started_at", ""),
                    "validation_finished_at": item.get("validation_finished_at", ""),
                }
            )


def write_available_csv(path: Path, report: dict) -> None:
    fields = [
        "validated_at",
        "candidate_id",
        "finding_id",
        "api_key_redacted",
        "key_sha256",
        "base_url",
        "base_url_sha256",
        "ok_models",
        "tested_models",
        "source_url",
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for item in report.get("results", []):
            if not item.get("ok"):
                continue
            writer.writerow(
                {
                    "validated_at": item.get("validation_finished_at", ""),
                    "candidate_id": item.get("candidate_id", ""),
                    "finding_id": item.get("finding_id", ""),
                    "api_key_redacted": item.get("api_key_redacted", ""),
                    "key_sha256": item.get("key_sha256", ""),
                    "base_url": item.get("base_url", ""),
                    "base_url_sha256": item.get("base_url_sha256", ""),
                    "ok_models": ", ".join(item.get("ok_models") or []),
                    "tested_models": item.get("tested_models", 0),
                    "source_url": item.get("source_url", ""),
                }
            )


if __name__ == "__main__":
    raise SystemExit(main())
