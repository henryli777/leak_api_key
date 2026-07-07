from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .config import build_queries, load_config
from .detectors import analyze_hit
from .models import SearchHit
from .notify import notify_dingtalk
from .report import build_health, emit_report
from .sources import run_sources, utc_now
from .storage import merge_findings, read_json, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Monitor public sources for redacted AI API key/base_url/model leaks.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run one monitoring pass")
    scan.add_argument("--config", default="config/targets.yml")
    scan.add_argument("--data-dir", default="data")
    scan.add_argument("--output-dir", default="dist")
    scan.add_argument("--sources", default="github,google", help="comma separated: github,google")
    scan.add_argument("--max-queries", type=int, default=None)
    scan.add_argument("--notify", action="store_true")
    scan.add_argument("--dry-run", action="store_true")

    sub.add_parser("self-test", help="run detector smoke test with synthetic data")
    args = parser.parse_args(argv)

    if args.command == "self-test":
        return self_test()
    if args.command in (None, "scan"):
        return run_scan(args)
    parser.print_help()
    return 2


def run_scan(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.max_queries:
        cfg.max_queries = args.max_queries
    queries = build_queries(cfg)
    requested_sources = {s.strip() for s in args.sources.split(",") if s.strip()}

    print(f"queries={len(queries)} sources={','.join(sorted(requested_sources))}")
    hits, source_stats = run_sources(cfg, queries, requested_sources)
    print(f"hits={len(hits)}")

    now_iso = utc_now()
    incoming: list[dict[str, Any]] = []
    for hit in hits:
        incoming.extend(analyze_hit(hit, now_iso))
    print(f"detected_findings={len(incoming)}")

    data_dir = Path(args.data_dir)
    findings_path = data_dir / "findings.json"
    existing = read_json(findings_path, [])
    merged, new_findings = merge_findings(existing, incoming)
    health = build_health(merged, new_findings, source_stats, len(queries), cfg.timezone)

    if not args.dry_run:
        write_json(findings_path, merged)
        write_json(data_dir / "last_run.json", health)
        write_json(Path(args.output_dir) / "health.json", health)
        write_json(Path(args.output_dir) / "findings.json", merged)
        emit_report(args.output_dir, merged, new_findings, health)
    else:
        print("dry_run=true; not writing data")

    if args.notify and not args.dry_run:
        sent = notify_dingtalk(health, new_findings, cfg.min_severity_to_notify)
        print(f"dingtalk_sent={sent}")

    return 0


def self_test() -> int:
    fake_key = "sk-proj-" + "AbCDefGhIjKlMnOpQrStUvWxYz0123456789"
    hit = SearchHit(
        source="self_test",
        query="synthetic",
        url="https://example.invalid/leak",
        title="Synthetic AI config leak",
        snippet=(
            "OPENAI_BASE_URL=https://api.example.invalid/v1 "
            f"OPENAI_API_KEY={fake_key} "
            "model=gpt-4o"
        ),
        fetched_at=utc_now(),
    )
    findings = analyze_hit(hit, utc_now())
    if not findings:
        print("self-test failed: no finding detected", file=sys.stderr)
        return 1
    text = str(findings)
    if "AbCDefGhIjKlMnOpQrStUvWxYz0123456789" in text:
        print("self-test failed: unredacted synthetic key found", file=sys.stderr)
        return 1
    print(f"self-test ok: {len(findings)} finding(s), redaction ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
