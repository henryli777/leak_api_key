from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from .config import build_queries_by_source, load_config
from .authorized_validator import build_authorized_validation_report_from_env, emit_validation_report
from .detectors import analyze_hit
from .models import SearchHit
from .notify import notify_dingtalk
from .pairing import collect_base_url_candidates, normalize_finding_timezones, pair_credential_findings, prepare_findings
from .private_report import emit_private_report
from .report import build_health, emit_report
from .safety import verify_public_exports
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
    verify = sub.add_parser("verify-exports", help="verify public exports do not contain raw secrets")
    verify.add_argument("--output-dir", default="dist")
    args = parser.parse_args(argv)

    if args.command == "self-test":
        return self_test()
    if args.command == "verify-exports":
        verify_public_exports(args.output_dir)
        print(f"public export safety ok: {args.output_dir}")
        return 0
    if args.command in (None, "scan"):
        return run_scan(args)
    parser.print_help()
    return 2


def run_scan(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.max_queries:
        cfg.max_queries = args.max_queries
    queries = build_queries_by_source(cfg)
    requested_sources = {s.strip() for s in args.sources.split(",") if s.strip()}

    print(f"queries={len(queries)} sources={','.join(sorted(requested_sources))}")
    hits, source_stats = run_sources(cfg, queries, requested_sources)
    print(f"hits={len(hits)}")

    now_iso = utc_now(cfg.timezone)
    incoming: list[dict[str, Any]] = []
    private_incoming: list[dict[str, Any]] = []
    private_report_enabled = bool(os.getenv("PRIVATE_REPORT_PASSWORD", "").strip())
    for hit in hits:
        incoming.extend(analyze_hit(hit, now_iso))
        if private_report_enabled:
            private_incoming.extend(analyze_hit(hit, now_iso, include_raw=True))
    print(f"detected_findings={len(incoming)}")

    data_dir = Path(args.data_dir)
    findings_path = data_dir / "findings.json"
    existing = prepare_findings(read_json(findings_path, []), cfg.timezone)
    incoming = normalize_finding_timezones(incoming, cfg.timezone)
    fallback_candidates = collect_base_url_candidates([*existing, *incoming])
    incoming = pair_credential_findings(incoming, fallback_candidates)
    merged, new_findings = merge_findings(existing, incoming)
    health = build_health(merged, new_findings, source_stats, len(queries), cfg.timezone)

    if not args.dry_run:
        validation_report, validation_configured = build_authorized_validation_report_from_env()
        write_json(findings_path, merged)
        write_json(data_dir / "last_run.json", health)
        write_json(Path(args.output_dir) / "health.json", health)
        write_json(Path(args.output_dir) / "findings.json", merged)
        emit_report(args.output_dir, merged, new_findings, health, validation_report)
        emit_validation_report(args.output_dir, validation_report)
        verify_public_exports(args.output_dir)
        if private_report_enabled:
            private_incoming = normalize_finding_timezones(private_incoming, cfg.timezone)
            private_fallback_candidates = collect_base_url_candidates([*private_incoming, *existing])
            private_incoming = pair_credential_findings(private_incoming, private_fallback_candidates)
            private_findings, _ = merge_findings([], private_incoming)
            generated = emit_private_report(args.output_dir, private_findings, health)
            print(f"private_report_generated={generated}")
        print(f"authorized_validation_generated={validation_configured}")
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
