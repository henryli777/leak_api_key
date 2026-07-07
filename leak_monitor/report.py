from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .models import SourceStats


def build_health(
    findings: list[dict[str, Any]],
    new_findings: list[dict[str, Any]],
    source_stats: list[SourceStats],
    query_count: int,
    timezone_name: str,
) -> dict[str, Any]:
    now_utc = datetime.utcnow().replace(microsecond=0)
    try:
        cn = datetime.now(ZoneInfo(timezone_name)).replace(microsecond=0)
    except Exception:
        cn = datetime.now().replace(microsecond=0)
    severity_counts = Counter(str(item.get("severity", "unknown")) for item in findings)
    type_counts = Counter(str(item.get("type", "unknown")) for item in findings)
    source_hits = {stat.source: stat.hits for stat in source_stats}
    return {
        "build_time_utc": now_utc.isoformat() + "Z",
        "build_time_cn": cn.isoformat(),
        "query_count": query_count,
        "total_findings": len(findings),
        "new_findings": len(new_findings),
        "severity_counts": dict(severity_counts),
        "type_counts": dict(type_counts),
        "source_hits": source_hits,
        "source_stats": [
            {
                "source": stat.source,
                "queries": stat.queries,
                "hits": stat.hits,
                "errors": stat.errors,
                "skipped": stat.skipped,
                "message": stat.message,
            }
            for stat in source_stats
        ],
    }


def emit_report(output_dir: str | Path, findings: list[dict[str, Any]], new_findings: list[dict[str, Any]], health: dict[str, Any]) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    _write_text(out / "index.html", render_html(findings, health))
    _write_text(out / "README.txt", "AI leak monitor report. Values are redacted; use source URLs for manual triage.\n")


def render_html(findings: list[dict[str, Any]], health: dict[str, Any]) -> str:
    rows = []
    for item in findings[:250]:
        source = (item.get("sources") or [{}])[0]
        source_url = html.escape(source.get("url") or "")
        title = html.escape(source.get("title") or source_url)
        excerpt = html.escape(source.get("excerpt") or "")
        models = html.escape(", ".join(item.get("models") or []))
        value = html.escape(item.get("value_redacted") or ", ".join(item.get("base_urls_redacted") or []))
        rows.append(
            "<tr>"
            f"<td><span class='sev {html.escape(str(item.get('severity')))}'>{html.escape(str(item.get('severity')))}</span></td>"
            f"<td>{html.escape(str(item.get('type')))}</td>"
            f"<td>{html.escape(str(item.get('provider')))}</td>"
            f"<td><code>{value}</code></td>"
            f"<td>{models}</td>"
            f"<td><a href='{source_url}'>{title}</a><div class='excerpt'>{excerpt}</div></td>"
            f"<td>{html.escape(str(item.get('last_seen_at') or ''))}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI 泄露线索监测</title>
  <style>
    body {{ margin: 0; font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1f2933; background: #f7f8fa; }}
    header {{ padding: 24px 28px; background: #102a43; color: white; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    main {{ padding: 22px 28px; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .metric {{ background: white; border: 1px solid #d9e2ec; border-radius: 6px; padding: 10px 12px; min-width: 140px; }}
    .metric strong {{ display: block; font-size: 22px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e2ec; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e6edf3; vertical-align: top; text-align: left; }}
    th {{ background: #eef3f8; font-weight: 650; }}
    code {{ word-break: break-all; }}
    a {{ color: #0b63ce; text-decoration: none; }}
    .excerpt {{ color: #52606d; margin-top: 6px; max-width: 640px; }}
    .sev {{ display: inline-block; border-radius: 4px; padding: 2px 7px; color: white; font-size: 12px; }}
    .sev.high {{ background: #ba2525; }}
    .sev.medium {{ background: #b7791f; }}
    .sev.low {{ background: #486581; }}
  </style>
</head>
<body>
  <header>
    <h1>AI 泄露线索监测</h1>
    <div>生成时间: {html.escape(str(health.get("build_time_cn") or health.get("build_time_utc")))}</div>
  </header>
  <main>
    <section class="summary">
      <div class="metric"><span>总线索</span><strong>{health.get("total_findings", 0)}</strong></div>
      <div class="metric"><span>本轮新增</span><strong>{health.get("new_findings", 0)}</strong></div>
      <div class="metric"><span>高危</span><strong>{(health.get("severity_counts") or {}).get("high", 0)}</strong></div>
      <div class="metric"><span>中危</span><strong>{(health.get("severity_counts") or {}).get("medium", 0)}</strong></div>
    </section>
    <table>
      <thead><tr><th>级别</th><th>类型</th><th>平台</th><th>脱敏值</th><th>模型</th><th>来源</th><th>最后发现</th></tr></thead>
      <tbody>{''.join(rows) or '<tr><td colspan="7">暂无线索</td></tr>'}</tbody>
    </table>
  </main>
</body>
</html>
"""


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
