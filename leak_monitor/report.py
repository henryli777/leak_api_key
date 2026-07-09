from __future__ import annotations

import html
from collections import Counter
from pathlib import Path
from typing import Any

from .csv_export import emit_findings_csv
from .dedup import dedupe_findings_for_export
from .models import SourceStats
from .timeutils import now_iso


def build_health(
    findings: list[dict[str, Any]],
    new_findings: list[dict[str, Any]],
    source_stats: list[SourceStats],
    query_count: int,
    timezone_name: str,
) -> dict[str, Any]:
    build_time = now_iso(timezone_name)
    severity_counts = Counter(str(item.get("severity", "unknown")) for item in findings)
    type_counts = Counter(str(item.get("type", "unknown")) for item in findings)
    source_hits = {stat.source: stat.hits for stat in source_stats}
    return {
        "build_time": build_time,
        "build_time_cn": build_time,
        "timezone": timezone_name,
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


def emit_report(
    output_dir: str | Path,
    findings: list[dict[str, Any]],
    new_findings: list[dict[str, Any]],
    health: dict[str, Any],
    validation_report: dict[str, Any] | None = None,
) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    emit_findings_csv(out, findings)
    _write_text(out / "index.html", render_html(findings, health, validation_report))
    _write_text(out / "README.txt", "AI leak monitor report. Values are redacted; use source URLs for manual triage.\n")


def render_html(findings: list[dict[str, Any]], health: dict[str, Any], validation_report: dict[str, Any] | None = None) -> str:
    rows = []
    sorted_findings = dedupe_findings_for_export(findings)
    for item in sorted_findings[:250]:
        source = (item.get("sources") or [{}])[0]
        source_url = html.escape(source.get("url") or "")
        title = html.escape(source.get("title") or source_url)
        excerpt = html.escape(source.get("excerpt") or "")
        models = html.escape(", ".join(item.get("models") or []))
        key_value = _code_block(item.get("key_redacted") or (item.get("value_redacted") if item.get("type") != "base_url" else ""))
        base_url = _code_block("\n".join(item.get("base_urls_redacted") or []) or item.get("base_url_redacted") or (item.get("value_redacted") if item.get("type") == "base_url" else ""))
        pair_source = html.escape(_pair_source_label(item))
        evidence = html.escape(str(item.get("public_evidence_label") or ""))
        dedup_count = html.escape(str(item.get("deduped_finding_count") or 1))
        first_seen = html.escape(str(item.get("first_seen_at") or ""))
        last_seen = html.escape(str(item.get("last_seen_at") or ""))
        rows.append(
            "<tr>"
            f"<td><span class='sev {html.escape(str(item.get('severity')))}'>{html.escape(str(item.get('severity')))}</span></td>"
            f"<td>{html.escape(str(item.get('type')))}</td>"
            f"<td>{html.escape(str(item.get('provider')))}</td>"
            f"<td class='secret-cell'>{key_value}</td>"
            f"<td class='url-cell'>{base_url}<div class='excerpt'>{pair_source}</div><div class='excerpt'>{evidence}</div><div class='excerpt'>合并线索: {dedup_count}</div></td>"
            f"<td>{models}</td>"
            f"<td><a href='{source_url}'>{title}</a><div class='excerpt'>{excerpt}</div></td>"
            f"<td>{first_seen}</td>"
            f"<td>{last_seen}</td>"
            "</tr>"
        )
    validation_summary = render_validation_summary(validation_report)
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
    .table-wrap {{ width: 100%; overflow-x: auto; border: 1px solid #d9e2ec; background: white; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .button {{ display: inline-flex; align-items: center; height: 34px; border-radius: 4px; padding: 0 12px; background: #0b63ce; color: white; font-weight: 650; text-decoration: none; }}
    .button.secondary {{ background: #486581; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .metric {{ background: white; border: 1px solid #d9e2ec; border-radius: 6px; padding: 10px 12px; min-width: 140px; }}
    .metric strong {{ display: block; font-size: 22px; }}
    table {{ width: 2240px; table-layout: fixed; border-collapse: collapse; background: white; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e6edf3; vertical-align: top; text-align: left; }}
    th {{ background: #eef3f8; font-weight: 650; }}
    .col-level {{ width: 72px; }}
    .col-type {{ width: 140px; }}
    .col-provider {{ width: 170px; }}
    .col-key {{ width: 380px; }}
    .col-base-url {{ width: 560px; }}
    .col-models {{ width: 180px; }}
    .col-source {{ width: 460px; }}
    .col-time {{ width: 170px; }}
    .secret-block {{ display: block; max-width: 100%; overflow-x: auto; white-space: pre; overflow-wrap: normal; word-break: normal; background: #f8fafc; border: 1px solid #d9e2ec; border-radius: 4px; padding: 6px 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.45; }}
    .url-cell .secret-block {{ max-height: 124px; }}
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
    <div>生成时间: {html.escape(str(health.get("build_time_cn") or health.get("build_time")))} | 时区: {html.escape(str(health.get("timezone") or "Asia/Shanghai"))}</div>
  </header>
  <main>
    <nav class="actions">
      <a class="button" href="validation.html">后台真实验证</a>
      <a class="button secondary" href="findings.csv">下载CSV</a>
      <a class="button secondary" href="private.html">明文页</a>
      <a class="button secondary" href="https://github.com/henryli777/leak_api_key/actions/workflows/leak-monitor.yml">重新验证</a>
    </nav>
    <section class="summary">
      <div class="metric"><span>总线索</span><strong>{health.get("total_findings", 0)}</strong></div>
      <div class="metric"><span>去重线索</span><strong>{len(sorted_findings)}</strong></div>
      <div class="metric"><span>本轮新增</span><strong>{health.get("new_findings", 0)}</strong></div>
      <div class="metric"><span>高危</span><strong>{(health.get("severity_counts") or {}).get("high", 0)}</strong></div>
      <div class="metric"><span>中危</span><strong>{(health.get("severity_counts") or {}).get("medium", 0)}</strong></div>
    </section>
    {validation_summary}
    <div class="table-wrap">
      <table>
        <colgroup>
          <col class="col-level">
          <col class="col-type">
          <col class="col-provider">
          <col class="col-key">
          <col class="col-base-url">
          <col class="col-models">
          <col class="col-source">
          <col class="col-time">
          <col class="col-time">
        </colgroup>
        <thead><tr><th>级别</th><th>类型</th><th>平台</th><th>密钥</th><th>base_url</th><th>模型</th><th>来源</th><th>发现时间</th><th>最后出现</th></tr></thead>
        <tbody>{''.join(rows) or '<tr><td colspan="9">暂无线索</td></tr>'}</tbody>
      </table>
    </div>
  </main>
</body>
</html>
"""


def render_validation_summary(validation_report: dict[str, Any] | None) -> str:
    if not validation_report:
        return ""
    target_count = validation_report.get("target_count", 0)
    ok_targets = validation_report.get("ok_targets", 0)
    tested_models = sum(int(item.get("tested_models") or 0) for item in validation_report.get("results", []))
    ok_models = sum(len(item.get("ok_models") or []) for item in validation_report.get("results", []))
    failed_models = max(tested_models - ok_models, 0)
    finished_at = html.escape(str(validation_report.get("finished_at") or ""))
    return (
        '<section class="summary">'
        f'<div class="metric"><span>验证目标</span><strong>{target_count}</strong></div>'
        f'<div class="metric"><span>可用目标</span><strong>{ok_targets}</strong></div>'
        f'<div class="metric"><span>测试模型</span><strong>{tested_models}</strong></div>'
        f'<div class="metric"><span>可用模型</span><strong>{ok_models}</strong></div>'
        f'<div class="metric"><span>不可用模型</span><strong>{failed_models}</strong></div>'
        f'<div class="metric"><span>验证时间</span><strong style="font-size:15px">{finished_at}</strong></div>'
        "</section>"
    )


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _pair_source_label(item: dict[str, Any]) -> str:
    if item.get("base_url_source") == "same_hit":
        return "同一线索发现"
    if item.get("base_url_source") == "historical_fallback":
        return "历史 base_url 备选"
    return ""


def _code_block(value: Any) -> str:
    text = str(value if value is not None else "")
    if not text:
        return ""
    return f"<code class='secret-block'>{html.escape(text)}</code>"
