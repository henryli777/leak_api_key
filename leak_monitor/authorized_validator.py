from __future__ import annotations

import html
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from .timeutils import DEFAULT_TIMEZONE, now_iso


DEFAULT_MODEL_LIBRARY = [
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-4.1-mini",
    "gpt-4.1",
    "claude-3-5-haiku-latest",
    "claude-3-5-sonnet-latest",
    "deepseek-chat",
    "deepseek-reasoner",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "qwen-plus",
    "qwen-turbo",
    "llama-3.1-8b-instant",
    "mistral-small-latest",
    "grok-3-mini",
]


CHAT_HINTS = (
    "gpt",
    "chat",
    "claude",
    "deepseek",
    "gemini",
    "qwen",
    "llama",
    "mistral",
    "grok",
    "glm",
    "kimi",
)


@dataclass(slots=True)
class ValidationTarget:
    name: str
    base_url: str
    api_key: str
    models: list[str]
    timeout_seconds: int = 20
    max_models: int = 12


def run_authorized_validation_from_env(output_dir: str | Path) -> bool:
    report, configured = build_authorized_validation_report_from_env()
    emit_validation_report(output_dir, report)
    return configured


def build_authorized_validation_report_from_env() -> tuple[dict[str, Any], bool]:
    raw = os.getenv("AUTHORIZED_VALIDATION_TARGETS_JSON", "").strip()
    if not raw:
        targets: list[ValidationTarget] = []
    else:
        targets = load_targets(raw)
    report = validate_targets(targets)
    return report, bool(targets)


def load_targets(raw_json: str) -> list[ValidationTarget]:
    data = json.loads(raw_json)
    if isinstance(data, dict):
        data = data.get("targets", [])
    if not isinstance(data, list):
        raise ValueError("AUTHORIZED_VALIDATION_TARGETS_JSON must be a list or an object with targets")

    targets: list[ValidationTarget] = []
    for idx, item in enumerate(data, 1):
        if not isinstance(item, dict):
            continue
        base_url = str(item.get("base_url") or "").strip()
        api_key = str(item.get("api_key") or "").strip()
        if not base_url or not api_key:
            continue
        models_raw = item.get("models") or []
        if isinstance(models_raw, str):
            models = [part.strip() for part in models_raw.replace("\n", ",").split(",") if part.strip()]
        else:
            models = [str(model).strip() for model in models_raw if str(model).strip()]
        targets.append(
            ValidationTarget(
                name=str(item.get("name") or f"target-{idx}").strip(),
                base_url=base_url,
                api_key=api_key,
                models=models,
                timeout_seconds=int(item.get("timeout_seconds") or 20),
                max_models=int(item.get("max_models") or 12),
            )
        )
    return targets


def validate_targets(targets: list[ValidationTarget]) -> dict[str, Any]:
    started_at = utc_now()
    results = [validate_target(target) for target in targets]
    ok_models_total = sum(len(item.get("ok_models") or []) for item in results)
    tested_models_total = sum(int(item.get("tested_models") or 0) for item in results)
    failed_models_total = max(tested_models_total - ok_models_total, 0)
    return {
        "validation_mode": "authorized_backend_live_test",
        "real_backend_validation": True,
        "uses_leaked_findings": False,
        "started_at": started_at,
        "finished_at": utc_now(),
        "target_count": len(targets),
        "ok_targets": sum(1 for item in results if item.get("ok")),
        "tested_models": tested_models_total,
        "ok_models": ok_models_total,
        "failed_models": failed_models_total,
        "results": results,
        "default_model_library": DEFAULT_MODEL_LIBRARY,
    }


def validate_target(target: ValidationTarget) -> dict[str, Any]:
    validation_started_at = utc_now()
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {target.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "leak-api-key-authorized-validator/1.0",
        }
    )
    base_url = normalize_base_url(target.base_url)
    model_result = fetch_models(session, base_url, target.timeout_seconds)
    model_ids = target.models or model_result.get("models") or []
    model_source = "configured" if target.models else model_result.get("source", "models_endpoint")
    if not model_ids:
        model_ids = DEFAULT_MODEL_LIBRARY
        model_source = "default_library"
    model_ids = filter_chat_models(model_ids)[: target.max_models]
    if not model_ids:
        model_ids = DEFAULT_MODEL_LIBRARY[: target.max_models]
        model_source = "default_library"

    tests = []
    for model in model_ids:
        tests.append(test_model(session, base_url, model, target.timeout_seconds))
        time.sleep(0.2)

    ok_models = [item["model"] for item in tests if item.get("ok")]
    failed_models = [item["model"] for item in tests if not item.get("ok")]
    return {
        "name": target.name,
        "base_url": base_url,
        "validated_by_backend": True,
        "validation_started_at": validation_started_at,
        "validation_finished_at": utc_now(),
        "models_endpoint": model_result,
        "model_source": model_source,
        "tested_models": len(tests),
        "ok": bool(ok_models),
        "ok_models": ok_models,
        "failed_models": failed_models,
        "tests": tests,
    }


def fetch_models(session: requests.Session, base_url: str, timeout_seconds: int) -> dict[str, Any]:
    url = api_url(base_url, "models")
    checked_at = utc_now()
    try:
        resp = session.get(url, timeout=timeout_seconds)
        elapsed_ms = round(resp.elapsed.total_seconds() * 1000)
        if resp.status_code >= 400:
            return {
                "ok": False,
                "source": "default_library",
                "checked_at": checked_at,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "error": summarize_error(resp.text),
                "models": [],
            }
        data = resp.json()
        models = parse_model_ids(data)
        return {
            "ok": True,
            "source": "models_endpoint",
            "checked_at": checked_at,
            "status_code": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "models": models,
        }
    except Exception as exc:
        return {
            "ok": False,
            "source": "default_library",
            "checked_at": checked_at,
            "error": str(exc)[:300],
            "models": [],
        }


def test_model(session: requests.Session, base_url: str, model: str, timeout_seconds: int) -> dict[str, Any]:
    url = api_url(base_url, "chat/completions")
    tested_at = utc_now()
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "temperature": 0,
        "max_tokens": 1,
        "stream": False,
    }
    try:
        resp = session.post(url, json=payload, timeout=timeout_seconds)
        elapsed_ms = round(resp.elapsed.total_seconds() * 1000)
        if resp.status_code >= 400:
            return {
                "model": model,
                "ok": False,
                "tested_at": tested_at,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "error": summarize_error(resp.text),
            }
        data = resp.json()
        return {
            "model": model,
            "ok": True,
            "tested_at": tested_at,
            "status_code": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "response_id": data.get("id", ""),
        }
    except Exception as exc:
        return {
            "model": model,
            "ok": False,
            "tested_at": tested_at,
            "error": str(exc)[:300],
        }


def parse_model_ids(data: Any) -> list[str]:
    raw_items = data.get("data", []) if isinstance(data, dict) else data
    models: list[str] = []
    if not isinstance(raw_items, list):
        return models
    for item in raw_items:
        if isinstance(item, str):
            models.append(item)
        elif isinstance(item, dict) and item.get("id"):
            models.append(str(item["id"]))
    return list(dict.fromkeys(models))


def filter_chat_models(models: list[str]) -> list[str]:
    out: list[str] = []
    for model in models:
        low = model.lower()
        if any(skip in low for skip in ("embedding", "embed", "rerank", "tts", "whisper", "image", "audio", "moderation")):
            continue
        if any(hint in low for hint in CHAT_HINTS):
            out.append(model)
    return list(dict.fromkeys(out))


def emit_validation_report(output_dir: str | Path, report: dict[str, Any]) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "validation.html").write_text(render_validation_html(report), encoding="utf-8")


def render_validation_html(report: dict[str, Any]) -> str:
    sections = []
    for result in sorted(report.get("results", []), key=lambda item: (bool(item.get("ok")), len(item.get("ok_models") or []), item.get("name", "")), reverse=True):
        tests = []
        for item in sorted(result.get("tests", []), key=lambda row: (bool(row.get("ok")), row.get("elapsed_ms") or 999999), reverse=True):
            status = '<span class="badge ok">可用</span>' if item.get("ok") else '<span class="badge fail">不可用</span>'
            err = item.get("error", "")
            tests.append(
                "<tr>"
                f"<td>{escape(item.get('model'))}</td>"
                f"<td>{status}</td>"
                f"<td>{escape(item.get('tested_at', ''))}</td>"
                f"<td>{escape(item.get('status_code', ''))}</td>"
                f"<td>{escape(item.get('elapsed_ms', ''))}</td>"
                f"<td>{escape(err)}</td>"
                "</tr>"
            )
        endpoint = result.get("models_endpoint", {})
        test_rows = "".join(tests) or '<tr><td colspan="6">未测试</td></tr>'
        ok_models_text = escape(", ".join(result.get("ok_models") or []) or "无")
        failed_models_text = escape(", ".join(result.get("failed_models") or []) or "无")
        sections.append(
            "<section>"
            f"<h2>{escape(result.get('name'))}</h2>"
            f"<p><strong>base_url:</strong> <code>{escape(result.get('base_url'))}</code></p>"
            f"<p><strong>后台验证时间:</strong> {escape(result.get('validation_started_at'))} 至 {escape(result.get('validation_finished_at'))}</p>"
            f"<p><strong>模型来源:</strong> {escape(result.get('model_source'))} | "
            f"<strong>/models:</strong> {'成功' if endpoint.get('ok') else '失败'} | "
            f"<strong>/models 验证时间:</strong> {escape(endpoint.get('checked_at', ''))}</p>"
            f"<p><strong>可用模型:</strong> {ok_models_text}</p>"
            f"<p><strong>不可用模型:</strong> {failed_models_text}</p>"
            "<table><thead><tr><th>模型</th><th>状态</th><th>验证时间</th><th>HTTP</th><th>耗时 ms</th><th>错误</th></tr></thead>"
            f"<tbody>{test_rows}</tbody></table>"
            "</section>"
        )
    default_models = "".join(f"<code>{escape(model)}</code>" for model in report.get("default_model_library", []))
    empty_state = (
        '<section><h2>未配置授权验证目标</h2>'
        '<p>配置 <code>AUTHORIZED_VALIDATION_TARGETS_JSON</code> 后，页面会显示 /models 拉取结果和模型可用性测试结果。</p>'
        "</section>"
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>后台真实模型验证结果</title>
  <style>
    body {{ margin: 0; font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f8fa; color: #1f2933; }}
    header {{ padding: 22px 26px; background: #102a43; color: white; }}
    main {{ padding: 22px 26px; }}
    section {{ margin-bottom: 22px; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .button {{ display: inline-flex; align-items: center; height: 34px; border-radius: 4px; padding: 0 12px; background: #0b63ce; color: white; font-weight: 650; text-decoration: none; }}
    .button.secondary {{ background: #486581; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }}
    .metric {{ background: white; border: 1px solid #d9e2ec; border-radius: 6px; padding: 10px 12px; min-width: 140px; }}
    .metric strong {{ display: block; font-size: 22px; }}
    .badge {{ display: inline-block; border-radius: 4px; padding: 2px 7px; color: white; font-size: 12px; }}
    .badge.ok {{ background: #207227; }}
    .badge.fail {{ background: #ba2525; }}
    .library {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .library code {{ background: white; border: 1px solid #d9e2ec; border-radius: 4px; padding: 4px 7px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e2ec; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid #e6edf3; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f8; }}
    code {{ word-break: break-all; }}
  </style>
</head>
<body>
  <header>
    <h1>后台真实模型验证结果</h1>
    <div>验证时间: {escape(report.get("started_at"))} 至 {escape(report.get("finished_at"))} | 目标: {escape(report.get("target_count"))} | 可用目标: {escape(report.get("ok_targets"))} | 模式: 授权后台实测</div>
  </header>
  <main>
    <nav class="actions">
      <a class="button" href="index.html">返回总览</a>
      <a class="button secondary" href="https://github.com/henryli777/leak_api_key/actions/workflows/leak-monitor.yml">重新验证</a>
    </nav>
    <section class="summary">
      <div class="metric"><span>验证目标</span><strong>{escape(report.get("target_count", 0))}</strong></div>
      <div class="metric"><span>可用目标</span><strong>{escape(report.get("ok_targets", 0))}</strong></div>
      <div class="metric"><span>测试模型</span><strong>{escape(report.get("tested_models", 0))}</strong></div>
      <div class="metric"><span>可用模型</span><strong>{escape(report.get("ok_models", 0))}</strong></div>
      <div class="metric"><span>不可用模型</span><strong>{escape(report.get("failed_models", 0))}</strong></div>
    </section>
    {''.join(sections) or empty_state}
    <section>
      <h2>默认模型库</h2>
      <div class="library">{default_models}</div>
    </section>
  </main>
</body>
</html>
"""


def normalize_base_url(base_url: str) -> str:
    return base_url.strip().rstrip("/") + "/"


def api_url(base_url: str, path: str) -> str:
    return urljoin(base_url, path)


def summarize_error(text: str) -> str:
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict):
                return str(error.get("message") or error.get("code") or error)[:300]
            if error:
                return str(error)[:300]
            return json.dumps(data, ensure_ascii=False)[:300]
    except Exception:
        pass
    return (text or "").replace("\n", " ")[:300]


def utc_now() -> str:
    return now_iso(DEFAULT_TIMEZONE)


def escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))
