from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_QUERY_TEMPLATES = [
    '"OPENAI_API_KEY" "OPENAI_BASE_URL"',
    '"OPENAI_API_KEY=" "sk-"',
    '"OPENAI_API_KEY:" "sk-"',
    '"OPENAI_API_KEY" "sk-proj-"',
    '"Authorization: Bearer sk-"',
    '"api_key" "sk-" "base_url"',
    '"apiKey" "sk-" "baseURL"',
    '"base_url" "https://" "sk-"',
    '"baseURL" "https://" "apiKey"',
    '"api_base" "https://" "sk-"',
    '"OPENAI_BASE_URL=" "https://"',
    '"OPENAI_BASE_URL:" "https://"',
    '"client = OpenAI" "base_url" "api_key"',
    '"OpenAI(" "base_url=" "api_key="',
    '"chat/completions" "sk-"',
    '"v1/models" "sk-"',
    '"ANTHROPIC_API_KEY" "claude"',
    '"DEEPSEEK_API_KEY" "deepseek"',
    '"GEMINI_API_KEY" "AIza"',
    '"GOOGLE_API_KEY" "AIza"',
    '"OPENROUTER_API_KEY" "sk-or-v1"',
    '"GROQ_API_KEY" "gsk_"',
    '"MISTRAL_API_KEY"',
    '"DASHSCOPE_API_KEY" "qwen"',
    '"grok" "base_url" "sk-"',
]

TARGET_QUERY_TEMPLATES = [
    '"{target}" "OPENAI_API_KEY" "sk-"',
    '"{target}" "OPENAI_BASE_URL" "https://"',
    '"{target}" "base_url" "sk-"',
    '"{target}" "baseURL" "apiKey"',
    '"{target}" "api_base" "https://"',
    '"{target}" "Authorization: Bearer sk-"',
    '"{target}" "chat/completions" "sk-"',
    '"{target}" "v1/models" "sk-"',
    '"{target}" "api_key" "model"',
    '"{target}" "ANTHROPIC_API_KEY"',
    '"{target}" "DEEPSEEK_API_KEY"',
    '"{target}" "gemini" "sk-"',
    '"{target}" "OPENROUTER_API_KEY"',
]


@dataclass(slots=True)
class SourceConfig:
    enabled: bool = True
    per_query: int = 10
    delay_seconds: float = 1.0
    fetch_pages: bool = False


@dataclass(slots=True)
class AppConfig:
    targets: list[str] = field(default_factory=list)
    query_templates: list[str] = field(default_factory=lambda: list(DEFAULT_QUERY_TEMPLATES))
    target_query_templates: list[str] = field(default_factory=lambda: list(TARGET_QUERY_TEMPLATES))
    max_queries: int = 24
    github: SourceConfig = field(default_factory=lambda: SourceConfig(per_query=12, delay_seconds=1.2))
    google: SourceConfig = field(default_factory=lambda: SourceConfig(per_query=10, delay_seconds=1.0))
    min_severity_to_notify: str = "medium"
    timezone: str = "Asia/Shanghai"


def _source_config(data: dict[str, Any] | None, defaults: SourceConfig) -> SourceConfig:
    if not data:
        return defaults
    return SourceConfig(
        enabled=bool(data.get("enabled", defaults.enabled)),
        per_query=int(data.get("per_query", defaults.per_query)),
        delay_seconds=float(data.get("delay_seconds", defaults.delay_seconds)),
        fetch_pages=bool(data.get("fetch_pages", defaults.fetch_pages)),
    )


def load_config(path: str | os.PathLike[str] | None) -> AppConfig:
    cfg = AppConfig()
    if not path or not Path(path).exists():
        return cfg

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    targets_raw = raw.get("targets", {})
    targets: list[str] = []
    if isinstance(targets_raw, dict):
        for key in ("keywords", "domains", "owners", "repos"):
            values = targets_raw.get(key) or []
            if isinstance(values, str):
                values = [values]
            targets.extend(str(v).strip() for v in values if str(v).strip())
    elif isinstance(targets_raw, list):
        targets.extend(str(v).strip() for v in targets_raw if str(v).strip())

    queries = raw.get("queries", {})
    query_templates = queries.get("templates") if isinstance(queries, dict) else None
    target_query_templates = queries.get("target_templates") if isinstance(queries, dict) else None

    sources = raw.get("sources", {})
    cfg.targets = list(dict.fromkeys(targets))
    if query_templates:
        cfg.query_templates = [str(q) for q in query_templates if str(q).strip()]
    if target_query_templates:
        cfg.target_query_templates = [str(q) for q in target_query_templates if str(q).strip()]
    if "max_queries" in raw:
        cfg.max_queries = int(raw["max_queries"])
    if "timezone" in raw:
        cfg.timezone = str(raw["timezone"])
    notify = raw.get("notify", {})
    if isinstance(notify, dict) and notify.get("min_severity"):
        cfg.min_severity_to_notify = str(notify["min_severity"])
    if isinstance(sources, dict):
        cfg.github = _source_config(sources.get("github"), cfg.github)
        cfg.google = _source_config(sources.get("google"), cfg.google)
    return cfg


def build_queries(cfg: AppConfig) -> list[str]:
    queries: list[str] = []
    queries.extend(cfg.query_templates)
    for target in cfg.targets:
        for template in cfg.target_query_templates:
            queries.append(template.format(target=target.replace('"', "")))
    return list(dict.fromkeys(q.strip() for q in queries if q.strip()))[: cfg.max_queries]
