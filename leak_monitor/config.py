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
    'inurl:/api/providers "baseUrl" "apiKey"',
    'inurl:/api/providers "baseURL" "apiKey"',
    'inurl:/api/providers "base_url" "api_key"',
    'inurl:/api/providers "sk-"',
    '"api/providers" "baseUrl" "apiKey"',
    '"api/providers" "baseUrl" "sk-"',
    '"api/providers" "models" "baseUrl"',
    '"ANTHROPIC_API_KEY" "claude"',
    '"DEEPSEEK_API_KEY" "deepseek"',
    '"OPENROUTER_API_KEY" "sk-or-v1"',
    '"MISTRAL_API_KEY"',
    '"DASHSCOPE_API_KEY" "qwen"',
    '"grok" "base_url" "sk-"',
]

DEFAULT_SOURCE_QUERY_GROUPS: dict[str, dict[str, list[str]]] = {
    "github": {
        "llm_openai_compatible": [
            '"OPENAI_API_KEY" "OPENAI_BASE_URL"',
            '"OPENAI_API_KEY=" "sk-"',
            '"OPENAI_API_KEY:" "sk-"',
            '"Authorization: Bearer sk-"',
            '"api_key" "sk-" "base_url"',
            '"baseURL" "apiKey" "sk-"',
            '"chat/completions" "sk-"',
            '"v1/models" "sk-"',
        ],
        "provider_config": [
            '"/api/providers" "baseUrl" "apiKey"',
            '"api/providers" "baseURL" "apiKey"',
            '"api/providers" "base_url" "api_key"',
            '"providers" "baseUrl" "apiKey" "models"',
        ],
        "path_signal": [
            '"/api/providers" "sk-"',
            '"api/providers" "OPENAI_BASE_URL"',
        ],
    },
    "google": {
        "path_signal": [
            'inurl:/api/providers "baseUrl" "apiKey"',
            'inurl:/api/providers "baseURL" "apiKey"',
            'inurl:/api/providers "base_url" "api_key"',
            'inurl:/api/providers "sk-"',
        ],
        "provider_config": [
            '"/api/providers" "baseUrl" "apiKey"',
            '"api/providers" "baseURL" "apiKey"',
            '"api/providers" "models" "baseUrl"',
        ],
        "llm_openai_compatible": [
            '"OPENAI_API_KEY=" "sk-"',
            '"Authorization: Bearer sk-"',
            '"base_url" "https://" "sk-"',
        ],
    },
}

TARGET_QUERY_TEMPLATES = [
    '"{target}" "OPENAI_API_KEY" "sk-"',
    '"{target}" "OPENAI_BASE_URL" "https://"',
    '"{target}" "base_url" "sk-"',
    '"{target}" "baseURL" "apiKey"',
    '"{target}" "api_base" "https://"',
    '"{target}" "Authorization: Bearer sk-"',
    '"{target}" "chat/completions" "sk-"',
    '"{target}" "v1/models" "sk-"',
    '"{target}" "api/providers" "baseUrl" "apiKey"',
    '"{target}" "api/providers" "baseUrl" "sk-"',
    '"{target}" inurl:/api/providers "apiKey"',
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
    source_query_groups: dict[str, dict[str, list[str]]] = field(
        default_factory=lambda: {
            source: {group: list(values) for group, values in groups.items()}
            for source, groups in DEFAULT_SOURCE_QUERY_GROUPS.items()
        }
    )
    max_queries: int = 36
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
    source_groups = queries.get("source_groups") if isinstance(queries, dict) else None

    sources = raw.get("sources", {})
    cfg.targets = list(dict.fromkeys(targets))
    if query_templates:
        cfg.query_templates = [str(q) for q in query_templates if str(q).strip()]
    if target_query_templates:
        cfg.target_query_templates = [str(q) for q in target_query_templates if str(q).strip()]
    if isinstance(source_groups, dict):
        cfg.source_query_groups = _source_query_groups(source_groups, cfg.source_query_groups)
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


@dataclass(frozen=True, slots=True)
class SearchQuery:
    source: str
    group: str
    text: str


def build_queries_by_source(cfg: AppConfig) -> list[SearchQuery]:
    queries: list[SearchQuery] = []
    for source, groups in cfg.source_query_groups.items():
        for group, templates in groups.items():
            for template in templates:
                if template and str(template).strip():
                    queries.append(SearchQuery(source=source, group=group, text=str(template).strip()))
            for target in cfg.targets:
                for template in cfg.target_query_templates:
                    text = template.format(target=target.replace('"', ""))
                    if text.strip():
                        queries.append(SearchQuery(source=source, group=group, text=text.strip()))

    if not queries:
        for query in build_queries(cfg):
            queries.append(SearchQuery(source="all", group="legacy", text=query))

    out: list[SearchQuery] = []
    seen: set[tuple[str, str, str]] = set()
    for item in queries:
        key = (item.source, item.group, item.text)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= cfg.max_queries:
            break
    return out


def _source_query_groups(
    raw: dict[str, Any],
    defaults: dict[str, dict[str, list[str]]],
) -> dict[str, dict[str, list[str]]]:
    out = {
        source: {group: list(values) for group, values in groups.items()}
        for source, groups in defaults.items()
    }
    for source, groups in raw.items():
        if not isinstance(groups, dict):
            continue
        source_key = str(source).strip()
        out[source_key] = {}
        for group, values in groups.items():
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            out[source_key][str(group).strip()] = [str(v).strip() for v in values if str(v).strip()]
    return out
