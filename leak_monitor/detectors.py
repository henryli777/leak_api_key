from __future__ import annotations

import hashlib
import html
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from .models import SearchHit
from .timeutils import now_iso as current_time_iso


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openrouter", re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{20,}\b")),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("google", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b")),
    ("openai_compatible", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
]

ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?P<name>
        OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|GEMINI_API_KEY|
        DEEPSEEK_API_KEY|OPENROUTER_API_KEY|GROQ_API_KEY|MISTRAL_API_KEY|
        DASHSCOPE_API_KEY|QWEN_API_KEY|XAI_API_KEY|API_KEY
    )\b
    \s*[:=]\s*
    (?P<quote>["']?)
    (?P<value>[A-Za-z0-9._:/+=@-]{16,})
    (?P=quote)
    """
)

BASE_URL_RE = re.compile(
    r"""(?ix)
    \b(?:
        base_url|baseURL|baseUrl|api_base|apiBase|OPENAI_BASE_URL|
        OPENAI_API_BASE|AZURE_OPENAI_ENDPOINT|endpoint|api_url|apiUrl
    )\b
    \s*[:=]\s*
    (?P<quote>["']?)
    (?P<url>https?://[^\s"'`<>{}\]\)]+)
    (?P=quote)
    """
)

LOOSE_AI_URL_RE = re.compile(
    r"""(?ix)
    https?://[^\s"'`<>{}\]\)]+/(?:v1|openai|anthropic|chat/completions|models)\b[^\s"'`<>{}\]\)]*
    """
)

MODEL_RE = re.compile(
    r"""(?ix)\b(
        gpt-[A-Za-z0-9._-]+|o[134](?:-[A-Za-z0-9._-]+)?|
        claude-[A-Za-z0-9._-]+|deepseek-[A-Za-z0-9._-]+|
        gemini-[A-Za-z0-9._-]+|qwen[A-Za-z0-9._-]*|
        glm-[A-Za-z0-9._-]+|llama-?[A-Za-z0-9._-]*|
        grok-[A-Za-z0-9._-]+|mistral-[A-Za-z0-9._-]+|
        kimi-[A-Za-z0-9._-]+
    )\b"""
)

PROVIDER_BY_NAME = {
    "OPENAI_API_KEY": "openai_compatible",
    "ANTHROPIC_API_KEY": "anthropic",
    "GOOGLE_API_KEY": "google",
    "GEMINI_API_KEY": "google",
    "DEEPSEEK_API_KEY": "deepseek",
    "OPENROUTER_API_KEY": "openrouter",
    "GROQ_API_KEY": "groq",
    "MISTRAL_API_KEY": "mistral",
    "DASHSCOPE_API_KEY": "dashscope",
    "QWEN_API_KEY": "dashscope",
    "XAI_API_KEY": "xai",
    "API_KEY": "unknown",
}

PLACEHOLDER_HINTS = (
    "your_",
    "your-",
    "example",
    "placeholder",
    "replace",
    "changeme",
    "xxx",
    "test_key",
    "demo_key",
    "${",
    "<",
    ">",
)

REFERENCE_VALUE_HINTS = (
    "api_key",
    "_key",
    "secret_key",
    "access_token",
    "bearer_token",
    "os.environ",
    "process.env",
    "getenv",
    "env:",
    "settings.",
    "config.",
)

AI_CONTEXT_TERMS = (
    "openai",
    "anthropic",
    "claude",
    "deepseek",
    "gemini",
    "gpt",
    "model",
    "chat/completions",
    "openrouter",
    "groq",
    "mistral",
    "dashscope",
    "qwen",
    "grok",
    "llm",
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def redact_secret(value: str) -> str:
    if len(value) <= 12:
        return "***"
    return f"{value[:8]}...{value[-4:]}"


def redact_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return value[:24] + "..." if len(value) > 28 else value
    host = parsed.netloc
    if "." in host:
        first, rest = host.split(".", 1)
        host = f"{first[:3]}...{rest}" if rest else f"{first[:3]}..."
    elif len(host) > 8:
        host = f"{host[:4]}..."
    safe_path = parsed.path
    if len(safe_path) > 24:
        safe_path = safe_path[:24] + "..."
    return urlunparse((parsed.scheme, host, safe_path, "", "", ""))


def clean_url(value: str) -> str:
    return value.strip().rstrip(".,;')")


def looks_like_secret(value: str) -> bool:
    low = value.lower()
    if len(value) < 16 or any(hint in low for hint in PLACEHOLDER_HINTS):
        return False
    if any(hint in low for hint in REFERENCE_VALUE_HINTS):
        return False
    if re.fullmatch(r"[A-Z0-9_]+", value) and value.endswith("_KEY"):
        return False
    if value.startswith(("http://", "https://")):
        return False
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    if len(set(compact)) < 8:
        return False
    return True


def looks_like_generic_secret(value: str) -> bool:
    low = value.lower()
    if any(word in low for word in ("request", "response", "payload", "sample", "dummy", "another", "different")):
        return False
    if not re.search(r"\d", value):
        return False
    if not re.search(r"[A-Z]", value):
        return False
    return True


def normalize_excerpt(text: str, max_len: int = 360, mask: bool = True) -> str:
    clean = re.sub(r"\s+", " ", text or "").strip()
    if mask:
        clean = mask_sensitive_text(clean)
    if len(clean) > max_len:
        clean = clean[: max_len - 3] + "..."
    return html.unescape(clean)


def mask_sensitive_text(text: str) -> str:
    out = text or ""
    for _, pattern in SECRET_PATTERNS:
        out = pattern.sub(lambda m: redact_secret(m.group(0)), out)
    out = ASSIGNMENT_RE.sub(
        lambda m: f"{m.group('name')}={redact_secret(m.group('value'))}",
        out,
    )
    return out


def _severity(secret_count: int, base_url_count: int, model_count: int) -> str:
    if secret_count and base_url_count:
        return "high"
    if secret_count:
        return "high"
    if base_url_count and model_count:
        return "medium"
    if base_url_count:
        return "medium"
    return "low"


def _dedup(values: list[str], limit: int = 20) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))[:limit]


def analyze_hit(hit: SearchHit, now_iso: str | None = None, include_raw: bool = False) -> list[dict[str, Any]]:
    now_iso = now_iso or current_time_iso()
    text = "\n".join(part for part in [hit.title, hit.snippet, hit.content] if part)
    low_text = text.lower()

    secret_matches_by_value: dict[str, str] = {}
    for provider, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if looks_like_secret(value):
                secret_matches_by_value.setdefault(value, provider)

    for match in ASSIGNMENT_RE.finditer(text):
        value = match.group("value").strip().strip(",")
        if looks_like_secret(value):
            provider = PROVIDER_BY_NAME.get(match.group("name").upper(), "unknown")
            if provider == "unknown" and not looks_like_generic_secret(value):
                continue
            secret_matches_by_value.setdefault(value, provider)

    secret_matches = [(provider, value) for value, provider in secret_matches_by_value.items()]

    base_urls = [clean_url(m.group("url")) for m in BASE_URL_RE.finditer(text)]
    if any(term in low_text for term in AI_CONTEXT_TERMS):
        base_urls.extend(clean_url(m.group(0)) for m in LOOSE_AI_URL_RE.finditer(text))
    base_urls = _dedup(base_urls)

    models = _dedup([m.group(1) for m in MODEL_RE.finditer(text)], limit=15)
    severity = _severity(len(secret_matches), len(base_urls), len(models))
    if severity == "low" and not models:
        return []

    excerpt = normalize_excerpt(text, mask=not include_raw)
    base_url_redacted = [redact_url(u) for u in base_urls]
    base_url_hashes = [sha256_text(u) for u in base_urls]
    findings: list[dict[str, Any]] = []

    for packed in _dedup([f"{p}\0{v}" for p, v in secret_matches]):
        provider_name, raw_value = packed.split("\0", 1)
        value_hash = sha256_text(raw_value)
        finding_id = sha256_text(f"credential:{provider_name}:{value_hash}")[:20]
        finding = {
                "id": finding_id,
                "type": "credential",
                "provider": provider_name,
                "severity": severity,
                "value_redacted": redact_secret(raw_value),
                "value_sha256": value_hash,
                "base_urls_redacted": base_url_redacted,
                "base_url_sha256": base_url_hashes,
                "models": models,
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "seen_count": 1,
                "sources": [
                    {
                        "source": hit.source,
                        "query": hit.query,
                        "url": hit.url,
                        "title": hit.title,
                        "excerpt": excerpt,
                        "fetched_at": hit.fetched_at or now_iso,
                    }
                ],
            }
        if include_raw:
            finding["raw_value"] = raw_value
            finding["raw_base_urls"] = base_urls
        findings.append(finding)

    if base_urls and not findings:
        for raw_url in base_urls:
            value_hash = sha256_text(raw_url)
            finding_id = sha256_text(f"base_url:{value_hash}")[:20]
            finding = {
                    "id": finding_id,
                    "type": "base_url",
                    "provider": "openai_compatible",
                    "severity": severity,
                    "value_redacted": redact_url(raw_url),
                    "value_sha256": value_hash,
                    "base_urls_redacted": [redact_url(raw_url)],
                    "base_url_sha256": [value_hash],
                    "models": models,
                    "first_seen_at": now_iso,
                    "last_seen_at": now_iso,
                    "seen_count": 1,
                    "sources": [
                        {
                            "source": hit.source,
                            "query": hit.query,
                            "url": hit.url,
                            "title": hit.title,
                            "excerpt": excerpt,
                            "fetched_at": hit.fetched_at or now_iso,
                        }
                    ],
                }
            if include_raw:
                finding["raw_value"] = raw_url
                finding["raw_base_urls"] = [raw_url]
            findings.append(finding)

    return findings
