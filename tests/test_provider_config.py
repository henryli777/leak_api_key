from pathlib import Path

from leak_monitor.config import AppConfig, build_queries_by_source
from leak_monitor.csv_export import build_provider_pair_rows, emit_findings_csv
from leak_monitor.detectors import analyze_hit, sha256_text
from leak_monitor.models import SearchHit
from leak_monitor.private_report import build_private_csv_rows
from leak_monitor.report import emit_report
from leak_monitor.safety import verify_public_exports
from leak_monitor.storage import merge_findings


NOW = "2026-07-09T10:00:00+08:00"


def test_api_providers_json_extracts_structured_provider_configs_without_cross_pairing():
    hit = SearchHit(
        source="google_serpapi",
        query='inurl:/api/providers "baseUrl" "apiKey"',
        url="https://service.vendor.ai/api/providers?token=secret-token",
        title="providers",
        content=(
            "["
            '{"name":"openai","baseUrl":"https://api.onevendor.ai/v1",'
            '"apiKey":"sk-one_abcdefghijklmnopqrstuvwxyz123456","models":["gpt-4o"]},'
            '{"name":"openrouter","baseURL":"https:\\/\\/api.twovendor.ai\\/v1",'
            '"apiKey":"sk-or-v1-abcdefghijklmnopqrstuvwxyz123456","models":["gpt-4o-mini"]}'
            "]"
        ),
        fetched_at=NOW,
    )

    findings = analyze_hit(hit, NOW, include_raw=True)
    provider_configs = [item for item in findings if item["type"] == "provider_config"]

    assert len(provider_configs) == 2
    assert {item["provider_name"] for item in provider_configs} == {"openai", "openrouter"}
    assert {item["raw_base_url"] for item in provider_configs} == {
        "https://api.onevendor.ai/v1",
        "https://api.twovendor.ai/v1",
    }
    assert {item["raw_value"] for item in provider_configs} == {
        "sk-one_abcdefghijklmnopqrstuvwxyz123456",
        "sk-or-v1-abcdefghijklmnopqrstuvwxyz123456",
    }
    assert all(item["endpoint_path"] == "/api/providers" for item in provider_configs)
    assert all(item["value_kind"] == "literal" for item in provider_configs)
    assert all(item["public_evidence_level"] == "strong_provider_config" for item in provider_configs)
    assert all(item["base_url_source"] == "provider_config" for item in provider_configs)


def test_provider_config_marks_env_refs_and_placeholders_without_key_hash():
    hit = SearchHit(
        source="github_code",
        query='"/api/providers" "baseUrl" "apiKey"',
        url="https://github.com/acme/app/blob/main/providers.js",
        title="providers.js",
        content="""
        export const providers = [
          { name: "env-provider", baseUrl: "https://api.envvendor.ai/v1", apiKey: process.env.OPENAI_API_KEY },
          { name: "placeholder-provider", baseURL: "https://api.holdervendor.ai/v1", apiKey: "YOUR_API_KEY" }
        ];
        """,
        fetched_at=NOW,
    )

    configs = [item for item in analyze_hit(hit, NOW, include_raw=True) if item["type"] == "provider_config"]

    by_name = {item["provider_name"]: item for item in configs}
    assert by_name["env-provider"]["value_kind"] == "env_ref"
    assert by_name["env-provider"]["key_sha256"] == ""
    assert by_name["env-provider"]["key_redacted"] == "process.env.OPENAI_API_KEY"
    assert by_name["placeholder-provider"]["value_kind"] == "placeholder"
    assert by_name["placeholder-provider"]["key_sha256"] == ""
    assert by_name["placeholder-provider"]["key_redacted"] == "YOUR_API_KEY"


def test_provider_config_non_sk_literal_like_values_are_placeholders():
    hit = SearchHit(
        source="github_code",
        query='"/api/providers" "baseUrl" "apiKey"',
        url="https://github.com/acme/app/blob/main/providers.js",
        title="providers.js",
        content="""
        export const providers = [
          { name: "vendor", baseUrl: "https://api.vendor.ai/v1", apiKey: "AbcDefGhIjKlMnOpQrStUvWxYz1234567890" }
        ];
        """,
        fetched_at=NOW,
    )

    configs = [item for item in analyze_hit(hit, NOW, include_raw=True) if item["type"] == "provider_config"]

    assert configs[0]["value_kind"] == "placeholder"
    assert configs[0]["key_sha256"] == ""
    assert "raw_value" not in configs[0]


def test_provider_pairs_csv_is_pair_level_and_sanitizes_source_url():
    raw_key = "sk-one_abcdefghijklmnopqrstuvwxyz123456"
    item = {
        "id": "provider-one",
        "type": "provider_config",
        "provider": "openai_compatible",
        "provider_name": "openai",
        "severity": "high",
        "endpoint_path": "/api/providers",
        "key_redacted": "sk-one_a...3456",
        "key_sha256": sha256_text(raw_key),
        "base_url_redacted": "https://api...one.test/v1",
        "base_url_sha256": [sha256_text("https://api.onevendor.ai/v1")],
        "base_url_source": "provider_config",
        "public_evidence_level": "strong_provider_config",
        "public_evidence_label": "provider config",
        "value_kind": "literal",
        "models": ["gpt-4o"],
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "seen_count": 1,
        "sources": [
            {
                "source": "google_serpapi",
                "url": "https://service.vendor.ai/api/providers?token=secret-token",
                "title": "providers",
                "query": "q",
            }
        ],
        "raw_value": raw_key,
        "raw_base_url": "https://api.onevendor.ai/v1",
        "raw_base_urls": ["https://api.onevendor.ai/v1"],
    }

    rows = build_provider_pair_rows([item, dict(item, id="duplicate-provider-one")])

    assert len(rows) == 1
    assert rows[0]["provider_name"] == "openai"
    assert rows[0]["endpoint_path"] == "/api/providers"
    assert rows[0]["value_kind"] == "literal"
    assert rows[0]["source_url"] == "https://service.vendor.ai/api/providers"
    assert raw_key not in str(rows)


def test_public_report_outputs_provider_pairs_and_export_safety(tmp_path: Path):
    raw_key = "sk-safe_abcdefghijklmnopqrstuvwxyz123456"
    finding = {
        "id": "provider-safe",
        "type": "provider_config",
        "provider": "openai_compatible",
        "provider_name": "safe",
        "severity": "high",
        "endpoint_path": "/api/providers",
        "key_redacted": "sk-safe_...3456",
        "key_sha256": sha256_text(raw_key),
        "base_url_redacted": "https://api...safe.test/v1",
        "base_url_sha256": [sha256_text("https://api.safevendor.ai/v1")],
        "base_url_source": "provider_config",
        "public_evidence_level": "strong_provider_config",
        "public_evidence_label": "provider config",
        "value_kind": "literal",
        "models": ["gpt-4o"],
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "seen_count": 1,
        "sources": [{"source": "unit", "url": "https://safevendor.ai/api/providers?key=abc", "title": "safe", "query": "q"}],
        "raw_value": raw_key,
        "raw_base_url": "https://api.safevendor.ai/v1",
        "raw_base_urls": ["https://api.safevendor.ai/v1"],
    }

    emit_report(
        tmp_path,
        [finding],
        [finding],
        {"build_time": NOW, "timezone": "Asia/Shanghai", "severity_counts": {"high": 1}},
    )
    emit_findings_csv(tmp_path, [finding])

    assert (tmp_path / "provider_pairs.csv").exists()
    verify_public_exports(tmp_path)
    public_text = (tmp_path / "provider_pairs.csv").read_text(encoding="utf-8-sig")
    assert raw_key not in public_text
    assert "?key=abc" not in public_text


def test_private_csv_includes_provider_config_context_and_raw_values():
    raw_key = "sk-private_abcdefghijklmnopqrstuvwxyz123456"
    rows = build_private_csv_rows(
        [
            {
                "id": "provider-private",
                "type": "provider_config",
                "provider": "openai_compatible",
                "provider_name": "private-provider",
                "endpoint_path": "/api/providers",
                "severity": "high",
                "value_kind": "literal",
                "key_redacted": "sk-private...3456",
                "key_sha256": sha256_text(raw_key),
                "base_url_redacted": "https://api...privatevendor.ai/v1",
                "base_url_sha256": [sha256_text("https://api.privatevendor.ai/v1")],
                "base_url_source": "provider_config",
                "public_evidence_level": "strong_provider_config",
                "models": ["gpt-4o"],
                "first_seen_at": NOW,
                "last_seen_at": NOW,
                "seen_count": 1,
                "sources": [{"source": "unit", "url": "https://privatevendor.ai/api/providers", "title": "providers", "query": "q"}],
                "raw_value": raw_key,
                "raw_base_url": "https://api.privatevendor.ai/v1",
                "raw_base_urls": ["https://api.privatevendor.ai/v1"],
            }
        ]
    )

    assert rows[0]["provider_name"] == "private-provider"
    assert rows[0]["endpoint_path"] == "/api/providers"
    assert rows[0]["value_kind"] == "literal"
    assert rows[0]["api_key"] == raw_key
    assert rows[0]["base_url"] == "https://api.privatevendor.ai/v1"


def test_public_export_safety_rejects_non_sk_literal_key_rows(tmp_path: Path):
    emit_findings_csv(
        tmp_path,
        [
            {
                "id": "groq-provider",
                "type": "provider_config",
                "provider": "groq",
                "provider_name": "groq",
                "endpoint_path": "/api/providers",
                "severity": "high",
                "value_kind": "literal",
                "key_redacted": "gsk_abc...1234",
                "key_sha256": sha256_text("gsk_abcdefghijklmnopqrstuvwxyz1234567890"),
                "base_url_redacted": "https://api...groq.com/openai/v1",
                "base_url_sha256": [sha256_text("https://api.groq.com/openai/v1")],
                "base_url_source": "provider_config",
                "public_evidence_level": "strong_provider_config",
                "models": ["llama-3.1-8b-instant"],
                "first_seen_at": NOW,
                "last_seen_at": NOW,
                "seen_count": 1,
                "sources": [{"source": "unit", "url": "https://vendor.ai/api/providers", "title": "providers", "query": "q"}],
            }
        ],
    )

    try:
        verify_public_exports(tmp_path)
    except ValueError as exc:
        assert "non-sk key_redacted" in str(exc)
    else:
        raise AssertionError("expected non-sk literal key export to fail safety verification")


def test_merge_findings_preserves_provider_config_as_stronger_base_url_source():
    existing = [
        {
            "id": "same-id",
            "type": "credential_pair",
            "provider": "openai_compatible",
            "severity": "high",
            "key_redacted": "sk-old...1234",
            "key_sha256": "keyhash",
            "base_url_redacted": "https://api...example.ai/v1",
            "base_url_sha256": ["basehash"],
            "base_url_source": "same_hit",
            "first_seen_at": NOW,
            "last_seen_at": NOW,
            "seen_count": 1,
            "sources": [],
        }
    ]
    incoming = [dict(existing[0], type="provider_config", base_url_source="provider_config")]

    merged, _ = merge_findings(existing, incoming)

    assert merged[0]["base_url_source"] == "provider_config"


def test_build_queries_by_source_splits_github_and_google_provider_queries():
    queries = build_queries_by_source(AppConfig())

    assert any(q.group == "path_signal" and q.source == "google" and "inurl:/api/providers" in q.text for q in queries)
    assert any(q.group == "provider_config" and q.source == "github" and '"api/providers"' in q.text for q in queries)
    assert any(q.group == "llm_openai_compatible" and q.source == "github" and "OPENAI_API_KEY" in q.text for q in queries)
