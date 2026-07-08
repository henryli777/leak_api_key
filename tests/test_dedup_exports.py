from leak_monitor.csv_export import build_csv_rows
from leak_monitor.detectors import analyze_hit
from leak_monitor.models import SearchHit
from leak_monitor.pairing import prepare_findings
from leak_monitor.private_report import build_private_csv_rows
from scripts.validate_authorized_models import collect_secret_base_urls, load_secrets


def pair(row_id: str, key_hash: str, base_url: str, base_hash: str, source: str = "historical_fallback"):
    return {
        "id": row_id,
        "type": "credential_pair",
        "provider": "openai_compatible",
        "severity": "high",
        "key_redacted": "sk-test...abcd",
        "key_sha256": key_hash,
        "base_url_redacted": base_url.replace("https://", "https://redacted."),
        "base_url_sha256": [base_hash],
        "base_url_source": source,
        "public_evidence_level": "candidate",
        "models": ["gpt-4o", "gpt-4o-mini"],
        "first_seen_at": "2026-07-07T10:00:00+08:00",
        "last_seen_at": "2026-07-07T11:00:00+08:00",
        "seen_count": 1,
        "sources": [{"source": "github_code", "url": f"https://example.test/{row_id}", "title": row_id, "query": "q"}],
        "raw_value": "sk-test-abcdefghijklmnopqrstuvwxyz",
        "raw_base_url": base_url,
        "raw_base_urls": [base_url],
    }


def test_public_csv_groups_repeated_key_with_multiple_base_urls():
    rows = build_csv_rows(
        [
            pair("a", "keyhash", "https://api.one.test/v1", "basehash1"),
            pair("b", "keyhash", "https://api.two.test/v1", "basehash2"),
        ]
    )

    assert len(rows) == 1
    assert rows[0]["key_sha256"] == "keyhash"
    assert rows[0]["base_url_sha256"] == "basehash1, basehash2"
    assert "https://redacted.api.one.test/v1" in rows[0]["base_url_redacted"]
    assert "https://redacted.api.two.test/v1" in rows[0]["base_url_redacted"]
    assert rows[0]["deduped_finding_count"] == "2"


def test_private_csv_groups_raw_key_and_raw_base_urls():
    rows = build_private_csv_rows(
        [
            pair("a", "keyhash", "https://api.one.test/v1", "basehash1"),
            pair("b", "keyhash", "https://api.two.test/v1", "basehash2"),
        ]
    )

    assert len(rows) == 1
    assert rows[0]["api_key"] == "sk-test-abcdefghijklmnopqrstuvwxyz"
    assert rows[0]["base_url"] == "https://api.one.test/v1\nhttps://api.two.test/v1"
    assert rows[0]["deduped_finding_count"] == "2"


def test_private_csv_does_not_put_base_url_raw_value_in_api_key():
    rows = build_private_csv_rows(
        [
            {
                "id": "base",
                "type": "base_url",
                "provider": "openai_compatible",
                "severity": "medium",
                "value_redacted": "https://api...example.test/v1",
                "value_sha256": "basehash",
                "base_urls_redacted": ["https://api...example.test/v1"],
                "base_url_sha256": ["basehash"],
                "raw_value": "https://api.example.test/v1",
                "raw_base_urls": ["https://api.example.test/v1"],
                "models": ["gpt-4o"],
                "first_seen_at": "2026-07-07T10:00:00+08:00",
                "last_seen_at": "2026-07-07T11:00:00+08:00",
                "seen_count": 1,
                "sources": [],
            }
        ]
    )

    assert rows[0]["api_key"] == ""
    assert rows[0]["base_url"] == "https://api.example.test/v1"


def test_detector_keeps_supported_ai_api_key_prefixes():
    hit = SearchHit(
        source="unit",
        query="q",
        url="https://example.test",
        title="mixed keys",
        snippet=(
            "OPENAI_API_KEY=sk-valid_abcdefghijklmnopqrstuvwxyz "
            "GOOGLE_API_KEY=AIzaSyCQabcdefghijklmnopqrstuvwxyz1234567890 "
            "GROQ_API_KEY=gsk_abcdefghijklmnopqrstuvwxyz1234567890 "
            "base_url=https://api.example.test/v1 model=gpt-4o"
        ),
        fetched_at="2026-07-07T10:00:00+08:00",
    )

    findings = analyze_hit(hit, "2026-07-07T10:00:00+08:00", include_raw=True)

    raw_values = {item.get("raw_value") for item in findings if item.get("type") == "credential"}
    assert raw_values == {
        "sk-valid_abcdefghijklmnopqrstuvwxyz",
        "AIzaSyCQabcdefghijklmnopqrstuvwxyz1234567890",
        "gsk_abcdefghijklmnopqrstuvwxyz1234567890",
    }


def test_prepare_findings_keeps_supported_ai_credentials():
    rows = prepare_findings(
        [
            {
                "id": "google-key",
                "type": "credential_pair",
                "provider": "google",
                "severity": "high",
                "key_redacted": "AIzaSyCQ...rDF8",
                "key_sha256": "googlehash",
                "base_url_redacted": "https://api...example.test/v1",
                "base_url_sha256": ["basehash"],
                "first_seen_at": "2026-07-07T10:00:00+08:00",
                "last_seen_at": "2026-07-07T11:00:00+08:00",
                "sources": [],
            },
            {
                "id": "sk-key",
                "type": "credential_pair",
                "provider": "openai_compatible",
                "severity": "high",
                "key_redacted": "sk-valid...abcd",
                "key_sha256": "skhash",
                "base_url_redacted": "https://api...example.test/v1",
                "base_url_sha256": ["basehash"],
                "first_seen_at": "2026-07-07T10:00:00+08:00",
                "last_seen_at": "2026-07-07T11:00:00+08:00",
                "sources": [],
            },
            {
                "id": "base",
                "type": "base_url",
                "provider": "openai_compatible",
                "severity": "medium",
                "value_redacted": "https://api...example.test/v1",
                "value_sha256": "basehash",
                "first_seen_at": "2026-07-07T10:00:00+08:00",
                "last_seen_at": "2026-07-07T11:00:00+08:00",
                "sources": [],
            },
        ],
        "Asia/Shanghai",
    )

    assert [row["id"] for row in rows] == ["google-key", "sk-key", "base"]


def test_local_validator_splits_multiline_base_urls_from_grouped_private_csv(tmp_path):
    secrets_path = tmp_path / "secrets.csv"
    secrets_path.write_text(
        "api_key,key_sha256,base_url,models\n"
        '"sk-test-abcdefghijklmnopqrstuvwxyz","keyhash","https://api.one.test/v1\nhttps://api.two.test/v1","gpt-4o"\n',
        encoding="utf-8",
    )

    secrets = load_secrets(secrets_path)
    base_urls = collect_secret_base_urls(secrets)

    assert len(secrets["keyhash"]) == 2
    assert [row["base_url"] for row in secrets["keyhash"]] == ["https://api.one.test/v1", "https://api.two.test/v1"]
    assert [row["base_url"] for row in base_urls] == ["https://api.one.test/v1", "https://api.two.test/v1"]
