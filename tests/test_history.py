import json

from leak_monitor import storage
from leak_monitor.pairing import prepare_findings
from leak_monitor import cli
from pathlib import Path


def finding(index):
    return {
        "id": f"finding-{index}", "type": "credential_pair", "provider": "openai_compatible",
        "key_redacted": "sk-valid...abcd", "key_sha256": f"key-{index}",
        "base_url_redacted": "https://api...example.test/v1", "base_url_sha256": ["basehash"],
        "base_url_source": "same_hit", "models": ["gpt-4o"], "severity": "high",
        "first_seen_at": "2026-10-08T10:00:00+08:00", "last_seen_at": "2026-10-08T11:00:00+08:00",
        "seen_count": 2, "sources": [{"source": "unit", "url": "https://example.test/config?api_key=private",
                                     "title": "synthetic", "excerpt": "evidence", "query": "q"}],
    }


def test_shards_bound_bytes_and_preserve_every_dedup_id(tmp_path):
    assert callable(getattr(storage, "write_history", None)), "bounded durable history is missing"
    original = [finding(i) for i in range(30)]
    storage.write_json(tmp_path / "findings.json", original)
    storage.write_history(tmp_path, original, max_shard_bytes=4096)
    shards = list((tmp_path / "history").glob("findings-*.json"))
    assert len(shards) > 1
    assert all(path.stat().st_size <= 4096 for path in shards)
    assert not (tmp_path / "findings.json").exists()
    restored = prepare_findings(storage.read_history(tmp_path), "Asia/Shanghai")
    assert {item["id"] for item in restored} == {f"finding-{i}" for i in range(30)}
    merged, new = storage.merge_findings(restored, [finding(17)])
    assert new == []
    duplicate = next(item for item in merged if item["id"] == "finding-17")
    assert duplicate["seen_count"] == 4
    assert duplicate["first_seen_at"] == "2026-10-08T10:00:00+08:00"
    assert duplicate["base_url_sha256"] == ["basehash"]


def test_legacy_migration_redacts_and_bounds_oversize_evidence(tmp_path):
    assert callable(getattr(storage, "read_history", None)), "legacy history migration is missing"
    item = finding(1)
    secret = "sk-synthetic_abcdefghijklmnopqrstuvwxyz1234567890"
    item.update(raw_value=secret, raw_base_url="https://raw.example.test", unexpected={"credential": secret})
    item["sources"][0].update(excerpt=(secret + " ") * 100000, raw_value=secret, title=secret)
    storage.write_json(tmp_path / "findings.json", [item])
    loaded = storage.read_history(tmp_path)
    assert loaded[0]["id"] == "finding-1"
    storage.write_history(tmp_path, loaded, max_shard_bytes=8192)
    content = "".join(path.read_text() for path in (tmp_path / "history").glob("findings-*.json"))
    assert secret not in content
    assert "raw_value" not in content and "raw_base_url" not in content and "unexpected" not in content
    assert "api_key=private" not in content
    assert len(content.encode()) <= 8192
    restored = storage.read_history(tmp_path)[0]
    assert restored["models"] == ["gpt-4o"]
    assert restored["sources"][0]["url"] == "https://example.test/config"


def test_rewriting_history_removes_stale_shards_and_fails_closed_on_corruption(tmp_path):
    assert callable(getattr(storage, "write_history", None)), "bounded durable history is missing"
    storage.write_history(tmp_path, [finding(i) for i in range(30)], max_shard_bytes=4096)
    storage.write_history(tmp_path, [finding(1)], max_shard_bytes=4096)
    assert len(list((tmp_path / "history").glob("findings-*.json"))) == 1
    assert len(storage.read_history(tmp_path)) == 1
    shard = next((tmp_path / "history").glob("findings-*.json"))
    shard.write_text("truncated")
    try:
        storage.read_history(tmp_path)
    except (ValueError, json.JSONDecodeError):
        pass
    else:
        raise AssertionError("corrupt durable history must not silently reset dedup state")


def test_scan_migrates_legacy_history_without_network_or_changing_snapshot_time(tmp_path, monkeypatch):
    data, output = tmp_path / "data", tmp_path / "dist"
    storage.write_json(data / "findings.json", [finding(1)])
    monkeypatch.setattr(cli, "run_sources", lambda *args: ([], []))
    monkeypatch.setattr(cli, "build_authorized_validation_report_from_env", lambda: ({"results": []}, False))
    monkeypatch.setenv("PRIVATE_REPORT_PASSWORD", "")
    config = Path(__file__).resolve().parents[1] / "config" / "targets.example.yml"
    result = cli.main(["scan", "--config", str(config), "--data-dir", str(data), "--output-dir", str(output)])
    assert result == 0
    assert not (data / "findings.json").exists(), "scan must not recreate oversized monolithic Git history"
    assert storage.read_history(data)[0]["id"] == "finding-1"
    assert json.loads((output / "findings.json").read_text())[0]["first_seen_at"] == "2026-10-08T10:00:00+08:00"
    assert json.loads((data / "last_run.json").read_text()) == json.loads((output / "health.json").read_text())


def test_optional_history_write_failure_keeps_verified_public_report(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_sources", lambda *args: ([], []))
    monkeypatch.setattr(cli, "build_authorized_validation_report_from_env", lambda: ({"results": []}, False))
    monkeypatch.setenv("PRIVATE_REPORT_PASSWORD", "")
    def unavailable(*args, **kwargs):
        raise OSError("synthetic unavailable history disk")
    monkeypatch.setattr(storage, "write_history", unavailable)
    if hasattr(cli, "write_history"):
        monkeypatch.setattr(cli, "write_history", unavailable)
    config = Path(__file__).resolve().parents[1] / "config" / "targets.example.yml"
    result = cli.main(["scan", "--config", str(config), "--data-dir", str(tmp_path / "data"), "--output-dir", str(tmp_path / "dist")])
    assert result == 0
    assert (tmp_path / "dist" / "index.html").is_file()
    assert not (tmp_path / "data" / "findings.json").exists()


def test_old_readonly_readiness_marker_cannot_block_public_report(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    (data / "history-ready").write_text("old")
    original_unlink = Path.unlink
    def readonly_marker(path, *args, **kwargs):
        if path.name == "history-ready":
            raise PermissionError("synthetic readonly marker")
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", readonly_marker)
    monkeypatch.setattr(cli, "run_sources", lambda *args: ([], []))
    monkeypatch.setattr(cli, "build_authorized_validation_report_from_env", lambda: ({"results": []}, False))
    monkeypatch.setenv("PRIVATE_REPORT_PASSWORD", "")
    config = Path(__file__).resolve().parents[1] / "config" / "targets.example.yml"
    assert cli.main(["scan", "--config", str(config), "--data-dir", str(data), "--output-dir", str(tmp_path / "dist")]) == 0
    assert (tmp_path / "dist" / "index.html").is_file()


def test_mixed_case_source_url_never_preserves_query_or_userinfo():
    item = finding(1)
    item["sources"][0]["url"] = "HTTPS://synthetic-user:synthetic-pass@example.test/config?token=private"
    item["sources"][0]["title"] = "HTTPS://synthetic-user:synthetic-pass@example.test/config?token=private"
    redacted = storage.redact_findings([item])[0]
    assert redacted["sources"][0]["url"] == "https://example.test/config"
    assert "synthetic-pass" not in redacted["sources"][0]["title"]
