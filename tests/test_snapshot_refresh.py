import json
from pathlib import Path

import project_support
import pytest


def test_ui_refresh_preserves_snapshot_payloads_and_private_pages(tmp_path):
    import importlib.util
    source = Path(__file__).resolve().parents[1] / "refresh_public_snapshot.py"
    assert source.exists(), "safe snapshot-only UI publication path is missing"
    spec = importlib.util.spec_from_file_location("snapshot_refresh", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    timestamp = "2026-10-08T21:25:26+08:00"
    payloads = {
        "health.json": json.dumps({"build_time": timestamp, "total_findings": 0}),
        "findings.json": "[]\n", "findings.csv": "id,type\n", "provider_pairs.csv": "id,type\n",
        "validation.json": json.dumps({"finished_at": timestamp, "results": []}),
        "private.html": "encrypted original", "private-report.enc": "encrypted bytes",
        "index.html": "<html><head></head><body>old public UI</body></html>",
        "validation.html": "<html><head></head><body>old validation UI</body></html>",
    }
    for name, value in payloads.items():
        (tmp_path / name).write_text(value)
    original = {name: (tmp_path / name).read_bytes() for name in payloads if name not in project_support.PUBLIC_PAGES}
    module.refresh_public_snapshot(tmp_path)
    for name, value in original.items():
        assert (tmp_path / name).read_bytes() == value, name
    for name in project_support.PUBLIC_PAGES:
        text = (tmp_path / name).read_text()
        assert timestamp in text
        assert "report-snapshot" in text and "public-refresh.js" in text
        assert "支持项目" in text
    assert (tmp_path / "public-refresh.js").exists()
    assert "支持项目" in (tmp_path / "404.html").read_text()


def test_source_provenance_requires_successful_collection_verification_and_artifact():
    import refresh_public_snapshot as snapshot
    assert callable(getattr(snapshot, "verify_source_run", None)), "source step provenance gate is missing"
    run = {"id": 123, "head_branch": "main", "path": ".github/workflows/leak-monitor.yml", "conclusion": "failure"}
    steps = [{"name": name, "conclusion": "success"} for name in ("Run leak monitor", "Verify public exports", "Upload report artifact")]
    snapshot.verify_source_run(run, {"jobs": [{"name": "build", "steps": steps}]}, "123")
    with pytest.raises(ValueError):
        snapshot.verify_source_run(run, {"jobs": [{"name": "safe-tests", "steps": []}]}, "123")
    steps[-1]["conclusion"] = "skipped"
    with pytest.raises(ValueError):
        snapshot.verify_source_run(run, {"jobs": [{"name": "build", "steps": steps}]}, "123")
