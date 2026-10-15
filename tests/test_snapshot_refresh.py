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


def test_publication_guard_requires_own_current_main_and_latest_available_report():
    import refresh_public_snapshot as snapshot
    run = {"id": 123, "repository": {"full_name": "owner/project", "id": 77},
           "head_branch": "main", "head_sha": "collection-sha", "status": "completed",
           "path": ".github/workflows/leak-monitor.yml", "conclusion": "success"}
    jobs = {"jobs": [{"name": "build", "steps": [{"name": name, "conclusion": "success"}
             for name in ("Run leak monitor", "Verify public exports", "Upload report artifact")]}]}
    artifact = {"id": 456, "name": "leak-monitor-report", "expired": False,
                "workflow_run": {"id": 123, "head_branch": "main", "head_sha": "collection-sha",
                                 "repository_id": 77, "head_repository_id": 77}}
    kwargs = dict(repository="owner/project", ref="refs/heads/main", checkout_sha="ui-sha", current_sha="ui-sha")
    snapshot.verify_publication_state(run, jobs, {"artifacts": [artifact]}, "123", **kwargs)
    for change in ({"repository": "other/project"}, {"ref": "refs/heads/feature"}, {"current_sha": "new-ui-sha"}):
        with pytest.raises(ValueError):
            snapshot.verify_publication_state(run, jobs, {"artifacts": [artifact]}, "123", **(kwargs | change))
    for unavailable in ({}, {"expired": True}, {"workflow_run": artifact["workflow_run"] | {"head_repository_id": 88}}):
        with pytest.raises(ValueError):
            snapshot.verify_publication_state(run, jobs, {"artifacts": [artifact | unavailable] if unavailable else []}, "123", **kwargs)
    newer = artifact | {"id": 457, "workflow_run": artifact["workflow_run"] | {"id": 124}}
    with pytest.raises(ValueError):
        snapshot.verify_publication_state(run, jobs, {"artifacts": [artifact, newer]}, "123", **kwargs)
