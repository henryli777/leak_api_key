"""Update public HTML/client assets using a previously verified snapshot, without collection."""

import argparse
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import shutil

from leak_monitor.authorized_validator import render_validation_html
from leak_monitor.report import render_html
from leak_monitor.safety import verify_public_exports
from project_support import PUBLIC_PAGES, apply_to_directory


def verify_source_run(run, jobs, run_id):
    if (str(run.get("id")) != str(run_id) or run.get("head_branch") != "main"
            or run.get("path") != ".github/workflows/leak-monitor.yml"
            or run.get("conclusion") not in {"success", "failure"}):
        raise ValueError("source must be a completed original main-branch collection workflow")
    required = {"Run leak monitor", "Verify public exports", "Upload report artifact"}
    for job in jobs.get("jobs", []):
        completed = {step.get("name") for step in job.get("steps", []) if step.get("conclusion") == "success"}
        if job.get("name") == "build" and required <= completed:
            return
    raise ValueError("source lacks successful collection, public export verification, or report artifact upload")


def verify_publication_state(run, jobs, artifacts, run_id, *, repository, ref, checkout_sha, current_sha):
    verify_source_run(run, jobs, run_id)
    if (ref != "refs/heads/main" or not checkout_sha or checkout_sha != current_sha
            or run.get("repository", {}).get("full_name") != repository or run.get("status") != "completed"):
        raise ValueError("UI publication requires this repository's unchanged current main branch")
    repository_id = run["repository"].get("id")
    reports = [artifact for artifact in artifacts.get("artifacts", [])
               if artifact.get("name") == "leak-monitor-report" and not artifact.get("expired")
               and artifact.get("workflow_run", {}).get("head_branch") == "main"
               and artifact.get("workflow_run", {}).get("repository_id") == repository_id
               and artifact.get("workflow_run", {}).get("head_repository_id") == repository_id]
    if not repository_id or not reports:
        raise ValueError("no unexpired original public report is available")
    latest = max(reports, key=lambda artifact: int(artifact["id"]))
    if (str(latest["workflow_run"].get("id")) != str(run_id)
            or latest["workflow_run"].get("head_sha") != run.get("head_sha")):
        raise ValueError("a newer public report exists; refusing to overwrite it with an older snapshot")


def refresh_public_snapshot(directory):
    root = Path(directory)
    verify_public_exports(root)
    allowed = {*PUBLIC_PAGES, "404.html", "public-refresh.js"}
    original = {path.relative_to(root): sha256(path.read_bytes()).hexdigest()
                for path in root.rglob("*") if path.is_file() and str(path.relative_to(root)) not in allowed}
    health = json.loads((root / "health.json").read_text(encoding="utf-8"))
    if not health.get("build_time") or datetime.fromisoformat(health["build_time"]).utcoffset() is None:
        raise ValueError("snapshot must retain its original timezone-aware collection timestamp")
    findings = json.loads((root / "findings.json").read_text(encoding="utf-8"))
    if not isinstance(findings, list):
        raise ValueError("snapshot findings must be a list")
    validation_path = root / "validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8")) if validation_path.exists() else None
    if (root / "validation.html").exists() and not validation:
        raise ValueError("existing validation page requires its original validation payload")
    (root / "index.html").write_text(render_html(findings, health, validation), encoding="utf-8")
    if validation is not None:
        (root / "validation.html").write_text(render_validation_html(validation), encoding="utf-8")
    shutil.copyfile(Path(__file__).parent / "leak_monitor" / "public-refresh.js", root / "public-refresh.js")
    apply_to_directory(root)
    verify_public_exports(root)
    for name, digest in original.items():
        if sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"snapshot payload unexpectedly changed: {name}")
    print("Public UI updated; original data, validation times and private files preserved.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    refresh_public_snapshot(parser.parse_args().directory)
