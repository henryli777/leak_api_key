"""Read-only GitHub provenance and freshness gate for UI-only publication."""

import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from refresh_public_snapshot import verify_publication_state


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


if __name__ == "__main__":
    repository = os.environ["GITHUB_REPOSITORY"]
    source = os.environ["SOURCE_RUN_ID"]
    if not source.isdecimal():
        raise ValueError("source run ID must be numeric")
    run = api(f"repos/{repository}/actions/runs/{source}")
    jobs = api(f"repos/{repository}/actions/runs/{source}/jobs?per_page=100")
    artifacts = api(f"repos/{repository}/actions/artifacts?per_page=100")
    current = api(f"repos/{repository}/git/ref/heads/main")["object"]["sha"]
    verify_publication_state(run, jobs, artifacts, source, repository=repository,
                             ref=os.environ["GITHUB_REF"], checkout_sha=os.environ["GITHUB_SHA"], current_sha=current)
    print("Verified newest original report from collection run", source)
