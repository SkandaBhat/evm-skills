from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
REFS = ROOT / "references"


def test_discovery_smoke(tmp_path: Path):
    discovered = tmp_path / "discovered.json"
    cmd = [
        sys.executable,
        str(SCRIPTS / "discover_cast_tree.py"),
        "--output",
        str(discovered),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(discovered.read_text(encoding="utf-8"))
    assert payload["total_paths"] > 0
    assert "address-zero" in payload["all_paths"]


def test_coverage_check_with_repo_manifest():
    discovered = REFS / "discovered-cast-paths.json"
    manifest = REFS / "command-manifest.json"
    if not discovered.exists() or not manifest.exists():
        raise AssertionError("expected discovered and manifest files to exist")

    cmd = [
        sys.executable,
        str(SCRIPTS / "check_coverage.py"),
        "--discovered",
        str(discovered),
        "--manifest",
        str(manifest),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
