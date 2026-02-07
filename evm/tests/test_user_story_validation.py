from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
REFS = ROOT / "references"


def _validator_cmd(stories_path: Path) -> list[str]:
    return [
        sys.executable,
        str(SCRIPTS / "validate_user_stories.py"),
        "--stories",
        str(stories_path),
        "--inventory",
        str(REFS / "rpc-method-inventory.json"),
        "--manifest",
        str(REFS / "method-manifest.json"),
        "--require-full-coverage",
    ]


def test_user_stories_validate_cleanly():
    cmd = _validator_cmd(REFS / "user-stories.json")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["coverage_ratio"] == 1.0


def test_user_stories_detect_invalid_method(tmp_path: Path):
    stories_path = tmp_path / "stories.json"
    stories = json.loads((REFS / "user-stories.json").read_text(encoding="utf-8"))
    stories["stories"][0]["methods"].append("eth_notARealMethod")
    stories_path.write_text(json.dumps(stories, indent=2), encoding="utf-8")

    cmd = _validator_cmd(stories_path)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert any("eth_notARealMethod" in err for err in payload["errors"])
