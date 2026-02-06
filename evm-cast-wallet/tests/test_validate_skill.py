from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def test_validate_skill_repo_skill():
    cmd = [sys.executable, str(SCRIPTS / "validate_skill.py"), str(ROOT)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Valid skill" in proc.stdout
