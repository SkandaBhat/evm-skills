from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module(module_name: str, filename: Path):
    spec = importlib.util.spec_from_file_location(module_name, filename)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_policy_eval_tiers():
    policy_eval = _load_module("policy_eval", SCRIPTS / "policy_eval.py")
    manifest = {
        "read-cmd": {"command_path": "read-cmd", "tier": "read", "enabled": True},
        "local-cmd": {
            "command_path": "local-cmd",
            "tier": "local-sensitive",
            "enabled": True,
            "requires_confirmation": True,
        },
        "broadcast-cmd": {
            "command_path": "broadcast-cmd",
            "tier": "broadcast",
            "enabled": True,
            "requires_confirmation": True,
        },
    }

    assert policy_eval.evaluate_policy(manifest, "read-cmd", {})["allowed"] is True
    assert policy_eval.evaluate_policy(manifest, "local-cmd", {})["allowed"] is False
    assert policy_eval.evaluate_policy(
        manifest,
        "local-cmd",
        {"allow_local_sensitive": True, "confirmation_token": "ok"},
    )["allowed"] is True
    assert policy_eval.evaluate_policy(
        manifest,
        "broadcast-cmd",
        {"allow_broadcast": True, "confirmation_token": "ok"},
    )["allowed"] is True


def test_wrapper_exec_read_command():
    manifest_path = ROOT / "references" / "command-manifest.json"
    if not manifest_path.exists():
        raise AssertionError("expected generated manifest to exist for wrapper test")

    request = {
        "command_path": "address-zero",
        "args": [],
        "context": {},
        "timeout_seconds": 20,
    }

    cmd = [
        sys.executable,
        str(SCRIPTS / "evm_cast.py"),
        "exec",
        "--manifest",
        str(manifest_path),
        "--request-json",
        json.dumps(request),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["status"] == "ok"
    assert payload["command_path"] == "address-zero"

