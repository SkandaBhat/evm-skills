#!/usr/bin/env python3
"""Validate command-path coverage between discovery, manifest, and wrapper support."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ALLOWED_TIERS = {"read", "local-sensitive", "broadcast"}


def _load_discovered(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    paths = data.get("all_paths", [])
    if not isinstance(paths, list):
        raise ValueError("discovered file missing list: all_paths")
    return sorted(str(p) for p in paths)


def _load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("manifest file missing list: entries")
    return data


def _manifest_paths(manifest: dict) -> list[str]:
    return sorted(str(entry.get("command_path", "")) for entry in manifest.get("entries", []))


def _validate_manifest_entries(manifest: dict) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for entry in manifest.get("entries", []):
        path = entry.get("command_path")
        if not isinstance(path, str) or not path.strip():
            errors.append("entry missing non-empty command_path")
            continue
        if path in seen:
            errors.append(f"duplicate command_path in manifest: {path}")
        seen.add(path)

        tier = entry.get("tier")
        if tier not in ALLOWED_TIERS:
            errors.append(f"invalid tier for {path}: {tier}")

        if not isinstance(entry.get("enabled", True), bool):
            errors.append(f"enabled must be boolean for {path}")

        if not isinstance(entry.get("requires_confirmation", False), bool):
            errors.append(f"requires_confirmation must be boolean for {path}")

        if entry.get("executor") != "cast_cli":
            errors.append(f"unsupported executor for {path}: {entry.get('executor')}")
    return errors


def _wrapper_supported_paths(python_bin: str, wrapper_script: Path, manifest_path: Path) -> list[str]:
    cmd = [
        python_bin,
        str(wrapper_script),
        "supported-paths",
        "--manifest",
        str(manifest_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"wrapper supported-paths failed: {proc.stderr.strip()}")
    payload = json.loads(proc.stdout)
    paths = payload.get("supported_paths", [])
    if not isinstance(paths, list):
        raise ValueError("wrapper supported-paths output missing list: supported_paths")
    return sorted(str(p) for p in paths)


def _diff(left: list[str], right: list[str]) -> tuple[list[str], list[str]]:
    left_set = set(left)
    right_set = set(right)
    return sorted(left_set - right_set), sorted(right_set - left_set)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovered", type=Path, required=True, help="discovered path JSON")
    parser.add_argument("--manifest", type=Path, required=True, help="manifest JSON")
    parser.add_argument(
        "--wrapper-script",
        type=Path,
        default=(Path(__file__).resolve().parent / "evm_cast.py"),
        help="wrapper script path",
    )
    parser.add_argument("--python-bin", default=sys.executable, help="python executable for wrapper")
    parser.add_argument("--fail-on-extra", action="store_true", help="fail on extra manifest paths")
    args = parser.parse_args()

    discovered = _load_discovered(args.discovered.resolve())
    manifest = _load_manifest(args.manifest.resolve())
    manifest_paths = _manifest_paths(manifest)
    wrapper_paths = _wrapper_supported_paths(
        args.python_bin, args.wrapper_script.resolve(), args.manifest.resolve()
    )

    manifest_errors = _validate_manifest_entries(manifest)
    missing_in_manifest, extra_in_manifest = _diff(discovered, manifest_paths)
    missing_in_wrapper, extra_in_wrapper = _diff(discovered, wrapper_paths)

    failures: list[str] = []
    failures.extend(manifest_errors)
    if missing_in_manifest:
        failures.append(f"missing_in_manifest={len(missing_in_manifest)}")
    if args.fail_on_extra and extra_in_manifest:
        failures.append(f"extra_in_manifest={len(extra_in_manifest)}")
    if missing_in_wrapper:
        failures.append(f"missing_in_wrapper={len(missing_in_wrapper)}")
    if args.fail_on_extra and extra_in_wrapper:
        failures.append(f"extra_in_wrapper={len(extra_in_wrapper)}")

    payload = {
        "discovered_count": len(discovered),
        "manifest_count": len(manifest_paths),
        "wrapper_count": len(wrapper_paths),
        "missing_in_manifest": missing_in_manifest,
        "extra_in_manifest": extra_in_manifest,
        "missing_in_wrapper": missing_in_wrapper,
        "extra_in_wrapper": extra_in_wrapper,
        "manifest_errors": manifest_errors,
        "ok": len(failures) == 0,
    }
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
