#!/usr/bin/env python3
"""Build or refresh the command manifest from discovered cast command paths."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


BROADCAST_PATHS = {
    "publish",
    "send",
    "upload-signature",
}

LOCAL_SENSITIVE_PREFIXES = {
    "wallet",
}

LOCAL_SENSITIVE_PATHS = {
    "mktx",
}


def _cast_version(cast_binary: str) -> str:
    proc = subprocess.run([cast_binary, "--version"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return "unknown"
    line = proc.stdout.splitlines()[0].strip() if proc.stdout else "unknown"
    return line or "unknown"


def classify_tier(command_path: str) -> str:
    head = command_path.split(" ", 1)[0]
    if command_path in BROADCAST_PATHS:
        return "broadcast"
    if command_path in LOCAL_SENSITIVE_PATHS:
        return "local-sensitive"
    if head in LOCAL_SENSITIVE_PREFIXES:
        return "local-sensitive"
    return "read"


def _requires_confirmation(tier: str) -> bool:
    return tier in {"local-sensitive", "broadcast"}


def _load_existing(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    return {entry["command_path"]: entry for entry in entries if "command_path" in entry}


def build_entries(discovered_paths: list[str], existing: dict[str, dict]) -> list[dict]:
    entries: list[dict] = []
    for command_path in sorted(discovered_paths):
        tier = classify_tier(command_path)
        previous = existing.get(command_path, {})
        entry = {
            "command_path": command_path,
            "tier": previous.get("tier", tier),
            "enabled": bool(previous.get("enabled", True)),
            "requires_confirmation": bool(
                previous.get("requires_confirmation", _requires_confirmation(tier))
            ),
            "executor": previous.get("executor", "cast_cli"),
            "notes": previous.get("notes", ""),
        }
        entries.append(entry)
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovered", type=Path, required=True, help="discovered path JSON file")
    parser.add_argument("--output", type=Path, required=True, help="manifest output path")
    parser.add_argument("--cast-binary", default="cast", help="cast binary path/name")
    args = parser.parse_args()

    discovered = json.loads(args.discovered.read_text(encoding="utf-8"))
    discovered_paths = discovered.get("all_paths", [])
    if not isinstance(discovered_paths, list):
        raise ValueError("discovered JSON missing list field: all_paths")

    existing = _load_existing(args.output)
    entries = build_entries([str(p) for p in discovered_paths], existing)

    payload = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cast_version": discovered.get("cast_version") or _cast_version(args.cast_binary),
        "source_discovered_file": str(args.discovered),
        "discovered_total_paths": len(discovered_paths),
        "entries": entries,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "ok",
                "output": str(args.output),
                "discovered_paths": len(discovered_paths),
                "manifest_entries": len(entries),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
