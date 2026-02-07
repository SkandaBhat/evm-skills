#!/usr/bin/env python3
"""Generate JSON-RPC method inventory from ethereum/execution-apis checkout."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


DEFAULT_SOURCES = [
    "src/eth/*.yaml",
    "src/debug/getters.yaml",
    "src/engine/openrpc/methods/*.yaml",
]


@dataclass
class Entry:
    name: str
    namespace: str
    sources: list[str]


def _git_head(path: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
        )
        return out.strip()
    except Exception:
        return None


def _extract_methods_from_yaml(payload: Any) -> list[str]:
    names: list[str] = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str):
                    names.append(name)
    return names


def build_inventory(source_dir: Path) -> dict[str, Any]:
    by_name: dict[str, set[str]] = {}
    for pattern in DEFAULT_SOURCES:
        for file in sorted(source_dir.glob(pattern)):
            payload = yaml.safe_load(file.read_text(encoding="utf-8"))
            for name in _extract_methods_from_yaml(payload):
                if not name.startswith(("eth_", "debug_", "engine_")):
                    continue
                rel = str(file.relative_to(source_dir))
                by_name.setdefault(name, set()).add(rel)

    entries: list[Entry] = []
    for name in sorted(by_name):
        entries.append(
            Entry(
                name=name,
                namespace=name.split("_", 1)[0],
                sources=sorted(by_name[name]),
            )
        )

    return {
        "source_repository": "https://github.com/ethereum/execution-apis",
        "source_ref": "local-checkout",
        "source_commit": _git_head(source_dir),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "count": len(entries),
        "methods": [entry.__dict__ for entry in entries],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        required=True,
        help="Path to local ethereum/execution-apis checkout",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON path",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    output = Path(args.output).resolve()

    if not source_dir.exists():
        raise SystemExit(f"source dir not found: {source_dir}")

    inventory = build_inventory(source_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "count": inventory["count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
