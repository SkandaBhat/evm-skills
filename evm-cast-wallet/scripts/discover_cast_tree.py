#!/usr/bin/env python3
"""Discover cast command paths by recursively parsing `--help` output."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


COMMAND_LINE_RE = re.compile(r"^\s{2,}([a-z0-9][a-z0-9-]*)\s{2,}.*$")


def _run_help(cast_binary: str, path: tuple[str, ...]) -> str:
    cmd = [cast_binary, *path, "--help"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Failed to run {' '.join(cmd)} (exit={proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def _parse_subcommands(help_text: str) -> list[str]:
    subs: list[str] = []
    in_commands = False
    for line in help_text.splitlines():
        stripped = line.strip()
        if stripped == "Commands:":
            in_commands = True
            continue

        if not in_commands:
            continue

        if stripped.startswith("Options:"):
            break

        match = COMMAND_LINE_RE.match(line)
        if not match:
            if line and not line.startswith(" "):
                break
            continue

        name = match.group(1)
        if name != "help":
            subs.append(name)

    return sorted(set(subs))


def _cast_version(cast_binary: str) -> str:
    proc = subprocess.run([cast_binary, "--version"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return "unknown"
    first_line = proc.stdout.splitlines()[0].strip() if proc.stdout else "unknown"
    return first_line or "unknown"


def discover_paths(cast_binary: str, max_depth: int) -> list[str]:
    queue: deque[tuple[str, ...]] = deque([()])
    seen: set[tuple[str, ...]] = {()}
    all_paths: list[tuple[str, ...]] = []

    while queue:
        current = queue.popleft()
        if len(current) >= max_depth:
            continue
        help_text = _run_help(cast_binary, current)
        for sub in _parse_subcommands(help_text):
            child = (*current, sub)
            all_paths.append(child)
            if child not in seen:
                seen.add(child)
                queue.append(child)

    return [" ".join(path) for path in sorted(all_paths)]


def _build_output(cast_binary: str, paths: Iterable[str]) -> dict:
    all_paths = sorted(paths)
    top_level = [p for p in all_paths if " " not in p]
    nested = [p for p in all_paths if " " in p]
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cast_binary": cast_binary,
        "cast_version": _cast_version(cast_binary),
        "total_paths": len(all_paths),
        "top_level_count": len(top_level),
        "nested_count": len(nested),
        "max_depth": max((len(p.split()) for p in all_paths), default=0),
        "top_level": top_level,
        "nested": nested,
        "all_paths": all_paths,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cast-binary", default="cast", help="cast binary path/name")
    parser.add_argument("--max-depth", type=int, default=4, help="maximum command depth to scan")
    parser.add_argument("--output", type=Path, help="output JSON file (default: stdout)")
    args = parser.parse_args()

    paths = discover_paths(args.cast_binary, args.max_depth)
    payload = _build_output(args.cast_binary, paths)
    serialized = json.dumps(payload, indent=2, sort_keys=False)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
    else:
        print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
