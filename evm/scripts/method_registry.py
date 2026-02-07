"""Method registry loaders for inventory + manifest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_manifest_by_method(path: Path) -> dict[str, dict[str, Any]]:
    raw = load_json(path)
    entries = raw.get("entries", [])
    by_method: dict[str, dict[str, Any]] = {}
    for entry in entries:
        method = str(entry.get("method", "")).strip()
        if method:
            by_method[method] = entry
    return by_method


def supported_methods_from_manifest(path: Path) -> list[str]:
    by_method = load_manifest_by_method(path)
    return sorted(m for m, e in by_method.items() if e.get("enabled", True))
