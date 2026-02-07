#!/usr/bin/env python3
"""Check method coverage between inventory and manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    inventory_methods = {m["name"] for m in inventory.get("methods", [])}
    manifest_methods = {e["method"] for e in manifest.get("entries", [])}

    missing_in_manifest = sorted(inventory_methods - manifest_methods)
    missing_in_inventory = sorted(manifest_methods - inventory_methods)
    ok = not missing_in_manifest and not missing_in_inventory

    payload = {
        "ok": ok,
        "inventory_count": len(inventory_methods),
        "manifest_count": len(manifest_methods),
        "missing_in_manifest": missing_in_manifest,
        "missing_in_inventory": missing_in_inventory,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
