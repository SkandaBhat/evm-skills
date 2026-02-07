#!/usr/bin/env python3
"""Build method-manifest.json from rpc-method-inventory.json."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


LOCAL_SENSITIVE_METHODS = {
    "eth_accounts",
    "eth_sign",
    "eth_signTransaction",
}

BROADCAST_METHODS = {
    "eth_sendRawTransaction",
    "eth_sendTransaction",
}


def classify_method(method: str) -> tuple[str, str, bool, str]:
    """Return tier, implementation, requires_confirmation, notes."""
    if method.startswith("engine_"):
        return (
            "operator",
            "adapter",
            True,
            "Execution client control-plane method; requires operator approval.",
        )
    if method in BROADCAST_METHODS:
        return (
            "broadcast",
            "adapter",
            True,
            "State-changing publish path; requires explicit confirmation.",
        )
    if method in LOCAL_SENSITIVE_METHODS:
        return (
            "local-sensitive",
            "adapter",
            False,
            "Uses local account authority.",
        )
    if method.startswith(("eth_", "debug_")):
        return (
            "read",
            "proxy",
            False,
            "Read or simulation path.",
        )
    return ("read", "deny", False, "Unknown namespace; disabled by default.")


def build_manifest(inventory: dict[str, Any]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for item in inventory.get("methods", []):
        method = str(item["name"])
        tier, implementation, requires_confirmation, notes = classify_method(method)
        entries.append(
            {
                "method": method,
                "tier": tier,
                "enabled": implementation != "deny",
                "implementation": implementation,
                "requires_confirmation": requires_confirmation,
                "notes": notes,
                "sources": item.get("sources", []),
            }
        )

    entries.sort(key=lambda e: e["method"])
    tier_counts: dict[str, int] = {}
    for entry in entries:
        tier = entry["tier"]
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_inventory_count": inventory.get("count"),
        "source_repository": inventory.get("source_repository"),
        "source_ref": inventory.get("source_ref"),
        "source_commit": inventory.get("source_commit"),
        "count": len(entries),
        "tier_counts": tier_counts,
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, help="Path to rpc-method-inventory.json")
    parser.add_argument("--output", required=True, help="Output path for method-manifest.json")
    args = parser.parse_args()

    inventory_path = Path(args.inventory).resolve()
    output_path = Path(args.output).resolve()

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    manifest = build_manifest(inventory)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(output_path),
                "count": manifest["count"],
                "tier_counts": manifest["tier_counts"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
