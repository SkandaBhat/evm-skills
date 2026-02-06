#!/usr/bin/env python3
"""Policy evaluation for cast command execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ALLOWED_TIERS = {"read", "local-sensitive", "broadcast"}


def load_manifest(manifest_path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    return {entry["command_path"]: entry for entry in entries if "command_path" in entry}


def evaluate_policy(
    manifest_by_path: dict[str, dict[str, Any]],
    command_path: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or {}
    entry = manifest_by_path.get(command_path)
    if not entry:
        return {
            "allowed": False,
            "reason": "Command path missing from manifest",
            "error_code": "MANIFEST_PATH_MISSING",
            "tier": None,
        }

    tier = entry.get("tier", "read")
    if tier not in ALLOWED_TIERS:
        return {
            "allowed": False,
            "reason": f"Invalid tier in manifest: {tier}",
            "error_code": "INVALID_TIER",
            "tier": tier,
        }

    if not entry.get("enabled", True):
        return {
            "allowed": False,
            "reason": "Command disabled in manifest",
            "error_code": "COMMAND_DISABLED",
            "tier": tier,
        }

    requires_confirmation = bool(entry.get("requires_confirmation", tier != "read"))
    confirmation_token = str(context.get("confirmation_token", "") or "")

    if tier == "read":
        return {
            "allowed": True,
            "reason": "Allowed read command",
            "error_code": None,
            "tier": tier,
        }

    if tier == "local-sensitive":
        if not bool(context.get("allow_local_sensitive", False)):
            return {
                "allowed": False,
                "reason": "Local-sensitive command not approved by context",
                "error_code": "LOCAL_SENSITIVE_NOT_APPROVED",
                "tier": tier,
            }
        if requires_confirmation and not confirmation_token:
            return {
                "allowed": False,
                "reason": "Confirmation token required for local-sensitive command",
                "error_code": "CONFIRMATION_REQUIRED",
                "tier": tier,
            }
        return {
            "allowed": True,
            "reason": "Local-sensitive command approved",
            "error_code": None,
            "tier": tier,
        }

    if tier == "broadcast":
        if not bool(context.get("allow_broadcast", False)):
            return {
                "allowed": False,
                "reason": "Broadcast command not approved by context",
                "error_code": "BROADCAST_NOT_APPROVED",
                "tier": tier,
            }
        if requires_confirmation and not confirmation_token:
            return {
                "allowed": False,
                "reason": "Confirmation token required for broadcast command",
                "error_code": "CONFIRMATION_REQUIRED",
                "tier": tier,
            }
        return {
            "allowed": True,
            "reason": "Broadcast command approved",
            "error_code": None,
            "tier": tier,
        }

    return {
        "allowed": False,
        "reason": "Unhandled policy path",
        "error_code": "POLICY_INTERNAL_ERROR",
        "tier": tier,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="manifest JSON path")
    parser.add_argument("--command-path", required=True, help="space-delimited command path")
    parser.add_argument(
        "--context-json",
        default="{}",
        help="execution context as JSON object",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    context = json.loads(args.context_json)
    if not isinstance(context, dict):
        raise ValueError("--context-json must decode to an object")

    result = evaluate_policy(manifest, args.command_path, context)
    print(json.dumps(result, indent=2))
    return 0 if result["allowed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
