#!/usr/bin/env python3
"""Validate agent user stories against method inventory and manifest policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


STORY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,64}$")
VALID_TIERS = {"read", "local-sensitive", "broadcast", "operator"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _required_flags_for_tier(tier: str) -> tuple[str | None, bool]:
    if tier == "local-sensitive":
        return "allow_local_sensitive", False
    if tier == "broadcast":
        return "allow_broadcast", True
    if tier == "operator":
        return "allow_operator", True
    return None, False


def _validate_story_shape(story: dict[str, Any], errors: list[str]) -> None:
    required_fields = [
        "id",
        "title",
        "persona",
        "goal",
        "tier",
        "rpc_url_required",
        "context_requirements",
        "methods",
        "acceptance_criteria",
    ]
    for field in required_fields:
        if field not in story:
            errors.append(f"story missing required field: {field}")

    story_id = story.get("id", "")
    if not isinstance(story_id, str) or not STORY_ID_RE.match(story_id):
        errors.append(f"invalid story id: {story_id!r}")

    tier = story.get("tier")
    if tier not in VALID_TIERS:
        errors.append(f"story {story_id}: invalid tier {tier!r}")

    methods = story.get("methods")
    if not isinstance(methods, list) or not methods or not all(isinstance(m, str) for m in methods):
        errors.append(f"story {story_id}: methods must be a non-empty string list")

    criteria = story.get("acceptance_criteria")
    if not isinstance(criteria, list) or not criteria or not all(isinstance(c, str) for c in criteria):
        errors.append(f"story {story_id}: acceptance_criteria must be a non-empty string list")

    context = story.get("context_requirements")
    if not isinstance(context, dict):
        errors.append(f"story {story_id}: context_requirements must be an object")
        return
    for key in ("allow_local_sensitive", "allow_broadcast", "allow_operator", "requires_confirmation"):
        if not isinstance(context.get(key), bool):
            errors.append(f"story {story_id}: context_requirements.{key} must be bool")

    if story.get("rpc_url_required") is not True:
        errors.append(f"story {story_id}: rpc_url_required must be true")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stories", required=True, help="Path to user-stories.json")
    parser.add_argument(
        "--inventory",
        required=True,
        help="Path to rpc-method-inventory.json",
    )
    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to method-manifest.json",
    )
    parser.add_argument(
        "--require-full-coverage",
        action="store_true",
        help="Fail if story methods do not cover all manifest methods.",
    )
    args = parser.parse_args()

    stories_doc = _load_json(Path(args.stories).resolve())
    inventory_doc = _load_json(Path(args.inventory).resolve())
    manifest_doc = _load_json(Path(args.manifest).resolve())

    errors: list[str] = []
    stories = stories_doc.get("stories")
    if not isinstance(stories, list) or not stories:
        print(json.dumps({"ok": False, "errors": ["stories must be a non-empty list"]}, indent=2))
        return 1

    inventory_methods = {str(m["name"]) for m in inventory_doc.get("methods", [])}
    manifest_entries = manifest_doc.get("entries", [])
    manifest_methods = {str(e["method"]) for e in manifest_entries}
    tier_by_method = {str(e["method"]): str(e["tier"]) for e in manifest_entries}

    if inventory_methods != manifest_methods:
        errors.append("inventory and manifest method sets do not match")

    seen_ids: set[str] = set()
    used_methods: set[str] = set()

    for raw_story in stories:
        if not isinstance(raw_story, dict):
            errors.append("story must be an object")
            continue

        _validate_story_shape(raw_story, errors)
        story_id = str(raw_story.get("id", ""))
        if story_id in seen_ids:
            errors.append(f"duplicate story id: {story_id}")
        seen_ids.add(story_id)

        story_tier = raw_story.get("tier")
        methods = raw_story.get("methods", [])
        context = raw_story.get("context_requirements", {})
        if not isinstance(methods, list) or not isinstance(context, dict):
            continue

        for method in methods:
            if not isinstance(method, str):
                continue
            used_methods.add(method)
            if method not in inventory_methods:
                errors.append(f"story {story_id}: unknown method not in inventory: {method}")
                continue
            if method not in manifest_methods:
                errors.append(f"story {story_id}: method missing from manifest: {method}")
                continue

            method_tier = tier_by_method.get(method)
            if method_tier != story_tier:
                errors.append(
                    f"story {story_id}: method {method} tier mismatch "
                    f"(story={story_tier}, manifest={method_tier})"
                )
                continue

            required_flag, requires_confirmation = _required_flags_for_tier(method_tier or "read")
            if required_flag and not context.get(required_flag, False):
                errors.append(
                    f"story {story_id}: method {method} requires context {required_flag}=true"
                )
            if requires_confirmation and not context.get("requires_confirmation", False):
                errors.append(
                    f"story {story_id}: method {method} requires requires_confirmation=true"
                )

    missing_from_stories = sorted(manifest_methods - used_methods)
    coverage_ratio = (len(used_methods) / len(manifest_methods)) if manifest_methods else 0.0

    if args.require_full_coverage and missing_from_stories:
        errors.append(
            f"full coverage required, but {len(missing_from_stories)} methods are not in stories"
        )

    payload = {
        "ok": not errors,
        "story_count": len(stories),
        "manifest_method_count": len(manifest_methods),
        "covered_method_count": len(used_methods & manifest_methods),
        "coverage_ratio": round(coverage_ratio, 6),
        "missing_methods": missing_from_stories,
        "errors": errors,
    }
    print(json.dumps(payload, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
