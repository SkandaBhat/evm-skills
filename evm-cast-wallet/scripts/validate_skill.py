#!/usr/bin/env python3
"""Local SKILL.md validator aligned with Agent Skills spec constraints."""

from __future__ import annotations

import argparse
import json
import unicodedata
from pathlib import Path
from typing import Any

import yaml


ALLOWED_FIELDS = {
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
}


def _find_skill_md(skill_dir: Path) -> Path | None:
    for name in ("SKILL.md", "skill.md"):
        candidate = skill_dir / name
        if candidate.exists():
            return candidate
    return None


def _parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    if not content.startswith("---"):
        raise ValueError("SKILL.md must start with YAML frontmatter (---)")
    parts = content.split("---", 2)
    if len(parts) < 3:
        raise ValueError("SKILL.md frontmatter not properly closed with ---")
    frontmatter_raw = parts[1]
    body = parts[2].strip()
    parsed = yaml.safe_load(frontmatter_raw)
    if not isinstance(parsed, dict):
        raise ValueError("SKILL.md frontmatter must be a YAML mapping")
    return parsed, body


def _validate_name(name: Any, skill_dir: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(name, str) or not name.strip():
        return ["Field 'name' must be a non-empty string"]

    norm = unicodedata.normalize("NFKC", name.strip())
    if len(norm) > 64:
        errors.append(f"Skill name exceeds 64 characters ({len(norm)} chars)")
    if norm != norm.lower():
        errors.append("Skill name must be lowercase")
    if norm.startswith("-") or norm.endswith("-"):
        errors.append("Skill name cannot start or end with a hyphen")
    if "--" in norm:
        errors.append("Skill name cannot contain consecutive hyphens")
    if not all(ch.isalnum() or ch == "-" for ch in norm):
        errors.append("Skill name contains invalid characters")

    dir_norm = unicodedata.normalize("NFKC", skill_dir.name)
    if dir_norm != norm:
        errors.append(f"Directory name '{skill_dir.name}' must match skill name '{norm}'")
    return errors


def validate_skill(skill_path: Path) -> list[str]:
    skill_path = skill_path.resolve()
    skill_dir = skill_path.parent if skill_path.is_file() else skill_path
    if not skill_dir.exists() or not skill_dir.is_dir():
        return [f"Not a valid skill directory: {skill_dir}"]

    skill_md = _find_skill_md(skill_dir)
    if skill_md is None:
        return [f"Missing required file: SKILL.md in {skill_dir}"]

    try:
        metadata, _body = _parse_frontmatter(skill_md.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [str(exc)]

    errors: list[str] = []
    extra = set(metadata.keys()) - ALLOWED_FIELDS
    if extra:
        errors.append(f"Unexpected fields in frontmatter: {', '.join(sorted(extra))}")

    if "name" not in metadata:
        errors.append("Missing required field in frontmatter: name")
    else:
        errors.extend(_validate_name(metadata["name"], skill_dir))

    description = metadata.get("description")
    if "description" not in metadata:
        errors.append("Missing required field in frontmatter: description")
    elif not isinstance(description, str) or not description.strip():
        errors.append("Field 'description' must be a non-empty string")
    elif len(description) > 1024:
        errors.append(f"Description exceeds 1024 characters ({len(description)} chars)")

    if "compatibility" in metadata:
        compatibility = metadata.get("compatibility")
        if not isinstance(compatibility, str):
            errors.append("Field 'compatibility' must be a string")
        elif len(compatibility) > 500:
            errors.append(f"Compatibility exceeds 500 characters ({len(compatibility)} chars)")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("skill_path", type=Path, help="skill directory or SKILL.md path")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args()

    errors = validate_skill(args.skill_path)
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2))
    else:
        if errors:
            print("Validation failed:")
            for err in errors:
                print(f"- {err}")
        else:
            print(f"Valid skill: {args.skill_path}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
