# Agent Skills Spec Findings (2026-02-06)

## Scope
This document captures verified requirements for writing a spec-compliant Agent Skills package.

## Verified requirements

### Skill structure
- A skill is a directory containing `SKILL.md` at minimum.
- Optional directories are `scripts/`, `references/`, and `assets/`.

### `SKILL.md` format
- Must start with YAML frontmatter (`---` block).
- Must include:
  - `name`
  - `description`
- Frontmatter keys allowed by validator:
  - `name`
  - `description`
  - `license`
  - `compatibility`
  - `metadata`
  - `allowed-tools` (experimental)

### Field constraints
- `name`
  - Non-empty.
  - Max 64 chars.
  - Lowercase.
  - Only alphanumeric unicode + `-`.
  - No leading/trailing hyphen.
  - No consecutive hyphens.
  - Must match parent directory name (after NFKC normalization).
- `description`
  - Non-empty.
  - Max 1024 chars.
- `compatibility`
  - If present, must be a string.
  - Max 500 chars.
- Unknown frontmatter fields fail validation.

### Progressive disclosure model
1. Metadata (`name` + `description`) loaded at startup.
2. Full `SKILL.md` body loaded on activation.
3. Referenced resources loaded on demand.

### Integration pattern
- Recommended system-prompt representation is `<available_skills>` XML with:
  - `<name>`
  - `<description>`
  - `<location>` (filesystem-based agents)

### Validation tooling
- Reference package: `skills-ref` (library + CLI).
- Reference commands:
  - `skills-ref validate <skill-path>`
  - `skills-ref read-properties <skill-path>`
  - `skills-ref to-prompt <skill-path>...`

## Notes for this repo
- Keep `SKILL.md` focused and move detail into `references/`.
- Use a generated command/path baseline for coverage guarantees rather than hand-maintained lists.
- Treat `allowed-tools` as optional due experimental status.

## Sources
- <https://agentskills.io/specification>
- <https://agentskills.io/integrate-skills>
- <https://agentskills.io/what-are-skills>
- <https://github.com/agentskills/agentskills/tree/main/skills-ref>
