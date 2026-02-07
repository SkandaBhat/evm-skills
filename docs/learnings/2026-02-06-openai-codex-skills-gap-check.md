# OpenAI Codex Skills Gap Check (2026-02-06)

## Scope
Checked `https://developers.openai.com/codex/skills/` and compared requirements/guidance against this repo's current structure.

## Verified from OpenAI Codex docs
- Codex skill metadata uses progressive disclosure: metadata first, full `SKILL.md` on activation.
- A skill directory requires `SKILL.md` with `name` and `description`.
- Optional skill folders include `scripts/`, `references/`, `assets/`, and `agents/openai.yaml`.
- Codex scans repo skills under `.agents/skills` from current directory up to repo root.
- Codex can detect skill changes/new installs automatically; restart is fallback if updates do not appear.
- Optional `agents/openai.yaml` supports UI metadata and dependency declarations (including MCP tools).

## Repo status vs Codex docs
- `SKILL.md` requirement: satisfied (`evm/SKILL.md`).
- Progressive disclosure shape: satisfied (heavy details moved to `references/` and scripts).
- Coverage/testing/tooling docs: satisfied (`docs/`, `evm/scripts/`, `evm/references/`).
- Repo discovery path (`.agents/skills/...`): missing in current layout.
  - Current skill lives at `evm/` repository root.
  - This is installable by path, but not in the default repo scan location described by Codex docs.
- Optional `agents/openai.yaml`: missing.
  - Not required for validity.
  - Useful for `default_prompt`, user-facing metadata, and declared MCP dependencies.

## Practical implications
- For local/checked-in auto-discovery in Codex, add skill(s) under `.agents/skills/`.
- For remote installs via installer tooling, path-based install can still work even if skill is not stored under `.agents/skills`.
- If we want richer Codex app UX and dependency signaling, add `agents/openai.yaml` in the skill directory.

## Recommended follow-up changes
1. Add `.agents/skills/evm/` path in this repo.
   - Either move the skill there or add a symlink/wrapper structure that keeps existing tooling stable.
2. Add `evm/agents/openai.yaml` with:
   - `interface.default_prompt` tuned for JSON-RPC task routing.
   - Optional `interface.display_name` and `short_description`.
   - Dependencies only when we actually require MCP tools.
3. Keep current inventory/coverage pipeline unchanged; it is orthogonal to Codex discovery path.

## Source
- <https://developers.openai.com/codex/skills/>
