# 2026-02-08: Codex Repo Discovery Packaging

## Decision
Add `.agents/skills/evm` as a repo-discovery alias that points to the existing `evm/` package.

## Why
The repo already uses `evm/` as the canonical skill path across docs, tests, and scripts. We need Codex-style repo discovery without breaking those existing references.

## Implementation
1. Created `.agents/skills/`.
2. Added `.agents/skills/evm` as a symlink to `../../evm`.
3. Kept `evm/` as the single canonical source tree.

## Verification
Verified:
1. `.agents/skills/evm` resolves to `evm/`.
2. CLI entrypoint runs through the alias path: `python3 .agents/skills/evm/scripts/evm_rpc.py --help`.

Inferred:
1. Hosts that support symlinks will discover the skill from `.agents/skills/evm` while avoiding file duplication drift.

