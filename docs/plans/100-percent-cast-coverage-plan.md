# Implementation Plan: 100% Cast Coverage

## Goal
Ship an Agent Skills-based EVM capability that provides complete coverage of discoverable `cast` commands while enforcing deterministic, policy-driven execution.

## Definition of 100% coverage
Coverage is computed as:

`implemented_paths / discovered_paths == 1.0`

Where:
- `discovered_paths` comes from command discovery (`cast --help` recursion).
- `implemented_paths` is the wrapper manifest with active executor mappings.

Every covered path must have:
1. policy classification,
2. executor mapping,
3. normalized result schema,
4. tests.

## Phase 0: Repo and docs foundation
1. Establish docs as source of truth.
2. Store baseline command-path snapshot in `docs/data/`.
3. Define update workflow for future findings.

Exit criteria:
- Docs index, learnings, and plan are present and linked.

## Phase 1: Skill package skeleton
1. Create skill directory (e.g. `evm-cast-wallet/`).
2. Add spec-compliant `SKILL.md` frontmatter:
   - `name`
   - `description`
   - optional `license` and `compatibility`
3. Add `references/` and `scripts/` layout.

Exit criteria:
- Skill validates via `skills-ref validate`.

## Phase 2: Discovery and manifest pipeline
1. Implement `scripts/discover_cast_tree.py`:
   - recursive help parsing,
   - deterministic sorted output.
2. Implement `scripts/build_manifest.py`:
   - merges discovered paths into command manifest template.
3. Create canonical manifest:
   - `references/command-manifest.json`.

Exit criteria:
- Manifest path count equals discovery path count.

## Phase 3: Policy engine and safety tiers
1. Define three policy tiers:
   - `read` (safe queries/transforms),
   - `local-sensitive` (key/keystore operations),
   - `broadcast` (chain-changing actions).
2. Implement `scripts/policy_eval.py`:
   - enforces allow/deny and confirmation requirements.
3. Add per-command policy in manifest.

Exit criteria:
- Every command path has explicit policy tier.

## Phase 4: Cast wrapper runtime
1. Implement `scripts/evm_cast.py` with JSON request/response contract:
   - input: `command_path`, `args`, `context`.
   - output: structured status, stdout/stderr, parsed payload, metadata.
2. Enforce:
   - deterministic argument assembly,
   - timeout handling,
   - strict error codes,
   - command audit events.
3. Include safe defaults:
   - JSON output where possible,
   - no implicit state-changing execution without policy pass.

Exit criteria:
- Wrapper can execute all `read` commands from manifest.

## Phase 5: Full path implementation
1. Add handlers for:
   - all top-level command paths,
   - nested `wallet` and `tx-pool` paths.
2. For sensitive/broadcast commands:
   - require explicit confirmation token in request context,
   - record decision in audit output.
3. Normalize output format across all paths.

Exit criteria:
- `implemented_paths == discovered_paths`.

## Phase 6: Test and CI coverage gates
1. Add `scripts/check_coverage.py`:
   - compares discovery JSON to manifest and wrapper map.
2. Test layers:
   - parser/discovery unit tests,
   - wrapper contract tests,
   - policy enforcement tests,
   - command smoke tests (all paths),
   - selected behavioral tests on local anvil for write commands.
3. CI hard fails on:
   - missing path mappings,
   - missing policy tiers,
   - schema validation failures.

Exit criteria:
- CI enforces 100% command-path coverage continuously.

## Test strategy (mandatory execution order)
1. Skill spec compliance:
   - `skills-ref validate evm-cast-wallet`
   - fallback when `skills-ref` is unavailable: `python3 evm-cast-wallet/scripts/validate_skill.py evm-cast-wallet`
2. Discovery freshness:
   - regenerate discovery JSON from current local `cast`.
3. Coverage integrity:
   - compare `discovered_paths` vs manifest vs wrapper mappings.
   - fail on any mismatch.
4. Wrapper contract tests:
   - schema validation for success/failure/timeout,
   - deterministic argv construction,
   - error code normalization.
5. Policy tests:
   - validate `read`, `local-sensitive`, and `broadcast` enforcement.
6. Command smoke tests:
   - at least one execution assertion per discovered command path.
7. Behavioral tests:
   - selected write-path checks on local anvil for tx flows.

Recommended CI command sequence:
1. `skills-ref validate evm-cast-wallet`
   - or fallback: `python3 evm-cast-wallet/scripts/validate_skill.py evm-cast-wallet`
2. `python3 evm-cast-wallet/scripts/discover_cast_tree.py --output evm-cast-wallet/references/discovered-cast-paths.json`
3. `python3 evm-cast-wallet/scripts/check_coverage.py --manifest evm-cast-wallet/references/command-manifest.json --discovered evm-cast-wallet/references/discovered-cast-paths.json`
4. `pytest -q`

## Phase 7: Operational rollout
1. Publish v1 skill package with explicit compatibility notes.
2. Gather telemetry:
   - command usage frequency,
   - failure classes,
   - policy rejections.
3. Use adoption signal to decide when to replace backend with native wallet core.

Exit criteria:
- Stable production usage with measured command coverage and failure rates.

## Non-goals for v1
- Replacing `cast` internals.
- Designing a new signing engine.
- Supporting commands absent from local `cast` discovery output.

## Risks and mitigations
1. `cast` version drift changes command tree.
   - Mitigation: regenerate discovery on every CI run or release.
2. Inconsistent output formatting across commands.
   - Mitigation: wrapper-level normalization and schema checks.
3. Unsafe execution of sensitive commands.
   - Mitigation: policy tiers + explicit confirmation tokens.

## Immediate next build tasks
1. Scaffold skill folder with valid `SKILL.md`.
2. Implement discovery and manifest scripts.
3. Implement wrapper contract for a first read-only slice.
4. Add coverage gate before expanding to write paths.
