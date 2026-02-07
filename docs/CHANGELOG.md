# Docs Changelog

## 2026-02-07
- Renamed skill package path from `evm-jsonrpc-wallet/` to `evm/`.
- Updated all docs/plans/learnings to the `evm/` package path.
- Implemented packaged runtime wrapper `evm/scripts/evm_rpc.py` with policy-first JSON-RPC execution.
- Added wrapper support modules (`rpc_contract`, `method_registry`, `policy_eval`, `rpc_transport`, `error_map`, `coverage_check`).
- Added wrapper runtime tests (`evm/tests/test_evm_rpc_wrapper.py`).
- Added runtime implementation learning note (`docs/learnings/2026-02-07-evm-wrapper-v0.1.md`).
- Updated skill and plans to reflect v0.1 runtime availability and current milestone status.

## 2026-02-06
- Initialized project documentation structure under `docs/`.
- Added persistent docs maintenance rules (`docs/AGENTS.md`).
- Added Agent Skills spec findings.
- Added cast architecture and decoupling findings.
- Added cast command-path baseline (120 paths) and JSON snapshot.
- Added the first full implementation plan for 100% cast coverage.
- Updated the implementation plan with explicit test order and CI command sequence.
- Added fallback validation path when `skills-ref` is unavailable.
- Added initial implementation learning log for the first usable skill package.
- Linked the implemented skill package from docs index.
- Added `evm-cast-wallet` skill package with spec-compliant `SKILL.md`.
- Added cast wrapper tooling (`discover`, `manifest`, `policy`, `exec`, `coverage`, `validate` scripts).
- Added generated discovery and manifest files under `evm-cast-wallet/references/`.
- Added automated tests for discovery, policy, wrapper execution, coverage, and skill validation.
- Added ready-to-run request examples for read and broadcast execution flows.
- Added env-only RPC URL behavior (no persistence) and explicit `RPC_URL_REQUIRED` guidance.
- Added OpenAI Codex skills docs gap check and repository alignment recommendations (`.agents/skills` path and optional `agents/openai.yaml`).
- Added cross-ecosystem update-pattern research (Codex, Agent Skills, OpenSkills, SkillPort, Claude plugins) with rollout implications for installed snapshots.
- Added installed-session field findings, including reproducible Foundry proxy-detection panic and required read-only JSON-RPC fallback direction.
- Removed `evm-cast-wallet` skill package and cast-only docs/plans.
- Added JSON-RPC method inventory from `ethereum/execution-apis` (`69` methods: `eth=40`, `debug=5`, `engine=24`).
- Added `evm` skill skeleton (JSON-RPC-only, no cast dependency).
- Added inventory sync script: `evm/scripts/sync_execution_apis_inventory.py`.
- Added JSON-RPC-only implementation plan (`docs/plans/json-rpc-only-skill-plan.md`).
- Added decision note documenting cast deprecation and JSON-RPC pivot.
- Added a dedicated JSON-RPC wrapper architecture plan covering module boundaries, request/response contract, policy flow, error taxonomy, retries, and test strategy.
- Added method manifest generation and a complete user story catalog for agent workflows.
- Added user story validator enforcing schema, tier/context policy alignment, and optional full method coverage.
