# Docs Changelog

## 2026-02-07
- Renamed skill package path from `evm-jsonrpc-wallet/` to `evm/`.
- Updated all docs/plans/learnings to the `evm/` package path.
- Implemented packaged runtime wrapper `evm/scripts/evm_rpc.py` with policy-first JSON-RPC execution.
- Added wrapper support modules (`rpc_contract`, `method_registry`, `policy_eval`, `rpc_transport`, `error_map`, `coverage_check`).
- Added wrapper runtime tests (`evm/tests/test_evm_rpc_wrapper.py`).
- Added runtime implementation learning note (`docs/learnings/2026-02-07-evm-wrapper-v0.1.md`).
- Updated skill and plans to reflect v0.1 runtime availability and current milestone status.
- Implemented `v0.2` adapter hardening (`evm/scripts/adapters.py`) for local-sensitive and broadcast methods.
- Added broadcast-specific remote error mapping for common transaction publish failures.
- Enforced minimum confirmation token length for broadcast/operator gated calls.
- Updated plans to mark `v0.3` as dropped; additional `engine_*` hardening moved to optional backlog.
- Added `v0.2` learning note (`docs/learnings/2026-02-07-v0.2-adapter-hardening.md`).
- Added detailed chain usability plan (`docs/plans/chain-usability-expansion.md`) for `chain`/`batch`, templating, output selectors, transforms, and convenience commands.
- Implemented and documented `v0.2.x` chain usability expansion and validation outcomes (`docs/learnings/2026-02-07-chain-usability-expansion.md`).
- Updated core plans/architecture docs to include shipped multi-step runtime and output shaping.
- Updated docs index to include new plan/learning entries and `transforms.py` module mapping.
- Cleaned documentation set and removed obsolete legacy-learning notes.

## 2026-02-06
- Initialized project documentation structure under `docs/`.
- Added persistent docs maintenance rules (`docs/AGENTS.md`).
- Added Agent Skills spec findings.
- Added OpenAI Codex skills docs gap check and repository alignment recommendations (`.agents/skills` path and optional `agents/openai.yaml`).
- Added cross-ecosystem update-pattern research (Codex, Agent Skills, OpenSkills, SkillPort, Claude plugins) with rollout implications for installed snapshots.
- Added JSON-RPC method inventory from `ethereum/execution-apis` (`69` methods: `eth=40`, `debug=5`, `engine=24`).
- Added `evm` skill skeleton (JSON-RPC-only runtime).
- Added inventory sync script: `evm/scripts/sync_execution_apis_inventory.py`.
- Added JSON-RPC-only implementation plan (`docs/plans/json-rpc-only-skill-plan.md`).
- Added a dedicated JSON-RPC wrapper architecture plan covering module boundaries, request/response contract, policy flow, error taxonomy, retries, and test strategy.
- Added method manifest generation and a complete user story catalog for agent workflows.
- Added user story validator enforcing schema, tier/context policy alignment, and optional full method coverage.
