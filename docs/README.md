# EVM Skills Docs

This directory is the source of truth for repository knowledge, decisions, and implementation plans.

## Operating Rules
- Read `docs/AGENTS.md` first.
- Keep `docs/learnings/` and `docs/plans/` aligned with the shipped implementation.
- Update `docs/CHANGELOG.md` for every documentation change.
- Remove obsolete documentation when it no longer reflects the current architecture.

## Document Map

### Working agreement
- `docs/AGENTS.md`: Documentation maintenance rules for future agent runs.
- `docs/CHANGELOG.md`: Dated log of documentation updates.
- `README.md`: Repository-level getting-started and human-to-agent prompt templates.

### Active learnings
- `docs/learnings/2026-02-07-cast-hybrid-runtime.md`: Cast codebase findings and wrapper/cast delegation boundary.
- `docs/learnings/2026-02-07-analytics-foundation-v0.1.md`: Initial analytics command rollout and shared analytics module foundation.
- `docs/learnings/2026-02-07-simplification-pass.md`: Post-audit simplification pass (shared parsers/prelude helpers, removed custom keccak implementation).

### Data snapshots
- `docs/data/execution-api-rpc-methods-2026-02-06.json`: Machine-readable inventory of 69 RPC methods.

### Active plans
- `docs/plans/cast-hybrid-architecture.md`: Target architecture for cast-backed low-level execution with wrapper-owned policy/safety controls.
- `docs/plans/analytics-commands-plan.md`: Roadmap for the 12 searcher-focused analytics commands and shared foundation.

### Archive
- `docs/archive/learnings/`: Historical learning notes from earlier milestones.
- `docs/archive/plans/`: Historical superseded plans kept for provenance.

### Skill Package
- `evm/SKILL.md`: Skill entrypoint and usage rules.
- `evm/scripts/evm_rpc.py`: Runtime JSON-RPC wrapper entrypoint.
- `evm/scripts/rpc_contract.py`: Request/response contract helpers.
- `evm/scripts/method_registry.py`: Manifest registry loader.
- `evm/scripts/policy_eval.py`: Policy gate evaluator.
- `evm/scripts/adapters.py`: Method-specific preflight validations for adapter methods.
- `evm/scripts/cast_adapter.py`: `cast` CLI adapter for RPC and low-level utility delegation.
- `evm/scripts/analytics_registry.py`: Event/topic/selector registry for analytics commands.
- `evm/scripts/analytics_time_range.py`: `--last-blocks` / `--since` window resolution helpers.
- `evm/scripts/analytics_scanner.py`: Reusable chunked/resumable log scan wrapper.
- `evm/scripts/analytics_aggregators.py`: Shared analytics aggregators.
- `evm/scripts/transforms.py`: Local transform helpers and ENS namehash support.
- `evm/scripts/logs_engine.py`: Chunked log querying, adaptive split, and deterministic dedupe helpers.
- `evm/scripts/abi_codec.py`: ABI encode/decode utilities for call data, outputs, and logs.
- `evm/scripts/multicall_engine.py`: Client-side aggregated `eth_call` execution and partial-failure handling.
- `evm/scripts/simulate_engine.py`: Simulation preflight helpers (`eth_call` + optional `eth_estimateGas`) with revert parsing.
- `evm/scripts/trace_engine.py`: Trace method negotiation and unsupported-path normalization.
- `evm/scripts/rpc_transport.py`: Hybrid transport (`cast rpc` default, direct HTTP for deterministic `eth_getLogs` orchestration).
- `evm/scripts/error_map.py`: Stable error codes/messages.
- `evm/scripts/sync_execution_apis_inventory.py`: Inventory sync tooling from execution-apis checkout.
- `evm/scripts/build_method_manifest.py`: Regenerates method manifest from inventory.
- `evm/scripts/coverage_check.py`: Inventory/manifest coverage checker.
- `evm/scripts/validate_user_stories.py`: Validates story schema, policy alignment, and coverage.
- `evm/references/rpc-method-inventory.json`: Source-of-truth method inventory for coverage tracking.
- `evm/references/method-manifest.json`: Tier/implementation mapping for all inventory methods.
- `evm/references/rpc-methods.md`: Human-readable method list by namespace.
- `evm/references/risk-tiers.md`: Risk and gating model for method classes.
- `evm/references/user-stories.json`: Machine-readable agent user stories.
- `evm/references/user-stories.md`: Human-readable user story catalog.
- `evm/tests/_evm_rpc_helpers.py`: Shared integration-test harness for RPC wrapper tests.
- `evm/tests/test_exec_policy.py`: Policy/exec behavior tests.
- `evm/tests/test_chain.py`: Chain/batch workflow tests.
- `evm/tests/test_logs.py`: Logs command behavior tests.
- `evm/tests/test_analytics.py`: Analytics command tests.
- `evm/tests/test_abi_multicall_sim_trace.py`: ABI, multicall, simulate, and trace tests.
- `evm/tests/test_convenience.py`: ENS/balance convenience command tests.
- `evm/tests/test_user_story_validation.py`: Story validation tests.
