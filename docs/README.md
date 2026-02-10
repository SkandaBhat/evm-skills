# EVM Skills Docs

This directory is the source of truth for repository knowledge, decisions, and implementation plans.

## Operating Rules
- Read `docs/AGENTS.md` first.
- Keep `docs/plans/` aligned with the shipped implementation.
- Treat `docs/learnings/` as local-only personal notes (gitignored).
- Update `docs/CHANGELOG.md` for every documentation change.
- Remove obsolete documentation when it no longer reflects the current architecture.

## Document Map

### Working agreement
- `docs/AGENTS.md`: Documentation maintenance rules for future agent runs.
- `docs/CHANGELOG.md`: Dated log of documentation updates.
- `README.md`: Repository-level getting-started and human-to-agent prompt templates.

### Data snapshots
- `docs/data/execution-api-rpc-methods-2026-02-06.json`: Machine-readable inventory of 69 RPC methods.

### Active plans
- `docs/plans/cast-hybrid-architecture.md`: Target architecture for cast-backed low-level execution with wrapper-owned policy/safety controls.
- `docs/plans/analytics-commands-plan.md`: Roadmap for the 12 searcher-focused analytics commands and shared foundation.
- `docs/plans/usability-prompt-pack.md`: Repeatable usability and skill-adherence prompt suites (quick and extended packs) with scoring rubric and tuned mainnet-safe defaults.

### Archive
- `docs/archive/plans/`: Historical superseded plans kept for provenance.

### Skill Package
- `.agents/skills/evm`: Codex repo-discovery path (symlink alias to `evm/`).
- `evm/SKILL.md`: Skill entrypoint and usage rules.
- `evm/scripts/evm_rpc.py`: Runtime JSON-RPC wrapper entrypoint.
- `evm/scripts/rpc_contract.py`: Request/response contract helpers.
- `evm/scripts/method_registry.py`: Manifest registry loader.
- `evm/scripts/policy_eval.py`: Policy gate evaluator.
- `evm/scripts/adapters.py`: Method-specific preflight validations for adapter methods.
- `evm/scripts/cast_adapter.py`: `cast` CLI adapter for RPC and low-level utility delegation.
- `evm/scripts/analytics_registry.py`: Event/topic/selector registry for analytics commands.
- `evm/scripts/analytics_arbitrage.py`: Dedicated arbitrage route-scanning engine used by `analytics arbitrage-patterns`.
- `evm/scripts/analytics_envelopes.py`: Shared analytics success/result envelope builders (`range`, `summary`, `scan_summary`, optional checkpoint).
- `evm/scripts/analytics_decoders.py`: Shared analytics log-row decoding helpers for swap-flow and factory-new-pools commands.
- `evm/scripts/analytics_pool_metadata.py`: Shared Uniswap V2 pool metadata fetch helper (`token0`, `token1`, `decimals`) for analytics commands.
- `evm/scripts/analytics_runtime.py`: Shared analytics runtime orchestration helpers (executor, range resolution, log scan wrapper, runtime prelude).
- `evm/scripts/analytics_time_range.py`: `--last-blocks` / `--since` window resolution helpers.
- `evm/scripts/analytics_scanner.py`: Reusable chunked/resumable log scan wrapper.
- `evm/scripts/analytics_aggregators.py`: Shared analytics aggregators.
- `evm/scripts/convenience_ens_balance.py`: Shared ENS resolution and balance convenience engine used by `ens resolve` and `balance`.
- `evm/scripts/transforms.py`: Local transform helpers and ENS namehash support.
- `evm/scripts/logs_engine.py`: Chunked log querying, adaptive split, and deterministic dedupe helpers.
- `evm/scripts/abi_codec.py`: ABI encode/decode utilities for call data, outputs, and logs.
- `evm/scripts/multicall_engine.py`: Client-side aggregated `eth_call` execution and partial-failure handling.
- `evm/scripts/simulate_engine.py`: Simulation preflight helpers (`eth_call` + optional `eth_estimateGas`) with revert parsing.
- `evm/scripts/trace_engine.py`: Trace method negotiation and unsupported-path normalization.
- `evm/scripts/rpc_transport.py`: Hybrid transport (`cast rpc` default, direct HTTP for deterministic `eth_getLogs` orchestration).
- `evm/scripts/provider_capabilities.py`: Shared provider capability/method-support detection helpers.
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
