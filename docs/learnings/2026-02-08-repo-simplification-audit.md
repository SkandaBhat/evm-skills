# 2026-02-08: Repository Simplification Audit (Skill-Developer Pass)

## Scope
Audited the `evm` skill repository for complexity that forces agents to write ad-hoc scripts, with a focus on reducing wrapper boilerplate and making command surfaces easier to extend.

## Verified hotspots
1. `evm/scripts/evm_rpc.py` is the dominant complexity hotspot:
   - pre-pass line count was ~4.1k lines.
2. Analytics command handlers repeated the same range-resolution and log-scan error plumbing.
3. Analytics parser setup repeated the same argument bundles (`--last-blocks`, `--since`, runtime args, scan tuning args).
4. Analytics command setup repeated the same runtime prelude (`manifest`, `env`, executor/context/timeout bootstrap).

## Changes shipped in this pass
1. Added shared render helpers in `evm/scripts/evm_rpc.py`:
   - `_render_for_args`
   - `_render_for_args_and_exit`
2. Generalized analytics range and scan orchestration in `evm/scripts/evm_rpc.py`:
   - `_analytics_resolve_range_or_exit`
   - `_analytics_scan_logs_or_exit`
3. Reused those helpers across:
   - `cmd_analytics_dex_swap_flow`
   - `cmd_analytics_factory_new_pools`
   - `cmd_analytics_arbitrage_patterns`
4. Extracted arbitrage engine logic into a dedicated module:
   - `evm/scripts/analytics_arbitrage.py`
   - command handler now focuses on argument/range orchestration and output shaping.
5. Added parser helper bundles to reduce repeated option declarations:
   - `_add_analytics_window_args`
   - `_add_analytics_runtime_args`
   - `_add_analytics_scan_args`
6. Added shared provider capability detection helper:
   - `evm/scripts/provider_capabilities.py`
   - reused by both analytics and trace paths.
7. Added compact arbitrage scan mode:
   - `analytics arbitrage-patterns --summary-only`
   - returns summary/range metadata without candidate/per-block row payloads.
8. Extracted ENS + balance convenience domain into a dedicated module:
   - `evm/scripts/convenience_ens_balance.py`
   - moved ENS resolution and balance orchestration logic out of `evm/scripts/evm_rpc.py`.
9. Added shared convenience RPC executor wrappers in `evm/scripts/evm_rpc.py` so command handlers stay thin while still using `run_rpc_request` policy gates.
10. Added shared analytics envelope builders:
   - `evm/scripts/analytics_envelopes.py`
   - standardized success payload envelope construction and range/summary/scan/checkpoint result composition.
11. Added shared analytics runtime prelude helper in `evm/scripts/evm_rpc.py`:
   - `_analytics_runtime_or_exit`
   - removes repeated `manifest` + `env` + executor wiring from analytics command handlers.
12. Extracted analytics log-row decoders into a dedicated module:
   - `evm/scripts/analytics_decoders.py`
   - moved swap-flow and factory-new-pools log decode loops out of `evm/scripts/evm_rpc.py`.
13. Extracted Uniswap V2 pool metadata fetch logic into:
   - `evm/scripts/analytics_pool_metadata.py`
   - removed `_analytics_fetch_pool_metadata` and its private helper chain from `evm/scripts/evm_rpc.py`.
14. Added arbitrage candidate pagination for token-efficient result iteration:
   - `analytics arbitrage-patterns --page <n> --page-size <m>`
   - pagination is applied within the existing `--limit` candidate cap.
15. Extracted analytics runtime orchestration helpers into:
   - `evm/scripts/analytics_runtime.py`
   - moved analytics executor, runtime prelude, range resolver, and scan wrapper helpers out of `evm/scripts/evm_rpc.py`.
16. Reduced `evm/scripts/evm_rpc.py` further to ~3.02k lines in this pass.
17. Kept command behavior/output contracts stable and verified with full test suite.

## Validation
1. Ran full test suite: `pytest -q evm/tests`
2. Result: all tests passed (`45 passed`).

## Why this helps LLM agents
1. Smaller repeated surfaces means fewer special cases to remember while composing commands.
2. Shared analytics option bundles make new analytics commands easier to add consistently.
3. Standardized render/exit flow reduces branching differences across commands.
4. Shared analytics envelopes reduce per-command output-shape branching when composing downstream selectors.
5. Decoder extraction keeps analytics handlers focused on orchestration and lowers the mental footprint for command extension.
6. Built-in pagination eliminates the need for ad-hoc post-processing scripts when iterating large arbitrage candidate sets.
7. Runtime helper extraction makes analytics command handlers mostly orchestration/data-shaping, reducing cognitive load for modifications.
8. `--summary-only` enables low-token analytics loops without custom jq/select plumbing.

## Next simplification candidates (inference)
1. Add cursor-based resume metadata for paginated arbitrage outputs (stable candidate continuation across repeated scans).
2. Consolidate analytics CLI argument bundles into a dedicated parser module to further thin `evm/scripts/evm_rpc.py`.
