# Analytics Commands Plan

## Objective
Add first-class, searcher-focused analytics commands on top of the existing `evm` wrapper while keeping:
1. wrapper-owned policy/safety controls,
2. deterministic JSON output contracts,
3. cast-backed low-level primitives where useful.

## Command roadmap
Target commands:
1. `analytics dex-swap-flow`
2. `analytics factory-new-pools`
3. `analytics arbitrage-patterns`
4. `analytics token-bought-never-sold`
5. `analytics token-largest-swaps`
6. `analytics mev-sandwich-around`
7. `analytics quote-compare`
8. `analytics pools-reserve-scan`
9. `analytics tx-trace-summary`
10. `analytics gas-effective-paid`
11. `analytics simulate-preflight`
12. `analytics token-transfer-spike`
13. `analytics flows-track`

## Status (2026-02-08)
Shipped:
1. `analytics dex-swap-flow` (Uniswap V2 pool flow scan)
2. `analytics factory-new-pools` (Uniswap V2/V3 factory creation scans)
3. `analytics arbitrage-patterns` (single-block arbitrage-like route classification on Uniswap V2/V3 swap logs)
4. P0 foundations:
   - event/ABI registry (`evm/scripts/analytics_registry.py`)
   - block-range resolver with `--last-blocks` and `--since` (`evm/scripts/analytics_time_range.py`)
   - resumable log scanner wrapper (`evm/scripts/analytics_scanner.py`)
   - shared aggregators (`evm/scripts/analytics_aggregators.py`)

Planned next:
1. `analytics pools-reserve-scan`
2. `analytics token-largest-swaps`
3. `analytics gas-effective-paid`
4. `analytics tx-trace-summary`

## Architectural rules
1. Keep all execution through `run_rpc_request` for policy gating.
2. Reuse `cast` via adapter for formatting/ABI/hash utilities where possible.
3. Keep `eth_getLogs` orchestration wrapper-controlled (chunk/split/dedupe).
4. Return stable machine-friendly envelopes with explicit `error_code`.
5. Keep checkpoint/resume deterministic for long scans.

## Output contract (analytics)
Each analytics command should emit:
1. `result.range` (resolved block window and basis)
2. `result.rows` (event/call-level rows)
3. `result.summary` (aggregates, counters)
4. `result.scan_summary` (chunking stats)
5. optional `result.checkpoint`

## Testing strategy
1. Integration tests with mock JSON-RPC server for every new command path.
2. Deterministic assertions for:
   - range resolution,
   - decode correctness,
   - aggregate totals,
   - checkpoint behavior.
3. Regression tests that non-analytics commands still run when `cast` is missing in PATH at startup.
