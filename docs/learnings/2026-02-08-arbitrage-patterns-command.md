# 2026-02-08: `analytics arbitrage-patterns` Command

## What shipped
`analytics arbitrage-patterns` now supports both single-block and window scans:
1. single block:
   - `python3 evm/scripts/evm_rpc.py analytics arbitrage-patterns --block <tag-or-number>`
2. block window:
   - `python3 evm/scripts/evm_rpc.py analytics arbitrage-patterns --last-blocks 10`
   - `python3 evm/scripts/evm_rpc.py analytics arbitrage-patterns --since 30m`
   - `python3 evm/scripts/evm_rpc.py analytics arbitrage-patterns --last-blocks 10 --summary-only`
3. paginated candidate views:
   - `python3 evm/scripts/evm_rpc.py analytics arbitrage-patterns --last-blocks 50 --limit 100 --page 2 --page-size 10`

The runtime keeps wrapper-routed JSON-RPC execution and now:
1. fetches blocks with transactions (`eth_getBlockByNumber(..., true)`),
2. attempts fast receipt collection via `eth_getBlockReceipts`,
3. falls back to per-tx `eth_getTransactionReceipt` when the provider does not support `eth_getBlockReceipts` (or returns invalid shape),
4. identifies Uniswap V2/V3 `Swap` logs,
5. resolves pool `token0`/`token1` via `eth_call`,
6. infers hop directions and flags arbitrage-like candidates.

Implementation structure:
1. command orchestration remains in `evm/scripts/evm_rpc.py`,
2. arbitrage engine logic is now in `evm/scripts/analytics_arbitrage.py`,
3. provider capability detection is shared via `evm/scripts/provider_capabilities.py`,
4. candidate pagination is handled in command orchestration (`--page`, `--page-size` within `--limit` cap).

## Heuristic implemented
A transaction is flagged as a candidate when one of these is true:
1. cyclic path: first input token equals last output token,
2. routed multi-hop pattern: token continuity across multiple pools,
3. mixed-route pattern: both Uniswap V2 and V3 swap events in one route.

Candidate rows include:
1. `tx_hash`,
2. inferred token path (`path_tokens`, `path_display`),
3. `swap_count`, `continuity_links`, `unique_pools`,
4. `has_cycle`, `cycle_gain_raw`,
5. `block_number`/`block_hash` context for window scans,
6. human-readable `reasons`.

Pagination envelope (`result.pagination`) includes:
1. `page`, `page_size`, `offset`,
2. `returned`, `capped_candidates`, `total_candidates`,
3. `has_next_page`, `is_truncated_by_limit`, `limit`.

## Output/operational learnings from live window scan
1. Scanning a 10-block window is materially faster and more reliable with `eth_getBlockReceipts` than pure per-tx receipt pulls.
2. Providers differ in support for `eth_getBlockReceipts`; explicit fallback is required for portability.
3. Window mode benefits from aggregate telemetry:
   - per-block summaries (`result.blocks`),
   - global summary counters (`result.summary`),
   - receipt-source counters (`result.summary.receipt_collection`).

## Verified behavior
Added integration coverage in `evm/tests/test_analytics.py`:
1. detects a synthetic cyclic V2+V3 route,
2. rejects invalid `--block` values with `INVALID_REQUEST`,
3. supports `--last-blocks` range scans with `eth_getBlockReceipts`,
4. falls back to `eth_getTransactionReceipt` when `eth_getBlockReceipts` is unsupported,
5. supports `--summary-only` to suppress `result.candidates` and `result.blocks` for low-token agent workflows,
6. supports paginated candidate output via `--page` + `--page-size`.

## Important limits (inference)
1. This is pattern detection, not a profitability proof.
2. It does not currently compute full transaction-wide token accounting across arbitrary transfer graphs.
3. It does not require trace methods and therefore cannot fully attribute internal transfers.
