# 2026-02-08: `analytics arbitrage-patterns` Command

## What shipped
Added a new analytics command to the `evm` wrapper:
1. `python3 evm/scripts/evm_rpc.py analytics arbitrage-patterns --block <tag-or-number>`

The command:
1. fetches one block with full transactions (`eth_getBlockByNumber(..., true)`),
2. fetches each transaction receipt (`eth_getTransactionReceipt`),
3. identifies Uniswap V2/V3 `Swap` logs,
4. resolves each pool's `token0`/`token1` via `eth_call`,
5. infers hop directions and flags arbitrage-like candidates.

## Heuristic now implemented
A transaction is flagged as a candidate when one of these is true:
1. cyclic path: first input token equals last output token,
2. routed multi-hop pattern: token continuity across multiple pools,
3. mixed-route pattern: both Uniswap V2 and V3 swap events in one route.

Candidate rows include:
1. `tx_hash`,
2. inferred token path (`path_tokens`, `path_display`),
3. `swap_count`, `continuity_links`, `unique_pools`,
4. `has_cycle`, `cycle_gain_raw`,
5. human-readable `reasons`.

## Verified behavior
1. Added integration coverage in `evm/tests/test_analytics.py`:
   - detects a synthetic cyclic V2+V3 route,
   - rejects invalid `--block` values with `INVALID_REQUEST`.
2. Command remains wrapper-routed JSON-RPC only (no alternate CLI path).

## Important limits (inference)
1. This is pattern detection, not a profitability proof.
2. It does not currently compute net token deltas for all transfers in a tx.
3. It does not require trace methods and therefore cannot fully attribute internal transfers.
