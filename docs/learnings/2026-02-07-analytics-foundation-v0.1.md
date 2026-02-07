# 2026-02-07: Analytics Foundation v0.1

## What shipped
Added initial high-level analytics commands to `evm/scripts/evm_rpc.py`:
1. `analytics dex-swap-flow`
   - scans Uniswap V2 `Swap` logs for one pool,
   - decodes rows,
   - computes net pool flow and volume aggregates.
2. `analytics factory-new-pools`
   - scans factory creation events,
   - supports `uniswap-v2` (`PairCreated`) and `uniswap-v3` (`PoolCreated`).

## New shared modules
1. `evm/scripts/analytics_registry.py`
   - canonical event declarations, selectors, topic0 constants.
2. `evm/scripts/analytics_time_range.py`
   - resolves `--last-blocks` and `--since` windows using live block timestamps.
3. `evm/scripts/analytics_scanner.py`
   - reusable log scanner wrapper over `logs_engine`,
   - supports checkpoint file progress updates for resumable scans.
4. `evm/scripts/analytics_aggregators.py`
   - reusable flow/aggregation helpers.

## Cast reuse
1. Continued cast-backed runtime model.
2. Added `cast_format_units` adapter for decimal rendering in analytics outputs.

## Important guardrail
`analytics_registry.py` uses hardcoded topic0 constants instead of import-time hashing to avoid startup failures when `cast` is missing from PATH for non-analytics commands.

## Validation
1. Added integration tests for both analytics commands in `evm/tests/test_analytics.py`.
2. Full test suite passes (`37` tests).
