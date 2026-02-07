# R1 Foundation + Logs Engine (2026-02-07)

## Summary
Implemented R1 from the advanced capability roadmap:
1. foundation updates for heavy-read policy context,
2. chunked `eth_getLogs` runtime support,
3. new `logs` CLI command with deterministic limits and adaptive split behavior.

## Implemented changes
1. Context and errors
   - Added `allow_heavy_read` in normalized context.
   - Added stable error codes for logs and upcoming advanced capabilities.
2. Logs engine
   - New module: `evm/scripts/logs_engine.py`
   - Features:
     - fixed-size block chunking for numeric ranges,
     - adaptive interval split on retryable/over-limit remote errors,
     - deterministic log dedupe by `(blockNumber, logIndex, transactionHash)`,
     - hard limits: `max_chunks`, `max_logs`,
     - heavy-read detection against configurable block-span threshold.
3. CLI integration
   - New subcommand: `python3 scripts/evm_rpc.py logs`
   - Input uses request JSON/file:
     - `filter` (eth_getLogs filter object),
     - `context`, `env`, `timeout_seconds`,
     - `chunk_size`, `max_chunks`, `max_logs`,
     - `adaptive_split`,
     - `heavy_read_block_range_threshold`.
   - Supports existing output modes:
     - `--compact`
     - `--result-only`
     - `--select`

## Behavior notes
1. Heavy-read gate
   - Large numeric block ranges are denied unless `context.allow_heavy_read=true`.
2. Error model
   - `LOGS_RANGE_TOO_LARGE` when chunk budget is exceeded.
   - `LOGS_TOO_MANY_RESULTS` when merged log count exceeds `max_logs`.
   - Underlying RPC failures are returned with cause payload when chunk fetch fails.
3. Compatibility
   - Existing `exec`, `chain`, `batch`, `ens resolve`, and `balance` behavior remains unchanged.

## Validation results
Executed on 2026-02-07:
1. `pytest -q evm/tests` -> `26 passed`
2. `python3 evm/scripts/coverage_check.py --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json` -> `ok: true` (`69/69`)
3. `python3 evm/scripts/validate_user_stories.py --stories evm/references/user-stories.json --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json --require-full-coverage` -> `ok: true`, `coverage_ratio: 1.0`
