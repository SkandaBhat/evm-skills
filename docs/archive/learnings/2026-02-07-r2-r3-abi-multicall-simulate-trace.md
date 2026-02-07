# R2 + R3 Runtime Expansion (2026-02-07)

## Summary
Implemented the next advanced capability phases for the `evm` skill runtime:
1. ABI encode/decode workflows,
2. client-side multicall aggregation,
3. simulation preflight with revert decoding,
4. trace command with capability negotiation and deterministic unsupported handling.

## Implemented changes
1. ABI codec module
   - New file: `evm/scripts/abi_codec.py`
   - Added operations:
     - `encode_call`
     - `decode_output`
     - `decode_log`
     - `function_selector`
     - `event_topic0`
   - Added `abi` command in `evm/scripts/evm_rpc.py`.
2. Chain transform expansion
   - Updated `evm/scripts/transforms.py` with:
     - `abi_encode_call`
     - `abi_decode_output`
     - `abi_decode_log`
3. Multicall engine
   - New file: `evm/scripts/multicall_engine.py`
   - Added `multicall` command in `evm/scripts/evm_rpc.py`.
   - Supports:
     - many `eth_call` steps in one request,
     - per-call success/error status,
     - optional per-call output decode,
     - deterministic partial-failure handling via `MULTICALL_PARTIAL_FAILURE`.
4. Simulation engine
   - New file: `evm/scripts/simulate_engine.py`
   - Added `simulate` command in `evm/scripts/evm_rpc.py`.
   - Supports:
     - `eth_call` semantic preflight,
     - optional `eth_estimateGas`,
     - revert decoding for `Error(string)` and panic selectors,
     - stable failure code `SIMULATION_REVERTED`.
5. Trace engine
   - New file: `evm/scripts/trace_engine.py`
   - Added `trace` command in `evm/scripts/evm_rpc.py`.
   - Supports method negotiation order and emits `TRACE_UNSUPPORTED` when methods are absent in manifest/provider.

## Notable runtime behavior
1. No public RPC fallback was introduced.
2. `ETH_RPC_URL` remains required for networked commands.
3. All new commands preserve deterministic JSON output and existing output flags (`--compact`, `--result-only`, `--select`).
4. Existing commands (`exec`, `logs`, `chain`, `batch`, `ens resolve`, `balance`) remain compatible.

## Validation results
Executed on 2026-02-07:
1. `pytest -q evm/tests` -> `33 passed`
2. `python3 evm/scripts/coverage_check.py --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json` -> `ok: true` (`69/69`)
3. `python3 evm/scripts/validate_user_stories.py --stories evm/references/user-stories.json --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json --require-full-coverage` -> `ok: true`, `coverage_ratio: 1.0`

## Remaining advanced roadmap
- R4 provenance completion is still pending.
