# Cast Hybrid Architecture Plan

## Goal
Use `cast` for low-level EVM/RPC primitives while retaining wrapper-owned policy, safety, and deterministic orchestration.

## Architecture
1. `evm/scripts/cast_adapter.py`
   - canonical process boundary for all `cast` calls,
   - stable parsing/mapping of stdout/stderr into wrapper contracts.
2. `evm/scripts/rpc_transport.py`
   - default: `cast rpc`,
   - exception: `eth_getLogs` via direct HTTP for deterministic split behavior.
3. `evm/scripts/abi_codec.py`
   - delegate `function_selector`, `event_topic0`, `encode_call`, `decode_output`.
4. `evm/scripts/transforms.py`
   - delegate `wei_to_eth`, `ens_namehash`.
5. `evm/scripts/evm_rpc.py`
   - unchanged role as policy + envelope orchestrator.

## Guardrails
1. No bypass of manifest policy checks.
2. Keep `RPC_URL_REQUIRED_MESSAGE` behavior unchanged.
3. Keep wrapper error taxonomy stable (`error_map.py`).
4. Keep logs chunking/splitting/dedupe deterministic and wrapper-controlled.

## Validation
1. Run integration tests: `pytest -q`.
2. Ensure simulated revert decoding still receives RPC error `data`.
3. Confirm chain transforms and balance formatting remain backward-compatible for existing prompts.

## Backlog
1. Add explicit `cast` preflight command (for install checks + version constraints).
2. Expand logs local preflight validation and decode/output controls.
3. Add provider capability matrix tests for trace methods and edge provider errors.
