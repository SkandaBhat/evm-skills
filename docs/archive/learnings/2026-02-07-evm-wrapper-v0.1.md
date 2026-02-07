# EVM Wrapper v0.1 Implementation (2026-02-07)

## Scope
Implemented the first packaged runtime wrapper for the renamed `evm` skill.

## Delivered runtime modules
Under `evm/scripts/`:
- `evm_rpc.py`
  - CLI entrypoint with:
    - `exec`
    - `supported-methods`
    - `manifest-summary`
- `rpc_contract.py`
  - Request parsing/validation and context/env normalization.
- `method_registry.py`
  - Manifest loading and enabled-method lookup.
- `policy_eval.py`
  - Tier gates for `read`, `local-sensitive`, `broadcast`, `operator`.
- `rpc_transport.py`
  - HTTP JSON-RPC transport with timeout and bounded retries.
- `error_map.py`
  - Stable wrapper error codes and mandated RPC-missing message.
- `coverage_check.py`
  - Inventory/manifest set-equality checker.

## Policy and safety behavior
- Wrapper enforces manifest policy before network calls.
- Missing RPC URL behavior:
  - `error_code = RPC_URL_REQUIRED`
  - message: `couldnt find an rpc url. give me an rpc url so i can add it to env.`
- No automatic public RPC endpoint selection is implemented.
- Broadcast methods are not retried by default.

## Tests added
- `evm/tests/test_evm_rpc_wrapper.py`
  - covers RPC URL requirement, policy denials, successful RPC call, and remote RPC error mapping.
- Existing story validation tests kept:
  - `evm/tests/test_user_story_validation.py`

## Verification results
- `pytest -q evm/tests` -> `7 passed`
- `python3 evm/scripts/coverage_check.py ...` -> `ok: true` (`69/69`)
- `python3 evm/scripts/validate_user_stories.py ... --require-full-coverage` -> `ok: true` (`69/69`, coverage `1.0`)
