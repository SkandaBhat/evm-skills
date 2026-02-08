# 2026-02-08: RPC Default Pool With User Override

## Decision
Runtime no longer requires `ETH_RPC_URL` to be present in env for read/simulate/trace/logs flows. Endpoint resolution now follows strict precedence:
1. `ETH_RPC_URL` (user/session override, single endpoint).
2. `ETH_RPC_DEFAULT_URLS` (optional default-pool override, comma/space/newline-separated).
3. Built-in Ethereum mainnet default pool.

## Built-in default pool
1. `https://ethereum-rpc.publicnode.com`
2. `https://eth.drpc.org`
3. `https://1rpc.io/eth`
4. `https://eth.llamarpc.com`

## Runtime behavior
1. If `ETH_RPC_URL` is present, wrapper uses only that endpoint (no fallback to public pool).
2. If default-pool mode is active, wrapper advances to the next endpoint only on transport/timeout failures.
3. JSON-RPC remote errors are returned directly and do not trigger endpoint switching.

## Implementation
1. Added endpoint resolver in `evm/scripts/rpc_contract.py`:
   - `DEFAULT_PUBLIC_MAINNET_RPC_URLS`
   - `DEFAULT_RPC_POOL_ENV_VAR`
   - `resolve_rpc_endpoints(execution_env)`
2. Updated `run_rpc_request` in `evm/scripts/evm_rpc.py` to:
   - resolve endpoint candidates,
   - execute transport attempts in order,
   - surface endpoint-source metadata in `rpc_request`.
3. Updated tests:
   - `evm/tests/test_exec_policy.py`
   - `evm/tests/test_logs.py`
   - `evm/tests/_evm_rpc_helpers.py`

## Verification
Verified:
1. `pytest -q evm/tests` -> `39 passed` (2026-02-08).
2. Missing-`ETH_RPC_URL` flows now succeed via default-pool path in test coverage.
3. Explicit `ETH_RPC_URL` prevents fallback to default-pool endpoints.
