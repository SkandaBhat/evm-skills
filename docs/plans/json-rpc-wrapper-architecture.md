# JSON-RPC Wrapper Architecture Plan

## Objective
Define a robust wrapper architecture for `evm` that:
1. supports all methods in `execution-apis` inventory,
2. enforces strict user-safe policy controls,
3. remains deterministic and testable,
4. remains JSON-RPC-only with a cast-backed low-level execution layer.

## Status (2026-02-07)
- Implemented modules:
  - `evm/scripts/evm_rpc.py`
  - `evm/scripts/rpc_contract.py`
  - `evm/scripts/method_registry.py`
  - `evm/scripts/policy_eval.py`
  - `evm/scripts/adapters.py`
  - `evm/scripts/transforms.py`
  - `evm/scripts/logs_engine.py`
  - `evm/scripts/abi_codec.py`
  - `evm/scripts/multicall_engine.py`
  - `evm/scripts/simulate_engine.py`
  - `evm/scripts/trace_engine.py`
  - `evm/scripts/rpc_transport.py`
  - `evm/scripts/error_map.py`
  - `evm/scripts/coverage_check.py`
- Implemented tests:
  - `evm/tests/test_evm_rpc_wrapper.py`
  - `evm/tests/test_user_story_validation.py`
- `v0.2` shipped:
  - adapter preflight validation for local-sensitive and broadcast methods
  - broadcast-specific remote error mapping
  - confirmation token minimum-length enforcement for broadcast/operator methods
- `v0.2.x` shipped:
  - chain/batch multi-step execution with template substitution
  - output extraction modes (`--result-only`, `--select`)
  - transform helpers (`hex_to_int`, `wei_to_eth`, `slice_last_20_bytes_to_address`)
  - convenience commands (`ens resolve`, `balance`)
- Advanced phases shipped:
  - R1: logs chunking + heavy-read gating
  - R2: ABI helpers + multicall command
  - R3: simulation preflight + trace negotiation command

## Design principles
1. Single responsibility per module.
2. Stable machine-readable response contract.
3. Policy-first execution (deny before network).
4. Inventory-driven coverage guarantees.
5. No hidden side effects (especially RPC URL persistence).

## Hard constraints
1. Require `ETH_RPC_URL` for networked operations.
2. If missing, return:
   - `error_code = RPC_URL_REQUIRED`
   - message: `couldnt find an rpc url. give me an rpc url so i can add it to env.`
3. Never auto-select public RPC endpoints.
4. No local key persistence in this wrapper.

## Proposed package layout
`evm/scripts/`
1. `evm_rpc.py`
   - CLI entrypoint.
   - Subcommands:
     - `exec`
     - `chain`
     - `batch`
     - `ens resolve`
     - `balance`
     - `supported-methods`
     - `manifest-summary`
2. `rpc_contract.py`
   - Request/response dataclasses and validation.
3. `method_registry.py`
   - Loads inventory + method manifest.
4. `policy_eval.py`
   - Evaluates tier gates and confirmation requirements.
5. `rpc_transport.py`
   - Hybrid transport (`cast rpc` for most methods; direct HTTP for deterministic `eth_getLogs` handling).
6. `transforms.py`
   - Transform helpers with cast-backed unit/namehash primitives.
7. `error_map.py`
   - Stable internal error taxonomy and JSON-RPC mapping.
8. `coverage_check.py`
   - Verifies inventory-to-manifest completeness.
9. `sync_execution_apis_inventory.py`
   - Already present, keeps inventory fresh.

## Data files
`evm/references/`
1. `rpc-method-inventory.json`
   - Generated from `execution-apis`.
2. `method-manifest.json` (new)
   - One row per method with:
     - `method`
     - `tier` (`read|local-sensitive|broadcast|operator`)
     - `enabled`
     - `implementation` (`proxy|adapter|deny`)
     - `requires_confirmation` (bool)
     - `notes`
3. `risk-tiers.md`
   - Human policy reference.
4. `user-stories.json`
   - Machine-readable agent workflows for wrapper behavior.
5. `user-stories.md`
   - Human-readable story catalog.

## Request/response contract
### Request
```json
{
  "method": "eth_getBalance",
  "params": ["0x...", "latest"],
  "id": 1,
  "context": {
    "allow_local_sensitive": false,
    "allow_broadcast": false,
    "allow_operator": false,
    "confirmation_token": null
  },
  "timeout_seconds": 20,
  "env": {
    "ETH_RPC_URL": "https://..."
  }
}
```

### Response
```json
{
  "timestamp_utc": "...",
  "method": "eth_getBalance",
  "status": "ok|denied|error|timeout",
  "ok": true,
  "error_code": null,
  "error_message": null,
  "policy": {},
  "rpc_request": {},
  "rpc_response": {},
  "result": "0x...",
  "duration_ms": 12
}
```

### Chain request
```json
{
  "steps": [
    {"id": "a", "method": "eth_blockNumber", "params": []},
    {"id": "b", "transform": "hex_to_int", "input": "{{a.result}}"}
  ],
  "context_defaults": {},
  "env": {"ETH_RPC_URL": "https://..."},
  "timeout_seconds": 20
}
```

### Chain response
```json
{
  "method": "chain",
  "status": "ok|error|denied|timeout",
  "ok": true,
  "failed_step_id": null,
  "steps_executed": 2,
  "steps": [],
  "outputs": {},
  "final_result": 123
}
```

## Execution flow
1. Parse request JSON.
2. Validate request schema.
3. Load method registry and manifest.
4. Evaluate policy gates (tier + context).
5. Resolve runtime env (`request.env` over process env).
6. Enforce RPC URL rule.
7. Build JSON-RPC payload and send.
8. Normalize success/error into stable wrapper response.
9. Emit deterministic JSON output.

For `chain`:
1. Parse and validate chain request.
2. Resolve `{{step.path}}` templates from prior step outputs.
3. Execute each step via:
   - shared RPC runner (`run_rpc_request`) for RPC steps
   - local transform runner for transform steps
4. Stop at first failed step and return nonzero code deterministically.
5. Emit one aggregate JSON response with all executed step payloads.

## Method handling strategy
1. `proxy` path:
   - Direct pass-through for methods where wrapper-level validation is sufficient.
2. `adapter` path:
   - Method-specific pre/post checks for sensitive or complex methods.
   - Implemented adapters:
     - `eth_accounts`
     - `eth_sign`
     - `eth_signTransaction`
     - `eth_sendTransaction`
     - `eth_sendRawTransaction`
   - `engine_*` preflight hardening is optional backlog.
3. `deny` path:
   - Explicit unsupported/disabled states with stable reason code.

## Policy model
1. `read`: allow by default.
2. `local-sensitive`: require `allow_local_sensitive=true`.
3. `broadcast`: require `allow_broadcast=true` and `confirmation_token` length `>= 8`.
4. `operator`: require `allow_operator=true` and `confirmation_token` length `>= 8`.
5. Unknown method: deny with `METHOD_NOT_IN_MANIFEST`.

## Error taxonomy
Internal wrapper codes:
1. `INVALID_REQUEST`
2. `METHOD_NOT_IN_MANIFEST`
3. `METHOD_DISABLED`
4. `POLICY_DENIED`
5. `ADAPTER_VALIDATION_FAILED`
6. `RPC_URL_REQUIRED`
7. `RPC_TRANSPORT_ERROR`
8. `RPC_TIMEOUT`
9. `RPC_REMOTE_ERROR` (JSON-RPC error object returned)
10. `RPC_BROADCAST_NONCE_TOO_LOW` / `RPC_BROADCAST_ALREADY_KNOWN` /
    `RPC_BROADCAST_UNDERPRICED` / `RPC_BROADCAST_INSUFFICIENT_FUNDS`
11. `INTERNAL_ERROR`

JSON-RPC remote errors remain available under `rpc_response.error`.

## Retry and timeout policy
1. Default timeout: 20s.
2. Retries only for transient transport faults (connection reset, 429, 502, 503, 504).
3. Max retries: 2 with bounded backoff (e.g., 150ms, 400ms).
4. No retries for non-idempotent broadcast methods unless explicitly enabled.

## Output modes
1. `--compact`: compact JSON output.
2. `--result-only`: print only `result` (`exec`) or `final_result` (`chain`) for successful calls.
3. `--select <jsonpath-lite>`:
   - supports root `$`, `.key`, `[index]`.
   - returns selector extraction for direct piping.

## Observability
1. Include `duration_ms` and request correlation `id`.
2. Include policy decision block for all outcomes.
3. Do not log sensitive raw values by default.

## Testing architecture
1. Unit tests
   - contract validation
   - policy evaluation
   - error normalization
2. Integration tests (mock HTTP server)
   - success and JSON-RPC error cases
   - retry and timeout behavior
3. Coverage tests
   - inventory count == manifest count
   - no unmapped methods
4. Safety tests
   - missing RPC URL returns mandated message
   - no endpoint auto-discovery fallback
5. Story validation tests
   - story schema and tier/context correctness
   - full method coverage from stories (when required)
   - canonical command:
     - `python3 evm/scripts/validate_user_stories.py --stories evm/references/user-stories.json --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json --require-full-coverage`

## Milestones
1. M1: Contracts + registry + policy + manifest + coverage checker.
2. M2: `evm_rpc.py exec` with proxy-mode for `read` methods.
3. M3 (`v0.2`): local-sensitive/broadcast adapters + broadcast error mapping.
4. M4 (`v0.2.x`): chain/batch, template resolution, output selectors, transforms, ENS/balance convenience commands.
5. M5: CI test matrix + release hardening.
6. M6 (optional backlog): deeper `engine_*` payload preflight validation.

## Definition of done
1. Every inventory method has manifest entry.
2. Every manifest entry resolves to `proxy|adapter|deny`.
3. Wrapper outputs stable schema for all failures/successes.
4. Safety invariants pass tests (RPC URL, policy gates, no hidden fallbacks).
