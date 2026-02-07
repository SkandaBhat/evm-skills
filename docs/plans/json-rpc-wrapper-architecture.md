# JSON-RPC Wrapper Architecture Plan

## Objective
Define a robust wrapper architecture for `evm` that:
1. supports all methods in `execution-apis` inventory,
2. enforces strict user-safe policy controls,
3. remains deterministic and testable,
4. does not depend on `cast`.

## Status (2026-02-07)
- Implemented modules:
  - `evm/scripts/evm_rpc.py`
  - `evm/scripts/rpc_contract.py`
  - `evm/scripts/method_registry.py`
  - `evm/scripts/policy_eval.py`
  - `evm/scripts/rpc_transport.py`
  - `evm/scripts/error_map.py`
  - `evm/scripts/coverage_check.py`
- Implemented tests:
  - `evm/tests/test_evm_rpc_wrapper.py`
  - `evm/tests/test_user_story_validation.py`

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
     - `supported-methods`
     - `manifest-summary`
2. `rpc_contract.py`
   - Request/response dataclasses and validation.
3. `method_registry.py`
   - Loads inventory + method manifest.
4. `policy_eval.py`
   - Evaluates tier gates and confirmation requirements.
5. `rpc_transport.py`
   - HTTP JSON-RPC client with timeout/retry policy.
6. `error_map.py`
   - Stable internal error taxonomy and JSON-RPC mapping.
7. `coverage_check.py`
   - Verifies inventory-to-manifest completeness.
8. `sync_execution_apis_inventory.py`
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

## Method handling strategy
1. `proxy` path:
   - Direct pass-through for methods where wrapper-level validation is sufficient.
2. `adapter` path:
   - Method-specific pre/post checks for sensitive or complex methods.
   - First adapters:
     - `eth_sendTransaction`
     - `eth_sendRawTransaction`
     - `engine_*`
3. `deny` path:
   - Explicit unsupported/disabled states with stable reason code.

## Policy model
1. `read`: allow by default.
2. `local-sensitive`: require `allow_local_sensitive=true`.
3. `broadcast`: require `allow_broadcast=true` and `confirmation_token`.
4. `operator`: require `allow_operator=true` and `confirmation_token`.
5. Unknown method: deny with `METHOD_NOT_IN_MANIFEST`.

## Error taxonomy
Internal wrapper codes:
1. `INVALID_REQUEST`
2. `METHOD_NOT_IN_MANIFEST`
3. `METHOD_DISABLED`
4. `POLICY_DENIED`
5. `RPC_URL_REQUIRED`
6. `RPC_TRANSPORT_ERROR`
7. `RPC_TIMEOUT`
8. `RPC_REMOTE_ERROR` (JSON-RPC error object returned)
9. `INTERNAL_ERROR`

JSON-RPC remote errors remain available under `rpc_response.error`.

## Retry and timeout policy
1. Default timeout: 20s.
2. Retries only for transient transport faults (connection reset, 429, 502, 503, 504).
3. Max retries: 2 with bounded backoff (e.g., 150ms, 400ms).
4. No retries for non-idempotent broadcast methods unless explicitly enabled.

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
3. M3: Broadcast/operator gating + adapters for sensitive methods.
4. M4: Full inventory mapping + CI test matrix + docs updates.

## Definition of done
1. Every inventory method has manifest entry.
2. Every manifest entry resolves to `proxy|adapter|deny`.
3. Wrapper outputs stable schema for all failures/successes.
4. Safety invariants pass tests (RPC URL, policy gates, no hidden fallbacks).
