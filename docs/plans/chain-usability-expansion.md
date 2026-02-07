# Chain Usability Expansion Plan (`v0.2.x`)

## Objective
Make the `evm` skill usable for multi-step agent workflows without ad-hoc scripting by shipping:
1. `chain`/`batch` execution,
2. machine-friendly output selectors,
3. local transform helpers,
4. ENS and balance convenience commands built on the same policy-enforced core.

## Status (2026-02-07)
- Completed and shipped in this repo state.

## Scope
1. `chain` and `batch` commands
   - Input: JSON request with ordered `steps`.
   - Step types:
     - RPC step: `{id, method, params, optional context/env/timeout/rpc_id}`
     - Transform step: `{id, transform, input}`
   - Template references:
     - `{{step_id.result}}` and jsonpath-lite traversal on prior step output.
   - Deterministic fail-fast:
     - stop at first non-`ok` step.
2. Output modes for `exec` and `chain`
   - `--result-only`
   - `--select <jsonpath-lite>`
   - Existing `--compact` preserved.
3. Transform helpers
   - `hex_to_int`
   - `wei_to_eth`
   - `slice_last_20_bytes_to_address`
4. Convenience commands
   - `ens resolve <name>`
   - `balance <name-or-address> --at <tag>`
   - Both use the same `run_rpc_request` policy/manifest path.

## Architecture decisions
1. Shared core runner
   - `run_rpc_request(req, manifest_by_method)` returns `(exit_code, payload)`.
   - Used by `exec`, `chain`, ENS, and balance commands.
2. Stable error model
   - Existing exit semantics preserved:
     - `0`: success
     - `1`: transport/remote runtime error
     - `2`: invalid request/template/transform/selector
     - `4`: policy denial
3. No policy bypass
   - Chain RPC steps and convenience commands execute through the same manifest+policy gates.
4. No RPC URL fallback
   - Missing `ETH_RPC_URL` still returns mandated message.
5. JSON-RPC-only runtime
   - ENS resolution implemented with JSON-RPC `eth_call` + local namehash.

## Chain request contract
```json
{
  "id": "optional-run-id",
  "timeout_seconds": 20,
  "context_defaults": {
    "allow_local_sensitive": false,
    "allow_broadcast": false,
    "allow_operator": false,
    "confirmation_token": ""
  },
  "env": {
    "ETH_RPC_URL": "https://..."
  },
  "steps": [
    {
      "id": "resolver",
      "method": "eth_call",
      "params": [{"to": "0x...", "data": "0x..."}, "latest"]
    },
    {
      "id": "resolver_addr",
      "transform": "slice_last_20_bytes_to_address",
      "input": "{{resolver.result}}"
    }
  ]
}
```

## Chain response contract
```json
{
  "timestamp_utc": "...",
  "method": "chain",
  "status": "ok|error|denied|timeout",
  "ok": true,
  "error_code": null,
  "error_message": null,
  "request": {},
  "failed_step_id": null,
  "steps_executed": 2,
  "steps": [],
  "outputs": {},
  "final_result": "0x...",
  "duration_ms": 12
}
```

## Validation checklist
1. Runtime tests
   - `pytest -q evm/tests`
2. Coverage consistency
   - `python3 evm/scripts/coverage_check.py --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json`
3. Story consistency
   - `python3 evm/scripts/validate_user_stories.py --stories evm/references/user-stories.json --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json --require-full-coverage`

## Acceptance criteria
1. Agents can execute multi-step workflows with one command and deterministic JSON output.
2. Template substitution can consume prior step outputs safely.
3. Output extraction supports direct piping (`--result-only`, `--select`).
4. ENS and balance convenience commands work without public RPC fallback.
5. Existing safety invariants remain intact.
