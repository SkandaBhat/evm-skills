# Chain Usability Expansion (`v0.2.x`) (2026-02-07)

## Context
User feedback highlighted a practical gap: single-call JSON-RPC wrapper support was not enough for common agent workflows (ENS resolution, multi-step reads, and result post-processing).

## Implemented
1. Added shared runtime core in `evm/scripts/evm_rpc.py`
   - `run_rpc_request(req, manifest_by_method)` now powers all command flows.
2. Added chained execution commands
   - `chain` and alias `batch`.
   - Request supports ordered `steps` with unique IDs.
   - Steps can reference prior step outputs via templates (`{{step_id.path}}`).
   - Deterministic fail-fast behavior on first failed step.
3. Added machine-friendly output modes
   - `--result-only`
   - `--select <jsonpath-lite>` with `$`, `.key`, `[index]`.
4. Added local transform helpers in new module `evm/scripts/transforms.py`
   - `hex_to_int`
   - `wei_to_eth`
   - `slice_last_20_bytes_to_address`
5. Added convenience commands
   - `ens resolve <name>`
   - `balance <name-or-address> --at <tag>`
   - Both execute via shared policy/manifest-gated runtime path.

## ENS implementation detail
- ENS resolution uses JSON-RPC `eth_call` only:
  1. ENS registry `resolver(bytes32)` lookup.
  2. Resolver `addr(bytes32)` lookup.
- No RPC fallback selection.
- Local namehash support is implemented in `transforms.py`.

## Validation results
Executed on 2026-02-07:
1. `pytest -q evm/tests` -> `21 passed`
2. `python3 evm/scripts/coverage_check.py --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json` -> `ok: true` (`69/69`)
3. `python3 evm/scripts/validate_user_stories.py --stories evm/references/user-stories.json --inventory evm/references/rpc-method-inventory.json --manifest evm/references/method-manifest.json --require-full-coverage` -> `ok: true`, `coverage_ratio: 1.0`

## Outcome
Agents can now run one non-interactive command with JSON input, deterministic JSON output, and multi-step variable reuse without writing ad-hoc scripts.
