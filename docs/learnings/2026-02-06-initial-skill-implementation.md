# Initial Skill Implementation (2026-02-06)

## Delivered
Implemented a usable first version of skill package:
- `evm-cast-wallet/SKILL.md`
- `evm-cast-wallet/scripts/discover_cast_tree.py`
- `evm-cast-wallet/scripts/build_manifest.py`
- `evm-cast-wallet/scripts/policy_eval.py`
- `evm-cast-wallet/scripts/evm_cast.py`
- `evm-cast-wallet/scripts/check_coverage.py`
- `evm-cast-wallet/scripts/validate_skill.py` (local fallback validator)
- `evm-cast-wallet/references/*`
- `evm-cast-wallet/tests/*`

## Runtime baseline from implementation
- Local cast version: `cast Version: 1.4.1-stable`
- Discovered command paths: `120`
- Manifest entries: `120`
- Coverage check: pass (`missing_in_manifest=0`, `missing_in_wrapper=0`)

## Verified commands executed
- `python3 evm-cast-wallet/scripts/check_coverage.py ...` -> ok
- `python3 evm-cast-wallet/scripts/evm_cast.py exec --request-file ...` -> ok for `address-zero`
- `python3 evm-cast-wallet/scripts/evm_cast.py manifest-summary ...` -> ok

## Test results
- `pytest -q evm-cast-wallet/tests` -> `5 passed`.

## Validation tooling note
- `skills-ref` was not installed in this environment.
- Added local fallback validator (`scripts/validate_skill.py`) enforcing the same key frontmatter constraints used in this repo workflow.

## Practical usage
Agents should call `scripts/evm_cast.py exec` with JSON requests rather than invoking raw `cast` directly, so policy and normalized response handling are always applied.

## RPC URL state decision
- RPC URL handling is env-only for this skill.
- No persistence to disk is implemented.
- For RPC-required commands with no `ETH_RPC_URL` and no `--rpc-url`, wrapper returns:
  - `error_code = RPC_URL_REQUIRED`
  - `error_message = couldnt find an rpc url. give me an rpc url so i can add it to env.`
