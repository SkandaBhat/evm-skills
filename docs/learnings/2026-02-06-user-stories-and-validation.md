# User Stories and Validation Model (2026-02-06)

## Scope
Added agent-facing user stories for the JSON-RPC skill and a validator that checks story correctness against inventory + manifest.

## Added artifacts
- `evm-jsonrpc-wallet/references/user-stories.json`
  - Machine-readable story catalog.
  - Includes tier, required context gates, methods, and acceptance criteria.
- `evm-jsonrpc-wallet/references/user-stories.md`
  - Human-readable story summary.
- `evm-jsonrpc-wallet/references/method-manifest.json`
  - Tier and implementation mapping for all inventory methods.
- `evm-jsonrpc-wallet/scripts/build_method_manifest.py`
  - Deterministic manifest generator from method inventory.
- `evm-jsonrpc-wallet/scripts/validate_user_stories.py`
  - Story validator with policy + coverage checks.

## Validation rules implemented
1. Story schema checks:
   - Required fields present and typed.
   - Unique story IDs with constrained format.
2. Method integrity checks:
   - Story methods exist in inventory.
   - Story methods exist in method manifest.
3. Tier/policy checks:
   - Story tier must match each referenced method tier.
   - Required context flags must be present for non-read tiers.
4. Coverage checks:
   - Reports method coverage ratio.
   - Optional hard fail with `--require-full-coverage`.

## Current result
- `story_count = 17`
- `manifest_method_count = 69`
- `covered_method_count = 69`
- `coverage_ratio = 1.0`

Validated with:
`python3 evm-jsonrpc-wallet/scripts/validate_user_stories.py --stories evm-jsonrpc-wallet/references/user-stories.json --inventory evm-jsonrpc-wallet/references/rpc-method-inventory.json --manifest evm-jsonrpc-wallet/references/method-manifest.json --require-full-coverage`
