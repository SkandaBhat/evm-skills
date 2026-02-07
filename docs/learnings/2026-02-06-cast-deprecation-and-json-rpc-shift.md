# Cast Deprecation and JSON-RPC Shift (2026-02-06)

## Decision
Deprecate and remove the cast-based skill package from this repo, and pivot to a JSON-RPC-only skill architecture.

## Why
1. Runtime reliability issues in real sessions (Foundry panic path).
2. Agent behavior control is stronger with a direct JSON-RPC contract.
3. RPC URL policy can be enforced strictly (`ETH_RPC_URL` only, no invented endpoints).
4. Coverage can be grounded directly in `ethereum/execution-apis` method definitions.

## Executed changes
- Removed `evm-cast-wallet/` package files.
- Removed cast-specific baseline data and cast-only implementation plan docs.
- Added JSON-RPC method inventory derived from `execution-apis`.
- Added JSON-RPC-only implementation plan and new skill skeleton (`evm/`).

## Source
- User direction in task thread on 2026-02-06:
  - remove cast-based skill completely.
  - plan against full RPC set from `ethereum/execution-apis`.
