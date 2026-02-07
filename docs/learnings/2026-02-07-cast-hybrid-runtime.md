# 2026-02-07: Cast-Backed Hybrid Runtime

## Decision
Keep the `evm` wrapper as the product-level control plane, and delegate low-level execution primitives to `cast`.

## Why
Reviewing `../foundry/crates/cast` showed mature implementations for:
1. raw JSON-RPC requests (`cast rpc` / `cmd/rpc.rs`),
2. ABI helpers (`calldata`, `decode-abi`, `sig`, `sig-event`),
3. unit and ENS primitives (`from-wei`, `namehash`, `resolve-name`),
4. event/log filter parsing (`cmd/logs.rs`).

This lets the skill drop duplicated low-level plumbing while keeping wrapper-specific safeguards.

## Delegation Boundary
Wrapper-owned responsibilities:
1. policy/permission gating from manifest tiers,
2. safety controls (`allow_*`, confirmation tokens),
3. chain/batch templating and transform orchestration,
4. stable machine-readable envelopes and error codes,
5. deterministic logs chunk/split/dedupe protections.

Cast-delegated responsibilities:
1. most method transport via `cast rpc`,
2. ABI selector/topic generation and calldata/output codecs,
3. wei formatting and ENS namehash.

## Implementation Notes
1. Added `evm/scripts/cast_adapter.py` as a single integration surface.
2. Switched `evm/scripts/rpc_transport.py` to call `cast rpc` for most methods.
3. Kept `eth_getLogs` on direct HTTP transport because `cast rpc` may internally retry provider range errors (`-32005`) and bypass wrapper split logic.
4. Updated `abi_codec.py` and `transforms.py` to use cast-backed primitives.

## Operational Requirement
`cast` is now a required dependency for normal wrapper operation.
