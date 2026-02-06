# Cast Architecture and Decoupling Findings (2026-02-06)

## Scope
This summarizes prior architectural analysis of Foundry's upstream `cast` crate and what it means for this repo.

## Architectural summary
- `cast` is not just a tiny CLI shim.
- Entrypoint is small (`bin/main.rs`), but core logic is split across:
  - CLI option/dispatch layers.
  - Large library modules with real logic.
  - Command modules for wallet, tx building/sending, tracing, storage, interface/artifact operations.

## Key observed components
- `Cast<P>`: provider-facing operations (RPC calls, chain reads/writes, logs, subscriptions).
- `SimpleCast`: local transforms/encoding/decoding/hash utilities.
- `CastTxBuilder`: stateful transaction construction pipeline.
- Subcommands with substantial behavior:
  - `call`/`run`: tracing, local execution, debugging.
  - `storage`: compiler + explorer workflows.
  - `wallet`: keystore and signature operations.

## Thin-wrapper assessment
- Some commands are light wrappers around provider calls.
- Overall crate behavior is not a thin wrapper due to:
  - internal tx orchestration,
  - tracing/debug paths,
  - compile/explorer integrations,
  - wallet/keystore flows.

## Decoupling assessment
- Upstream `cast` is strongly coupled to Foundry workspace internals.
- It depends on multiple `foundry_*` path crates and shared workspace settings.
- Practical implication:
  - Do not try to extract upstream `cast` unchanged as the product architecture.
  - Prefer an adapter approach for v1: stable agent-facing wrapper, `cast` as backend.

## Implication for evm-skills
- Use `cast` as an execution backend in first iteration.
- Keep the agent contract stable so backend can later migrate to a dedicated wallet engine.

