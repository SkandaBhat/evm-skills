# Cast Command Coverage Baseline (2026-02-06)

## Purpose
Define the coverage target for v1: all discoverable `cast` command paths.

## Baseline snapshot
- Total command paths: `120`
- Top-level commands: `102`
- Nested subcommands: `18`
- Maximum observed depth: `2`

Machine-readable source of truth:
- `docs/data/cast-command-paths-2026-02-06.json`

## Discovery method
Command tree was discovered by recursively parsing:
- `cast --help`
- `cast <command> --help`
- `cast <command> <subcommand> --help`

and collecting all entries under each `Commands:` block.

## Nested command paths in this snapshot
- `tx-pool content`
- `tx-pool content-from`
- `tx-pool inspect`
- `tx-pool status`
- `wallet address`
- `wallet change-password`
- `wallet decrypt-keystore`
- `wallet import`
- `wallet list`
- `wallet new`
- `wallet new-mnemonic`
- `wallet private-key`
- `wallet public-key`
- `wallet remove`
- `wallet sign`
- `wallet sign-auth`
- `wallet vanity`
- `wallet verify`

## Coverage contract for implementation
For 100% coverage, every discovered command path must have:
1. A manifest entry.
2. A policy tier (read/local-sensitive/broadcast).
3. An executable mapping in the wrapper.
4. A normalized output contract.
5. At least one test assertion (smoke or behavioral).

## Update protocol
When `cast` version changes:
1. Regenerate the command-path JSON.
2. Update this doc with new counts and changed paths.
3. Update the implementation manifest.
4. Record the change in `docs/CHANGELOG.md`.
