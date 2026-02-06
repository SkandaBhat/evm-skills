# Risk Tiers

## `read`
Use for non-state-changing commands and local transforms.

Examples:
- `balance`
- `block`
- `chain-id`
- `decode-abi`
- `to-wei`
- `tx-pool inspect`

Policy:
- Allowed by default.

## `local-sensitive`
Use for commands that touch private keys, signatures, or keystores.

Examples:
- `wallet new`
- `wallet import`
- `wallet decrypt-keystore`
- `mktx`

Policy:
- Requires `context.allow_local_sensitive = true`.

## `broadcast`
Use for commands that can publish or externally mutate shared state.

Examples:
- `send`
- `publish`
- `upload-signature`

Policy:
- Requires `context.allow_broadcast = true`.
- Requires a non-empty `context.confirmation_token`.
