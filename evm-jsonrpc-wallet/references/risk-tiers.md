# JSON-RPC Risk Tiers

## Tier model
- `read`: non-mutating chain queries and deterministic reads.
- `local-sensitive`: methods that expose or use local account authority.
- `broadcast`: methods that publish transactions.
- `operator`: execution-client control or consensus-engine methods (infrastructure-scoped).

## Baseline mapping
- `read`:
  - `eth_*` reads (for example `eth_getBalance`, `eth_call`, `eth_getLogs`, `eth_estimateGas`, `eth_feeHistory`)
  - `debug_getRaw*` and `debug_getBadBlocks` (read-only but high-cost on some nodes)
- `local-sensitive`:
  - `eth_accounts`
  - `eth_sign`
  - `eth_signTransaction`
- `broadcast`:
  - `eth_sendTransaction`
  - `eth_sendRawTransaction`
- `operator`:
  - all `engine_*` methods

## Policy defaults
- Allow `read` by default.
- Require explicit allow flags for `local-sensitive`, `broadcast`, and `operator`.
- Require explicit confirmation token for `broadcast` and `operator`.
