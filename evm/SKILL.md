---
name: evm
description: Agent workflow for EVM operations using Ethereum JSON-RPC, with cast-backed low-level execution and policy-first wrapper controls.
license: Proprietary. LICENSE.txt has complete terms
compatibility: Requires python3, cast (Foundry CLI), and outbound internet access to Ethereum JSON-RPC endpoints. Supports optional ETH_RPC_URL override, otherwise uses built-in Ethereum mainnet RPC pool.
---

# EVM JSON-RPC Wallet Skill

Use this skill for EVM tasks through Ethereum JSON-RPC with a wrapper+cast hybrid runtime.

## Core rules
1. Use only the JSON-RPC wrapper flow defined in this skill.
2. Treat `cast` as required runtime dependency for low-level execution.
3. If `ETH_RPC_URL` is provided, use it as the RPC endpoint for requests.
4. If `ETH_RPC_URL` is missing, use the built-in Ethereum mainnet default pool.
5. Optional: `ETH_RPC_DEFAULT_URLS` can override the built-in default pool (comma/space/newline-separated URLs).
6. Do not persist RPC URLs to disk.

Default built-in Ethereum mainnet pool:
1. `https://ethereum-rpc.publicnode.com`
2. `https://eth.drpc.org`
3. `https://1rpc.io/eth`
4. `https://eth.llamarpc.com`

## Method coverage source of truth
- `references/rpc-method-inventory.json` (machine-readable inventory)
- `references/method-manifest.json` (tier + implementation mapping)
- `references/rpc-methods.md` (human-readable list)
- Source upstream: <https://github.com/ethereum/execution-apis>

## User stories
- `references/user-stories.json` contains machine-readable agent workflows.
- `references/user-stories.md` contains human-readable story summaries.
- Validate stories against inventory + manifest:
  - `python3 scripts/validate_user_stories.py --stories references/user-stories.json --inventory references/rpc-method-inventory.json --manifest references/method-manifest.json --require-full-coverage`

## Current status
- Runtime wrapper is available at `scripts/evm_rpc.py`.
- Cast adapter runtime is available at `scripts/cast_adapter.py`.
- `scripts/rpc_transport.py` delegates most methods through `cast rpc`, with deterministic HTTP path for `eth_getLogs`.
- `v0.2` adapter hardening is implemented for:
  - `eth_accounts`
  - `eth_sign`
  - `eth_signTransaction`
  - `eth_sendRawTransaction`
  - `eth_sendTransaction`
- `v0.2.x` chain usability is implemented:
  - `chain` and `batch` commands for multi-step workflows
  - template substitution across prior step outputs (`{{step_id.path}}`)
  - output extraction flags (`--result-only`, `--select`)
  - local transform helpers:
    - `hex_to_int`
    - `wei_to_eth`
    - `slice_last_20_bytes_to_address`
    - `abi_encode_call`
    - `abi_decode_output`
    - `abi_decode_log`
  - convenience commands:
    - `ens resolve <name>`
    - `balance <name-or-address> --at <tag>`
  - convenience domain extraction:
    - `scripts/convenience_ens_balance.py` now owns ENS resolution + balance orchestration used by wrapper commands
- analytics foundation (initial) is implemented:
  - `analytics dex-swap-flow`
  - `analytics factory-new-pools`
  - `analytics arbitrage-patterns`
  - shared analytics result envelope helpers: `scripts/analytics_envelopes.py`
  - shared analytics row decoders: `scripts/analytics_decoders.py`
  - shared analytics pool metadata helper: `scripts/analytics_pool_metadata.py`
  - shared analytics runtime helper: `scripts/analytics_runtime.py`
  - reusable range resolver (`--last-blocks` / `--since`) and resumable scan checkpoints
- R1 advanced capabilities (foundation + logs) are implemented:
  - `logs` command with chunked `eth_getLogs` workflows
  - heavy-read guard via `context.allow_heavy_read`
  - adaptive split and deterministic dedupe for large-range log scans
- R2 advanced capabilities (ABI + multicall) are implemented:
  - `abi` command with `encode_call`, `decode_output`, `decode_log`, selector/topic helpers
  - `multicall` command for aggregated `eth_call` workflows with per-call status and optional decode
- R3 advanced capabilities (simulation + trace) are implemented:
  - `simulate` command for `eth_call` + optional `eth_estimateGas` preflight
  - revert parsing for `Error(string)` and panic selectors
  - `trace` command with manifest/provider capability negotiation and `TRACE_UNSUPPORTED` fallback
- Coverage and policy tooling:
  - `scripts/build_method_manifest.py`
  - `scripts/coverage_check.py`
  - `scripts/validate_user_stories.py`
- Additional optional hardening remains:
  - R4 provenance completion
  - optional deeper `engine_*` payload preflight validation

## High-value commands
- List supported methods:
  - `python3 scripts/evm_rpc.py supported-methods --manifest references/method-manifest.json`
- Execute one JSON-RPC call through policy wrapper:
  - `python3 scripts/evm_rpc.py exec --manifest references/method-manifest.json --request-json '{"method":"eth_blockNumber","params":[],"context":{}}'`
- Execute a multi-step workflow:
  - `python3 scripts/evm_rpc.py chain --manifest references/method-manifest.json --request-json '{"steps":[{"id":"b","method":"eth_blockNumber","params":[]},{"id":"n","transform":"hex_to_int","input":"{{b.result}}"}]}'`
- Query logs with chunking:
  - `python3 scripts/evm_rpc.py logs --manifest references/method-manifest.json --request-json '{"filter":{"address":"0x1111111111111111111111111111111111111111","topics":[],"fromBlock":1,"toBlock":5000},"context":{"allow_heavy_read":true},"chunk_size":1000}'`
- Encode calldata from signature + args:
  - `python3 scripts/evm_rpc.py abi --request-json '{"operation":"encode_call","signature":"balanceOf(address)","args":["0x1111111111111111111111111111111111111111"]}'`
- Aggregate many reads:
  - `python3 scripts/evm_rpc.py multicall --manifest references/method-manifest.json --request-json '{"calls":[{"id":"a","to":"0x1111111111111111111111111111111111111111","signature":"balanceOf(address)","args":["0x1111111111111111111111111111111111111111"],"decode_output":["uint256"]}]}'`
- Simulation preflight:
  - `python3 scripts/evm_rpc.py simulate --manifest references/method-manifest.json --request-json '{"call_object":{"to":"0x1111111111111111111111111111111111111111","data":"0x70a082310000000000000000000000001111111111111111111111111111111111111111"},"include_estimate_gas":true}'`
- Trace request (if manifest/provider supports trace methods):
  - `python3 scripts/evm_rpc.py trace --manifest references/method-manifest.json --request-json '{"mode":"call","call_object":{"to":"0x1111111111111111111111111111111111111111","data":"0x1234"}}'`
- Balance convenience:
  - `python3 scripts/evm_rpc.py balance vitalik.eth --manifest references/method-manifest.json`
- ENS convenience:
  - `python3 scripts/evm_rpc.py ens resolve vitalik.eth --manifest references/method-manifest.json`
- Analytics (pool swap flow):
  - `python3 scripts/evm_rpc.py analytics dex-swap-flow --pool 0x1111111111111111111111111111111111111111 --last-blocks 5000 --manifest references/method-manifest.json`
- Analytics (factory new pools):
  - `python3 scripts/evm_rpc.py analytics factory-new-pools --factory 0x1111111111111111111111111111111111111111 --protocol uniswap-v2 --since 24h --manifest references/method-manifest.json`
- Analytics (block/window arbitrage pattern scan):
  - `python3 scripts/evm_rpc.py analytics arbitrage-patterns --block latest --manifest references/method-manifest.json`
  - `python3 scripts/evm_rpc.py analytics arbitrage-patterns --last-blocks 10 --manifest references/method-manifest.json`
  - `python3 scripts/evm_rpc.py analytics arbitrage-patterns --last-blocks 10 --summary-only --manifest references/method-manifest.json`
  - `python3 scripts/evm_rpc.py analytics arbitrage-patterns --last-blocks 100 --limit 100 --page 2 --page-size 10 --manifest references/method-manifest.json`
- Extract result for piping:
  - `python3 scripts/evm_rpc.py exec --manifest references/method-manifest.json --request-json '{"method":"eth_blockNumber","params":[]}' --result-only`
  - `python3 scripts/evm_rpc.py chain --manifest references/method-manifest.json --request-json '{"steps":[{"id":"b","method":"eth_blockNumber","params":[]}]}' --select '$.outputs.b.result'`
- Check manifest coverage:
  - `python3 scripts/coverage_check.py --inventory references/rpc-method-inventory.json --manifest references/method-manifest.json`

## References
- Coverage/archive plan: `docs/archive/plans/json-rpc-only-skill-plan.md`
- Method inventory data snapshot: `docs/data/execution-api-rpc-methods-2026-02-06.json`
- Risk model: `references/risk-tiers.md`
