---
name: evm
description: Agent workflow for EVM operations using Ethereum JSON-RPC only (no cast dependency), with method coverage aligned to ethereum/execution-apis.
license: Proprietary. LICENSE.txt has complete terms
compatibility: Requires python3 and an RPC endpoint provided by ETH_RPC_URL.
---

# EVM JSON-RPC Wallet Skill

Use this skill for EVM tasks through Ethereum JSON-RPC only.

## Core rules
1. Do not invoke `cast`.
2. Do not invent or auto-select public RPC URLs.
3. Require `ETH_RPC_URL` for RPC-dependent operations.
4. If `ETH_RPC_URL` is missing, ask:
   - `couldnt find an rpc url. give me an rpc url so i can add it to env.`
5. Do not persist RPC URLs to disk.

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
- `v0.2` adapter hardening is implemented for:
  - `eth_accounts`
  - `eth_sign`
  - `eth_signTransaction`
  - `eth_sendRawTransaction`
  - `eth_sendTransaction`
- Coverage and policy tooling:
  - `scripts/build_method_manifest.py`
  - `scripts/coverage_check.py`
  - `scripts/validate_user_stories.py`
- Additional optional `engine_*` payload preflight hardening is tracked as backlog.

## High-value commands
- List supported methods:
  - `python3 scripts/evm_rpc.py supported-methods --manifest references/method-manifest.json`
- Execute one JSON-RPC call through policy wrapper:
  - `python3 scripts/evm_rpc.py exec --manifest references/method-manifest.json --request-json '{"method":"eth_blockNumber","params":[],"context":{}}'`
- Check manifest coverage:
  - `python3 scripts/coverage_check.py --inventory references/rpc-method-inventory.json --manifest references/method-manifest.json`

## References
- Coverage plan: `docs/plans/json-rpc-only-skill-plan.md`
- Method inventory learning note: `docs/learnings/2026-02-06-execution-apis-rpc-inventory.md`
- Risk model: `references/risk-tiers.md`
