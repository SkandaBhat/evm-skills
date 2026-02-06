---
name: evm-cast-wallet
description: Agent workflow for EVM operations via Foundry cast with full command-path coverage tracking. Use this skill for chain queries, ABI encoding/decoding, tx construction/signing/sending, tracing, logs, ENS, and wallet/keystore actions when the environment has cast installed.
license: Proprietary. LICENSE.txt has complete terms
compatibility: Requires cast and python3. RPC-dependent commands require reachable RPC endpoints.
---

# EVM Cast Wallet Skill

Use this skill when the task requires EVM operations and `cast` is available.

## Primary workflow
1. Load command coverage baseline from `references/discovered-cast-paths.json`.
2. Validate command policy and mapping in `references/command-manifest.json`.
3. Execute via `scripts/evm_cast.py` instead of raw `cast` calls.
4. Use JSON response from wrapper for downstream reasoning and retries.

## Safety model
- `read`: safe read/query/transform commands.
- `local-sensitive`: key, signer, or keystore-sensitive commands.
- `broadcast`: state-changing or externally published actions.

Always enforce policy before execution. The wrapper handles this automatically.

## High-value commands
- Discovery and baseline:
  - `python3 scripts/discover_cast_tree.py --output references/discovered-cast-paths.json`
- Manifest generation:
  - `python3 scripts/build_manifest.py --discovered references/discovered-cast-paths.json --output references/command-manifest.json`
- Coverage validation:
  - `python3 scripts/check_coverage.py --discovered references/discovered-cast-paths.json --manifest references/command-manifest.json`
- Execute command:
  - `python3 scripts/evm_cast.py exec --request-file references/examples-read-request.json`

## Command execution contract
Request JSON:
- `command_path`: space-delimited cast command path (example: `wallet new`)
- `args`: argument array appended after command path
- `context`: policy flags (`allow_local_sensitive`, `allow_broadcast`, `confirmation_token`)
- `timeout_seconds`: command timeout

Response JSON includes:
- `status`: `ok`, `denied`, `error`, or `timeout`
- `error_code`: stable machine code for failures
- `stdout`, `stderr`, `exit_code`
- `parsed_stdout_json` when stdout is valid JSON
- `policy` decision details

## References
- Policy details: `references/risk-tiers.md`
- Request/response examples: `references/examples.md`
- Troubleshooting: `references/troubleshooting.md`
