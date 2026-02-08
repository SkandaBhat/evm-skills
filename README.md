# evm

Agent skill runtime for Ethereum JSON-RPC workflows with a cast-backed runtime.

This repo provides an `evm` skill with deterministic, policy-first commands for:
1. direct JSON-RPC execution,
2. multi-step chains with templating,
3. logs over ranges,
4. ABI encode/decode,
5. multicall-style aggregated reads,
6. simulation preflight,
7. trace negotiation,
8. high-level analytics commands (`analytics dex-swap-flow`, `analytics factory-new-pools`).

## Runtime Requirements
1. `python3`
2. `cast` (Foundry CLI) available in `PATH`
3. Optional `ETH_RPC_URL` from user/session to override the default public pool (never persisted by this skill)

Default mainnet pool (used only when `ETH_RPC_URL` is not set):
1. `https://ethereum-rpc.publicnode.com`
2. `https://eth.drpc.org`
3. `https://1rpc.io/eth`
4. `https://eth.llamarpc.com`

Architecture split:
1. Wrapper-owned: policy gates, safety controls, chain templating, deterministic envelopes, logs orchestration.
2. Cast-delegated: low-level JSON-RPC calls, ABI encode/decode primitives, selectors/topic hashes, wei/namehash utilities.

## Prompting Agents
Use this section when a human is interacting with an agent like Codex or Claude Code.

### 1) Start every session with this preamble

```text
Use the `evm` skill only.
Use JSON-RPC only via the skill wrapper commands.
Require cast as the low-level runtime; do not replace the wrapper with ad-hoc scripts.
Use `ETH_RPC_URL` when the user provides one; otherwise use the skill's default Ethereum mainnet RPC pool.
Do not persist RPC URLs to disk.
Prefer deterministic JSON output (`--compact`, `--result-only`, `--select`) when possible.
```

### 2) Reusable prompt templates

Balance and ENS:

```text
Using the evm skill, get the ETH balance of vitalik.eth on ethereum mainnet.
Return JSON with resolved address, wei, eth, block number, and timestamp.
```

ABI encode -> call -> decode:

```text
Using the evm skill, read USDC balanceOf(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045).
Do it as encode_call -> eth_call -> decode_output and return only the decoded integer.
```

Multicall-style token reads:

```text
Using the evm skill multicall command, fetch balanceOf for the same address on USDC and WETH.
Return one JSON object with per-call status and decoded outputs.
```

Logs query:

```text
Using the evm skill logs command, fetch Transfer logs for USDC between blocks 22000000 and 22001000.
Use chunking and return summary plus first 3 logs only.
```

Simulation preflight:

```text
Using the evm skill simulate command, preflight this call object and include estimate gas.
If reverted, decode and show revert reason.
```

Trace with graceful fallback:

```text
Using the evm skill trace command, trace this call.
If trace is unsupported, return the TRACE_UNSUPPORTED payload clearly.
```

Searcher-style analytics:

```text
Using the evm skill analytics dex-swap-flow command, scan this Uniswap V2 pair over the last 5000 blocks.
Return token0/token1 metadata, per-swap rows, and net pool flow summary.
```

```text
Using the evm skill analytics factory-new-pools command, find new pools created by this factory over the last 24h.
Return only pool address, token0, token1, and tx hash.
```

### 3) General prompt pattern

```text
Using the evm skill, <goal>.
Use <command(s)>.
Return <exact output shape>.
If reliability/privacy is important, ask me for `ETH_RPC_URL` and use it as override.
```

## References
- Codex repo-discovery alias: `.agents/skills/evm` (symlink to `evm/`)
- Skill entrypoint: `evm/SKILL.md`
- Runtime wrapper: `evm/scripts/evm_rpc.py`
- Documentation index: `docs/README.md`
