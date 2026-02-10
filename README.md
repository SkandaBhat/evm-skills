# evm

`evm` is a searcher-oriented Ethereum JSON-RPC skill.

It gives you a policy-first wrapper for safety and consistency, while delegating low-level RPC/ABI execution to `cast`.

If you want to inspect blocks, decode DEX activity, preflight actions, and debug failures without writing one-off glue scripts, this is what it is built for.

## High-Level Features

- Block triage for arb-like routes with `analytics arbitrage-patterns` (single block or windows via `--last-blocks` / `--since`).
- Pool-level swap flow summaries with `analytics dex-swap-flow`.
- New pool discovery from factory events with `analytics factory-new-pools`.
- Chunked, resumable log scanning with `logs` (adaptive split + deterministic dedupe).
- Batched `eth_call` snapshots with `multicall`.
- Pre-trade simulation and revert parsing with `simulate`.
- Trace-based root-cause workflows with `trace` (provider-method negotiation included).
- Signed transaction broadcast through the same policy path with `exec`.

## Runtime Requirements

1. `python3`
2. `cast` (Foundry CLI) in `PATH`
3. Optional `ETH_RPC_URL` if you want a specific endpoint.

If `ETH_RPC_URL` is not set, the wrapper uses a built-in Ethereum mainnet pool and does not persist URLs:
1. `https://ethereum-rpc.publicnode.com`
2. `https://eth.drpc.org`
3. `https://1rpc.io/eth`
4. `https://eth.llamarpc.com`

## Quick Start (Codex/Claude Code)

1. Start your session with the prompt preamble below.
2. Ask for one concrete workflow (examples included right after).
3. Keep outputs deterministic with `--result-only` or `--select` when needed.

## Agent Prompt Starter

Use this when you want an agent to stay inside the intended operating model:

```text
Use the `evm` skill only.
Use JSON-RPC only through the wrapper commands.
Require cast as the low-level runtime.
Use ETH_RPC_URL when I provide it; otherwise use the skill's default pool.
Do not persist RPC URLs.
Prefer deterministic output with --result-only or --select.
```

## Prompt Examples

Inspect latest block for arb-like routes:

```text
Analyze the latest Ethereum block for arb-like swap routes.
Return the top 5 candidates with tx hash, inferred token path, and reason.
```

Summarize pool flow:

```text
Analyze this Uniswap V2 pool over the last 1000 blocks.
Return token metadata, net directional flow, and top 10 swaps by absolute amount.
```

Preflight call and decode failures:

```text
Simulate this call object and include gas estimate.
If it reverts, decode and return the revert reason.
```

## Architecture Snapshot

Wrapper-owned responsibilities:
- Policy gates.
- Request/response normalization.
- Chain templating and transforms.
- Deterministic logs orchestration and analytics envelopes.

Cast-owned responsibilities:
- Low-level JSON-RPC transport for most methods.
- ABI primitives and utility conversions.

## References

- Codex repo-discovery path: `.agents/skills/evm` (symlink to `evm/`)
- Skill entrypoint: `evm/SKILL.md`
- Documentation index: `docs/README.md`
