# evm

`evm` is an Ethereum JSON-RPC skill for agent workflows.

It gives you a policy-first wrapper for safety and consistency, while delegating low-level RPC/ABI execution to `cast`.

It provides structured workflows for block inspection, DEX activity analysis, preflight simulation, and failure diagnosis without one-off glue scripts.

## High-Level Features

- Block triage for arb-like routes across single blocks or recent windows.
- Pool-level swap flow summaries.
- New pool discovery from factory events.
- Chunked, resumable log scanning with adaptive split and deterministic dedupe.
- Batched multi-contract state snapshots.
- Pre-trade simulation and revert parsing.
- Signed transaction broadcast through the same policy path.

## Runtime Requirements

1. `python3`
2. `cast` (Foundry CLI) in `PATH`
3. Optional `ETH_RPC_URL` if you want a specific endpoint.

If `ETH_RPC_URL` is not set, the wrapper uses a built-in Ethereum mainnet pool and does not persist URLs:
1. `https://ethereum-rpc.publicnode.com`
2. `https://eth.drpc.org`
3. `https://1rpc.io/eth`
4. `https://eth.llamarpc.com`

For larger analytics windows, provider quotas can cause 429/range errors. Prefer a dedicated `ETH_RPC_URL`, and tune `--chunk-size` and `--max-chunks` (or reduce the window with `--last-blocks`). `--since` can be more rate-limit prone because it resolves block timestamps first.

## Install (Codex / Claude Code)

Use the official installation guides:
- [Codex skills](https://developers.openai.com/codex/skills/)
- [Claude Code skills](https://docs.anthropic.com/en/docs/claude-code/skills)

After installing this repository's `evm` skill, restart your Codex or Claude Code session if it does not appear immediately.

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
Analyze the weth/usdc uniswap v2 pool over the last 1000 blocks.
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

## Roadmap

Wishlist items:
- Broader DEX analytics coverage beyond Uniswap (additional pool/event models).
- Smarter provider-aware scan tuning with automatic backoff and chunk-size adaptation.
- Higher-signal route triage scoring with clearer reason labels for candidate ranking.
- Richer wallet intelligence workflows (balances, approvals, and exposure snapshots).
- First-class report outputs for downstream automation and dashboard ingestion.

## References

- Codex repo-discovery path: `.agents/skills/evm` (symlink to `evm/`)
- Skill entrypoint: `evm/SKILL.md`
- [Codex skills docs](https://developers.openai.com/codex/skills/)
- [Claude Code skills docs](https://docs.anthropic.com/en/docs/claude-code/skills)

## License

MIT. See `LICENSE`.
