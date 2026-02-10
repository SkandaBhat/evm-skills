# 2026-02-10: README Human-First Agent Usage Rewrite

## What changed
The top-level `README.md` was rewritten to focus on humans using Codex/Claude Code, not direct script invocation.

## Why
Most users consume this skill through an agent session. The top-level README should optimize for:
1. what workflows are supported,
2. how to prompt the agent effectively,
3. where implementation details live when needed.

## Content decisions captured
1. Consolidated capability messaging into a high-level features section.
2. Mapped implemented commands to concrete searcher workflows:
   - `analytics arbitrage-patterns`,
   - `analytics dex-swap-flow`,
   - `analytics factory-new-pools`,
   - `logs`,
   - `multicall`,
   - `simulate`,
   - `trace`,
   - `exec` for signed tx broadcast.
3. Replaced script-level quick start commands with agent-first prompt examples.
4. Removed internal script-path references from top-level README references.
5. Simplified prompt examples to concise standalone requests without repeating skill-selection boilerplate.
6. Preserved architectural constraints:
   - JSON-RPC-only workflow,
   - wrapper + cast hybrid runtime,
   - deterministic output shaping.

## Verification status
1. This was a documentation-only change.
2. No runtime behavior changes were introduced in this task.
