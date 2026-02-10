# 2026-02-10: Runtime Transport and Analytics Usability Learnings

## Context
During a live request to analyze Uniswap V2 WETH/USDC swap flow over the last 1000 blocks, we exercised:
1. `analytics dex-swap-flow`
2. `logs` with explicit `eth_getLogs` ranges
3. custom post-processing for top-k swap ranking

## Verified findings

### 1) `cast` transport can hard-fail under restricted sandbox runtime conditions
- Observed repeated `RPC_TRANSPORT_ERROR` failures with `cast` panic output:
  - `Attempted to create a NULL object`
  - stack includes `system-configuration` / `reqwest` path.
- During restricted sandbox mode, this affected calls that route through `cast` (for example `eth_blockNumber`, metadata `eth_call` inside analytics flows).
- After full network/danger-full-access mode was enabled in-session, direct `cast rpc` and wrapper `exec` calls against the same Alchemy endpoint succeeded.

Implication:
- This behavior was environment-specific (sandbox runtime), not a confirmed issue with the user RPC endpoint itself.
- Runtime resilience is still valuable because direct HTTP paths remained usable when cast-path calls failed.

### 2) `logs` path remained usable with user-provided RPC and direct HTTP transport
- `logs` succeeded when run with `ETH_RPC_URL` against the user-provided Alchemy endpoint.
- This path worked because `eth_getLogs` uses direct HTTP in `rpc_transport.py`.

Implication:
- Keeping a deterministic direct HTTP path for selected read methods is operationally valuable.

### 3) Adaptive split heuristics miss some provider quota/rate-limit errors
- Built-in pool attempts produced remote/provider errors such as:
  - `Failed to validate quota usage` (`-32603`)
  - HTTP `403` with raw `error code: 1010`
- Current `logs_engine.SPLIT_ERROR_PATTERNS` does not include explicit quota phrases like `quota`, `rate limit`, `validate quota usage`, `1010`.

Implication:
- Some retryable/reroutable provider failures are treated as terminal instead of split/retry/failover opportunities.

### 4) `analytics dex-swap-flow` does not provide built-in top-k ranking by absolute swap amount
- Command output includes full `rows` + aggregate `summary`.
- For "top 10 swaps by absolute amount", post-processing is currently required.

Implication:
- Common analyst workflows need extra client-side logic that could be first-class in the command.

### 5) Skill metadata should explicitly state internet dependency
- Session behavior confirmed that real RPC workflows require outbound network access.
- We updated `evm/SKILL.md` `compatibility` metadata to include outbound internet access to Ethereum JSON-RPC endpoints.

Implication:
- Users and orchestration layers get an upfront signal that the skill cannot run meaningfully in offline/sandboxed-no-network contexts.

## Recommended improvements

1. Add optional HTTP fallback for read-tier JSON-RPC methods when `cast` returns known process/panic transport failures.
2. Expand log split/retry pattern matching to include quota/rate-limit provider signatures (`quota`, `rate limit`, `1010`, `validate quota usage`).
3. Add `analytics dex-swap-flow` ranking controls, for example:
   - `--top-k N`
   - `--rank-by abs-token0|abs-token1|abs-usd-proxy`
   - optional `--summary-only` with ranked subset.
4. Add an integration test matrix case that simulates `cast` transport failure while verifying read-only fallback behavior (without changing broadcast safety posture).

## Verification status
1. Findings are based on live command executions during this session.
2. No runtime code changes were made in this task.
