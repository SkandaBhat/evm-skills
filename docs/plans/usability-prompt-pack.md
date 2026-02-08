# Usability Prompt Pack

Date: 2026-02-08

## Goal
Provide a fast, repeatable prompt suite to test usability and skill adherence for Codex/Claude sessions using the `evm` skill.

## Session Harness
Paste this first in every test session:

```text
Use the `evm` skill only.
For onchain operations, use skill commands only.
Do not use ad-hoc bash/curl/cast RPC calls unless the skill cannot do the task; if blocked, say why.
If ETH_RPC_URL is provided, use it; otherwise use the built-in default mainnet pool.
Do not persist RPC URLs to disk.
Prefer deterministic JSON output (`--compact`, `--result-only`, `--select`) when possible.
```

## Quick Pack (5 prompts)
Use this on every change.

1. Balance + ENS:
```text
Using the evm skill, get the ETH balance of vitalik.eth on ethereum mainnet.
Return JSON with fields: resolved_address, wei, eth, block_number, timestamp_utc.
```

2. ABI encode -> call -> decode:
```text
Using the evm skill, read USDC balanceOf(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045).
Do it as encode_call -> eth_call -> decode_output.
If decode_output returns a cast-style formatted numeric string (for example "12345 [1.234e4]"),
normalize it and return only the plain integer digits.
```

3. Logs with deterministic controls:
```text
Using the evm skill logs command, fetch ERC20 Transfer logs for USDC over the latest 100 blocks.
Use --event transfer and chunking.
Return summary plus first 3 rows only.
```

4. Multicall-style reads:
```text
Using the evm skill multicall command, fetch balanceOf for 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 on USDC and WETH.
Return one JSON object with per-call status and decoded outputs.
```

5. Simulate preflight:
```text
Using the evm skill simulate command, preflight this call object:
{"to":"0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","data":"0x70a08231000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"}
Include estimate gas.
If reverted, decode and show revert reason.
```

## Extended Pack (10 prompts)
Use this before release or after notable refactors.

1. Chain workflow with templating:
```text
Using the evm skill chain command, execute:
1) eth_getBalance for 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 at latest
2) transform wei_to_eth on the previous result
Return both wei and eth values.
```

2. Trace with fallback:
```text
Using the evm skill trace command, trace this eth_call payload:
{"to":"0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","data":"0x18160ddd"}
If trace is unsupported, return the TRACE_UNSUPPORTED payload clearly.
```

3. Analytics dex swap flow:
```text
Using the evm skill analytics dex-swap-flow command, scan this Uniswap V2 pair over the last 5000 blocks:
0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc
Return token metadata, rows, and summary.
```

4. Analytics factory pools:
```text
Using the evm skill analytics factory-new-pools command, scan Uniswap V2 factory for the last 24h:
0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f
Return only pool, token0, token1, tx hash.
```

5. Heavy-read guardrail check:
```text
Using the evm skill logs command, request a very large block range without allow_heavy_read.
Return the policy denial payload.
```

6. Result shaping check:
```text
Using the evm skill exec command for eth_blockNumber, return result only.
Do not return the full envelope.
```

7. JSONPath select check:
```text
Using the evm skill chain command, run a single eth_blockNumber step and return only $.outputs.<step_id>.result via --select.
```

8. Missing RPC UX check:
```text
Using the evm skill, perform eth_blockNumber with no ETH_RPC_URL available.
Use the built-in default pool; only request ETH_RPC_URL if the default pool fails.
```

9. Broadcast denial check:
```text
Using the evm skill, try eth_sendRawTransaction without allow_broadcast or confirmation_token.
Return the policy denial payload.
```

10. Local-sensitive denial check:
```text
Using the evm skill, try eth_sign without allow_local_sensitive.
Return the policy denial payload.
```

## Scoring Rubric
Score each run 0/1 for each item.

1. Skill adherence: no ad-hoc RPC via bash/curl/cast when skill path exists.
2. Correct guardrails: policy denials and RPC endpoint precedence/fallback UX are correct.
3. Command choice: uses the best-fit skill command for each prompt.
4. Output quality: shape matches request and is deterministic where requested.
5. Turn economy: completes in minimal back-and-forth.

Suggested thresholds:
1. Quick pack pass: at least 4/5.
2. Extended pack pass: at least 8/10.

## Run Log Template
Copy this per test session:

```text
Date:
Agent:
Branch/Commit:
RPC Provider:

Quick Pack:
1) PASS/FAIL - notes
2) PASS/FAIL - notes
3) PASS/FAIL - notes
4) PASS/FAIL - notes
5) PASS/FAIL - notes

Extended Pack:
1) PASS/FAIL - notes
2) PASS/FAIL - notes
3) PASS/FAIL - notes
4) PASS/FAIL - notes
5) PASS/FAIL - notes
6) PASS/FAIL - notes
7) PASS/FAIL - notes
8) PASS/FAIL - notes
9) PASS/FAIL - notes
10) PASS/FAIL - notes

Aggregate:
Quick score:
Extended score:
Key regressions:
```
