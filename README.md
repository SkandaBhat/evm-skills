# evm

Agent skill runtime for Ethereum JSON-RPC workflows with a cast-backed runtime.

This repo provides an `evm` skill with deterministic, policy-first commands for:
1. direct JSON-RPC execution,
2. multi-step chains with templating,
3. logs over ranges,
4. ABI encode/decode,
5. multicall-style aggregated reads,
6. simulation preflight,
7. trace negotiation.

## Runtime Requirements
1. `python3`
2. `cast` (Foundry CLI) available in `PATH`
3. `ETH_RPC_URL` provided by the user/session (not persisted by this skill)

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
Never invent or auto-select public RPC URLs.
If ETH_RPC_URL is missing, ask exactly:
"couldnt find an rpc url. give me an rpc url so i can add it to env."
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

### 3) General prompt pattern

```text
Using the evm skill, <goal>.
Use <command(s)>.
Return <exact output shape>.
If blocked by missing ETH_RPC_URL, ask me for it.
```

## References
- Skill entrypoint: `evm/SKILL.md`
- Runtime wrapper: `evm/scripts/evm_rpc.py`
- Documentation index: `docs/README.md`
