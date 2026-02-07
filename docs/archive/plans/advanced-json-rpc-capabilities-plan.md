# Advanced JSON-RPC Capabilities Plan

## Objective
Implement the next layer of `evm` skill capabilities while keeping the runtime JSON-RPC-only contract and wrapper-first controls:
1. robust log querying,
2. ABI encode/decode workflows,
3. multicall aggregation,
4. simulation and safety preflight,
5. trace support,
6. stronger provenance in all outputs.

## Status (2026-02-07)
- R1 (foundation + logs) shipped:
  - `allow_heavy_read` context normalization.
  - logs-focused stable error taxonomy updates.
  - new `logs` command in `evm/scripts/evm_rpc.py`.
  - new `evm/scripts/logs_engine.py` with chunking, adaptive split, and dedupe.
- R2 (ABI + multicall) shipped:
  - new `abi` command in `evm/scripts/evm_rpc.py`.
  - new `evm/scripts/abi_codec.py` and ABI transforms in `evm/scripts/transforms.py`.
  - new `multicall` command in `evm/scripts/evm_rpc.py`.
  - new `evm/scripts/multicall_engine.py` for deterministic aggregated `eth_call` handling.
- R3 (simulation + trace) shipped:
  - new `simulate` command in `evm/scripts/evm_rpc.py`.
  - new `evm/scripts/simulate_engine.py` with revert decoding and gas-estimate preflight.
  - new `trace` command in `evm/scripts/evm_rpc.py`.
  - new `evm/scripts/trace_engine.py` with method negotiation and explicit unsupported behavior.
- Remaining:
  - R4 (provenance completion)

## Why this plan
The current runtime is strong for single-method and chained workflows, but power-user questions often require:
1. historical log scans over large ranges,
2. decoded calldata/logs/output,
3. many calls in one query,
4. simulation and revert diagnostics before action,
5. execution traces where nodes support them,
6. auditable metadata for every answer.

## Scope
In scope:
1. New runtime modules and CLI surfaces for the six capabilities above.
2. Shared contracts and output schema updates.
3. Policy additions for high-cost and high-risk read operations.
4. Test coverage for deterministic behavior and failure handling.

Out of scope:
1. Non-RPC analytics APIs.
2. Background indexer/database services.
3. Wallet key management.

## Design constraints
1. Preserve existing `exec` and `chain` compatibility.
2. Keep deterministic JSON output and explicit nonzero exits.
3. Keep `ETH_RPC_URL` requirements and no endpoint auto-selection.
4. Keep policy-first execution.

## Proposed module additions
`evm/scripts/`
1. `logs_engine.py`
   - Range chunking, adaptive splitting, and result normalization for `eth_getLogs`.
2. `abi_codec.py`
   - Function/event selector support, arg encoding, output/log decoding.
3. `multicall_engine.py`
   - Multicall request construction, chunking, decode integration.
4. `simulate_engine.py`
   - `eth_call` + `eth_estimateGas` preflight and revert extraction.
5. `trace_engine.py`
   - `debug_traceCall` / `trace_call` strategy with capability detection.
6. `provenance.py`
   - Uniform provenance block attached to all command outputs.

## CLI and request contract expansion
Add subcommands:
1. `logs`
2. `abi`
3. `multicall`
4. `simulate`
5. `trace`

Add request-level fields (where relevant):
1. `block_context`:
   - `block_tag` (`latest|safe|finalized|<hex|int>`)
   - `block_number`
   - `block_hash`
2. `provenance`:
   - `include_block_timestamp` (bool)
   - `include_request_hash` (bool)
3. `limits`:
   - `max_logs`
   - `max_chunks`
   - `max_calls_per_batch`

## Capability plan

### Phase A: Contracts and policy foundation
1. Extend shared request validators for new command payload shapes.
2. Add high-cost read guardrails:
   - `allow_heavy_read` context flag for logs/trace over large ranges.
3. Extend stable error taxonomy:
   - `LOGS_RANGE_TOO_LARGE`
   - `LOGS_TOO_MANY_RESULTS`
   - `ABI_ENCODE_FAILED`
   - `ABI_DECODE_FAILED`
   - `MULTICALL_PARTIAL_FAILURE`
   - `TRACE_UNSUPPORTED`
   - `SIMULATION_REVERTED`

Deliverables:
1. Updated `error_map.py`
2. Updated `rpc_contract.py` and `policy_eval.py`
3. Base tests for new validations

### Phase B: Logs engine (`eth_getLogs` at scale)
1. Implement chunked querying:
   - fixed chunk mode (`from_block..to_block` sliced by `chunk_size`)
   - adaptive bisection on provider errors/timeouts.
2. Implement deterministic merge and dedupe:
   - `(blockNumber, logIndex, transactionHash)` key.
3. Add strict limits:
   - fail with stable code when output exceeds budget.
4. Add optional decode hook for event ABI.

Deliverables:
1. `logs_engine.py`
2. `evm_rpc.py logs` command
3. integration tests with mocked paginated responses and failures

### Phase C: ABI codec helpers
1. Encode:
   - function selector and calldata from signature + args.
2. Decode:
   - function return values by signature.
   - event logs by signature/topic layout.
3. Add chain-friendly transforms usable from `chain`:
   - `abi_encode_call`
   - `abi_decode_output`
   - `abi_decode_log`

Deliverables:
1. `abi_codec.py`
2. `transforms.py` integration
3. tests with canonical ERC-20 / Uniswap V2 examples

### Phase D: Multicall support
1. Implement `multicall` command contract:
   - input list of calls (`to`, `data`, optional `decode` signature).
2. Implement client-side aggregated `eth_call` execution in chunked batches.
3. Return per-call status (`ok`/`error`) and decoded outputs when requested.
4. Optional future enhancement:
   - onchain multicall contract path with chain-aware address registry.

Deliverables:
1. `multicall_engine.py`
2. integration tests for partial failures and chunking

### Phase E: Simulation and safety preflight
1. Implement `simulate` command:
   - run `eth_call` for semantic result.
   - run `eth_estimateGas` for cost signal.
2. Decode common revert formats:
   - `Error(string)`
   - panic codes.
3. Add optional `state_override` pass-through where node supports it.
4. Add policy note for broadcast workflows:
   - recommended simulation step before `eth_sendRawTransaction`.

Deliverables:
1. `simulate_engine.py`
2. command + response schema
3. tests covering successful simulation and revert decoding

### Phase F: Trace support
1. Implement capability negotiation:
   - try preferred trace method order and cache support result.
2. Support:
   - `debug_traceCall`
   - `trace_call` (if available)
   - `debug_traceTransaction` for tx hash mode
3. Add normalization layer for different trace payload shapes.
4. Add explicit graceful failure when node does not support tracing.

Deliverables:
1. `trace_engine.py`
2. `trace` command
3. tests for unsupported-node and supported-node paths

### Phase G: Provenance everywhere
1. Add provenance block to every success/error payload:
   - `rpc_url_fingerprint` (hashed, not raw URL)
   - `request_hash`
   - `response_hash`
   - `queried_block_number`
   - `queried_block_hash`
   - `queried_block_timestamp_utc`
   - `client_timestamp_utc`
2. Ensure `--result-only` and `--select` still work without breaking JSON mode.

Deliverables:
1. `provenance.py`
2. response schema updates in `evm_rpc.py`
3. regression tests for existing commands

## Testing plan
1. Unit tests
   - ABI encode/decode correctness vectors
   - logs chunk planner and split logic
   - trace capability detection
2. Integration tests
   - mock RPC server for logs pagination, multicall partial failures, simulation reverts
3. Contract/regression tests
   - `exec`, `chain`, `ens resolve`, `balance` unchanged behavior
4. Validation commands
   - `pytest -q evm/tests`
   - coverage and user-story validators remain green

## Rollout plan
1. R1: foundation + logs (largest immediate value)
2. R2: ABI + multicall
3. R3: simulation + trace
4. R4: provenance completion + docs refresh

Each release gate:
1. full test pass
2. deterministic schema checks
3. no regression in existing CLI behavior

## Acceptance criteria
1. Agent can query large log ranges reliably with deterministic limits and stable errors.
2. Agent can encode/decode common contract interactions without ad-hoc scripts.
3. Agent can run many read calls efficiently through multicall with per-call status.
4. Agent can simulate transactions and receive normalized revert details.
5. Agent can obtain traces when supported and clear `TRACE_UNSUPPORTED` when not.
6. Every response includes enough provenance to audit the exact data snapshot.

## Risks and mitigations
1. Provider heterogeneity:
   - Mitigation: capability detection + fallback strategies + explicit unsupported codes.
2. Large response payloads:
   - Mitigation: chunking and strict caps with stable failure modes.
3. ABI mismatch errors:
   - Mitigation: explicit decode errors with selector/signature context.
4. Trace instability across clients:
   - Mitigation: normalized trace schema and per-client adapters.
