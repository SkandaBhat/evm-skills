# Installed Session Findings (2026-02-06)

Note: This is a historical record from the removed cast-based skill and is retained as migration rationale.

## Scope
This note captures learnings from a real Codex session where `evm-cast-wallet` was installed at `~/.codex/skills/evm-cast-wallet` and used for `balance vitalik.eth`.

## What worked
- The agent correctly activated the skill flow:
  - Read `SKILL.md` and references.
  - Queried supported command paths from wrapper.
  - Executed `scripts/evm_cast.py exec` for policy-governed command execution.
- The agent recovered to a working answer using JSON-RPC fallback and reported:
  - ENS resolution result.
  - Balance snapshot with block number and timestamp context.

## What failed
- `cast` network commands crashed with a Foundry panic:
  - `Attempted to create a NULL object.`
  - location in `system-configuration ... dynamic_store.rs`
  - backtrace includes `hyper_util::client::proxy::matcher::mac::with_system`.
- Disabling proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) did not reliably prevent failure in this environment.

## Key lessons
1. Wrapper alone is not enough when upstream `cast` binary panics at runtime.
2. Skill needs first-class handling for known panic signatures, not generic `EXEC_FAILED` only.
3. For read-only paths, a deterministic JSON-RPC fallback path is required for reliability.
4. Balance answers should always include snapshot context (`block`, `block_timestamp_utc`) to avoid ambiguous numbers.
5. Installed-snapshot behavior is confirmed:
   - Skill executes from `~/.codex/skills/...`.
   - Remote push does not automatically rewrite that snapshot.

## Recommended implementation upgrades
1. Add panic classification in `scripts/evm_cast.py`:
   - Detect known signature and return `error_code=CAST_PANIC_PROXY_DETECTION`.
   - Include actionable hint to switch to fallback read flow.
2. Add a built-in fallback script for read operations:
   - Start with ENS resolve + `eth_getBalance` + block timestamp in one atomic request flow.
3. Add tests that simulate panic stderr and verify classification.
4. Keep fallback restricted to read-only methods unless explicitly approved for writes.

## Source
- Interactive run transcript shared by user (installed-skill session on 2026-02-06).
