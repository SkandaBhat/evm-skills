# JSON-RPC Only Skill Plan

## Goal
Ship an agent skill that provides 100% coverage of JSON-RPC methods defined in `ethereum/execution-apis`, without any `cast` dependency.

## Status (2026-02-07)
- Completed:
  - Phase 1 (inventory/scaffolding)
  - Phase 2 (core runtime wrapper in `evm/scripts/evm_rpc.py`)
  - method manifest + story validation tooling
- Remaining:
  - deeper method-specific adapters for sensitive/operator paths
  - CI wiring and release hardening

## Scope baseline
- Source repository: <https://github.com/ethereum/execution-apis>
- Snapshot commit: `585763b34564202d4611d318006ea1f3efb43616`
- Snapshot data: `docs/data/execution-api-rpc-methods-2026-02-06.json`
- Method count: `69`
  - `eth`: `40`
  - `debug`: `5`
  - `engine`: `24`

## Non-goals
- No `cast` integration or `cast` fallback.
- No RPC URL persistence to disk.

## Architecture
Detailed module-level architecture lives in:
- `docs/plans/json-rpc-wrapper-architecture.md`

1. Method registry
   - Generated inventory from `execution-apis` YAML definitions.
   - Canonical file: `evm/references/rpc-method-inventory.json`.
2. RPC wrapper
   - Build `scripts/evm_rpc.py` with JSON request/response contract:
     - request: `method`, `params`, `id`, `context`, optional `env`.
     - response: `status`, `error_code`, `result`, `rpc_error`, `duration_ms`, `policy`.
3. Policy engine
   - Risk tiers: `read`, `local-sensitive`, `broadcast`, `operator`.
   - Explicit gates:
     - `allow_local_sensitive`
     - `allow_broadcast`
     - `allow_operator`
     - `confirmation_token` for `broadcast` and `operator`.
4. Environment model
   - Require `ETH_RPC_URL` for all networked methods.
   - If missing: return `RPC_URL_REQUIRED` with message:
     - `couldnt find an rpc url. give me an rpc url so i can add it to env.`
   - Never auto-select public RPC endpoints.
5. Method adapters
   - Phase 1: generic pass-through for `eth_*`/`debug_*`.
   - Phase 2: stricter adapter behavior and validation for sensitive methods.
   - Phase 3: explicit handling for `engine_*` methods and operator gating.

## Coverage definition
`coverage = implemented + intentionally_denied_with_reason`

Every method in inventory must have one of:
1. executable implementation path, or
2. policy denial path with stable reason code and remediation guidance.

## Delivery phases

### Phase 1: Inventory and scaffolding
1. Keep method inventory synced from `execution-apis`.
2. Add `evm/SKILL.md` and references.
3. Add wrapper request/response schema docs.

### Phase 2: Core runtime
1. Implement `scripts/evm_rpc.py`.
2. Implement policy layer and standardized errors.
3. Implement explicit RPC URL enforcement.

### Phase 3: 100% method mapping
1. Add method manifest with tier and support status for all `69` methods.
2. Mark each method as:
   - `implemented`
   - `denied` with reason code
3. Add machine-checked coverage report.

### Phase 4: Test and validation
1. Unit tests
   - request validation
   - policy gating
   - error normalization
2. Integration tests
   - mock JSON-RPC server responses
   - end-to-end wrapper behavior
3. Coverage tests
   - fail CI if inventory count != manifest count
   - fail CI if any method is unmapped
4. Story validation
   - validate `references/user-stories.json` against inventory + manifest
   - fail CI if required story coverage threshold is not met

### Phase 5: Packaging and rollout
1. Place skill under `.agents/skills/evm` for Codex repo discovery.
2. Keep path-install instructions for clients that install snapshots.
3. Publish update workflow:
   - sync inventory
   - run coverage checks
   - run tests
   - commit versioned docs/data updates.

## Test strategy
1. Deterministic local tests
   - no live RPC required.
2. Optional live smoke tests
   - gated by explicit `ETH_RPC_URL`.
3. Contract tests for user-safe behavior
   - missing RPC URL prompts user, not endpoint hallucination.
   - no hidden fallback to external public RPCs.

## Acceptance criteria
1. `cast` files removed from repo.
2. Skill metadata and docs describe JSON-RPC-only model.
3. Inventory includes all methods from upstream snapshot.
4. Coverage checker proves all methods are mapped.
5. Tests pass in CI for wrapper, policy, and coverage.
