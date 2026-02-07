# EVM Skills Docs

This directory is the source of truth for repository knowledge, decisions, and implementation plans.

## Operating Rules
- Read `docs/AGENTS.md` first.
- Keep `docs/learnings/` and `docs/plans/` aligned with the shipped implementation.
- Update `docs/CHANGELOG.md` for every documentation change.
- Remove obsolete documentation when it no longer reflects the current architecture.

## Document Map

### Working agreement
- `docs/AGENTS.md`: Documentation maintenance rules for future agent runs.
- `docs/CHANGELOG.md`: Dated log of documentation updates.
- `README.md`: Repository-level getting-started and human-to-agent prompt templates.

### Learnings
- `docs/learnings/2026-02-06-agent-skills-spec.md`: Agent Skills spec and validation requirements.
- `docs/learnings/2026-02-06-openai-codex-skills-gap-check.md`: Gap check against OpenAI Codex skills docs and repo alignment notes.
- `docs/learnings/2026-02-06-skill-update-patterns-research.md`: Cross-ecosystem research on skill update/autoupdate patterns.
- `docs/learnings/2026-02-06-execution-apis-rpc-inventory.md`: Complete method inventory from `ethereum/execution-apis`.
- `docs/learnings/2026-02-06-user-stories-and-validation.md`: User story catalog and validation model tied to inventory/manifest coverage.
- `docs/learnings/2026-02-07-evm-wrapper-v0.1.md`: First packaged runtime wrapper implementation for the `evm` skill.
- `docs/learnings/2026-02-07-v0.2-adapter-hardening.md`: Adapter preflight validation and broadcast error mapping hardening.
- `docs/learnings/2026-02-07-chain-usability-expansion.md`: Chain/batch runtime expansion, output selectors, transforms, and ENS/balance convenience commands.
- `docs/learnings/2026-02-07-r1-foundation-and-logs.md`: R1 rollout with heavy-read policy context and chunked `eth_getLogs` engine.
- `docs/learnings/2026-02-07-r2-r3-abi-multicall-simulate-trace.md`: R2/R3 rollout with ABI helpers, multicall, simulation preflight, and trace command support.

### Data snapshots
- `docs/data/execution-api-rpc-methods-2026-02-06.json`: Machine-readable inventory of 69 RPC methods.

### Plans
- `docs/plans/json-rpc-only-skill-plan.md`: End-to-end implementation plan for JSON-RPC method coverage.
- `docs/plans/json-rpc-wrapper-architecture.md`: Detailed wrapper architecture (modules, contracts, policy, errors, testing).
- `docs/plans/chain-usability-expansion.md`: Detailed plan for multi-step chain execution and agent usability improvements.
- `docs/plans/advanced-json-rpc-capabilities-plan.md`: Detailed plan for logs engine, ABI helpers, multicall, simulation, trace support, and provenance.

### Skill Package
- `evm/SKILL.md`: Skill entrypoint and usage rules.
- `evm/scripts/evm_rpc.py`: Runtime JSON-RPC wrapper entrypoint.
- `evm/scripts/rpc_contract.py`: Request/response contract helpers.
- `evm/scripts/method_registry.py`: Manifest registry loader.
- `evm/scripts/policy_eval.py`: Policy gate evaluator.
- `evm/scripts/adapters.py`: Method-specific preflight validations for adapter methods.
- `evm/scripts/transforms.py`: Local transform helpers and ENS namehash support.
- `evm/scripts/logs_engine.py`: Chunked log querying, adaptive split, and deterministic dedupe helpers.
- `evm/scripts/abi_codec.py`: ABI encode/decode utilities for call data, outputs, and logs.
- `evm/scripts/multicall_engine.py`: Client-side aggregated `eth_call` execution and partial-failure handling.
- `evm/scripts/simulate_engine.py`: Simulation preflight helpers (`eth_call` + optional `eth_estimateGas`) with revert parsing.
- `evm/scripts/trace_engine.py`: Trace method negotiation and unsupported-path normalization.
- `evm/scripts/rpc_transport.py`: JSON-RPC HTTP transport.
- `evm/scripts/error_map.py`: Stable error codes/messages.
- `evm/scripts/sync_execution_apis_inventory.py`: Inventory sync tooling from execution-apis checkout.
- `evm/scripts/build_method_manifest.py`: Regenerates method manifest from inventory.
- `evm/scripts/coverage_check.py`: Inventory/manifest coverage checker.
- `evm/scripts/validate_user_stories.py`: Validates story schema, policy alignment, and coverage.
- `evm/references/rpc-method-inventory.json`: Source-of-truth method inventory for coverage tracking.
- `evm/references/method-manifest.json`: Tier/implementation mapping for all inventory methods.
- `evm/references/rpc-methods.md`: Human-readable method list by namespace.
- `evm/references/risk-tiers.md`: Risk and gating model for method classes.
- `evm/references/user-stories.json`: Machine-readable agent user stories.
- `evm/references/user-stories.md`: Human-readable user story catalog.
- `evm/tests/test_evm_rpc_wrapper.py`: Wrapper runtime integration tests.
- `evm/tests/test_user_story_validation.py`: Story validation tests.
