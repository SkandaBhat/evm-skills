# EVM Skills Docs

This directory is the source of truth for repository knowledge, decisions, and implementation plans.

## Operating Rules
- Read `docs/AGENTS.md` first.
- Treat `docs/learnings/` as the canonical history of technical findings.
- Treat `docs/plans/` as the canonical implementation plans.
- Keep `docs/CHANGELOG.md` updated whenever any learning or plan changes.

## Document Map

### Working agreement
- `docs/AGENTS.md`: Documentation maintenance rules for future agent runs.
- `docs/CHANGELOG.md`: Dated log of documentation updates.

### Learnings
- `docs/learnings/2026-02-06-agent-skills-spec.md`: Agent Skills spec and validation requirements.
- `docs/learnings/2026-02-06-openai-codex-skills-gap-check.md`: Gap check against OpenAI Codex skills docs and repo alignment notes.
- `docs/learnings/2026-02-06-skill-update-patterns-research.md`: Cross-ecosystem research on skill update/autoupdate patterns.
- `docs/learnings/2026-02-06-installed-session-findings.md`: Field-test findings that motivated cast deprecation.
- `docs/learnings/2026-02-06-execution-apis-rpc-inventory.md`: Complete method inventory from `ethereum/execution-apis`.
- `docs/learnings/2026-02-06-cast-deprecation-and-json-rpc-shift.md`: Decision log for removing cast and pivoting to JSON-RPC-only skill architecture.
- `docs/learnings/2026-02-06-user-stories-and-validation.md`: User story catalog and validation model tied to inventory/manifest coverage.
- `docs/learnings/2026-02-07-evm-wrapper-v0.1.md`: First packaged runtime wrapper implementation for the `evm` skill.
- `docs/learnings/2026-02-07-v0.2-adapter-hardening.md`: Adapter preflight validation and broadcast error mapping hardening.
- `docs/learnings/2026-02-07-chain-usability-expansion.md`: Chain/batch runtime expansion, output selectors, transforms, and ENS/balance convenience commands.
- `docs/data/execution-api-rpc-methods-2026-02-06.json`: Machine-readable inventory of 69 RPC methods.

### Plans
- `docs/plans/json-rpc-only-skill-plan.md`: End-to-end implementation plan for 100% JSON-RPC method coverage.
- `docs/plans/json-rpc-wrapper-architecture.md`: Detailed wrapper architecture (modules, contracts, policy, errors, testing).
- `docs/plans/chain-usability-expansion.md`: Detailed plan for multi-step chain execution and agent usability improvements.

### Skill Package
- `evm/SKILL.md`: JSON-RPC-only skill entrypoint.
- `evm/scripts/sync_execution_apis_inventory.py`: Inventory sync tooling from execution-apis checkout.
- `evm/scripts/evm_rpc.py`: Runtime JSON-RPC wrapper entrypoint.
- `evm/scripts/rpc_contract.py`: Request/response contract helpers.
- `evm/scripts/method_registry.py`: Manifest registry loader.
- `evm/scripts/policy_eval.py`: Policy gate evaluator.
- `evm/scripts/adapters.py`: Method-specific preflight validations for adapter methods.
- `evm/scripts/transforms.py`: Local transform helpers and ENS namehash support.
- `evm/scripts/rpc_transport.py`: JSON-RPC HTTP transport.
- `evm/scripts/error_map.py`: Stable error codes/messages.
- `evm/scripts/coverage_check.py`: Inventory/manifest coverage checker.
- `evm/references/rpc-method-inventory.json`: Source-of-truth method inventory for coverage tracking.
- `evm/references/method-manifest.json`: Tier/implementation mapping for all inventory methods.
- `evm/references/rpc-methods.md`: Human-readable method list by namespace.
- `evm/references/risk-tiers.md`: Initial risk and gating model for method classes.
- `evm/references/user-stories.json`: Machine-readable agent user stories.
- `evm/references/user-stories.md`: Human-readable user story catalog.
- `evm/scripts/build_method_manifest.py`: Regenerates method manifest from inventory.
- `evm/scripts/validate_user_stories.py`: Validates story schema, policy alignment, and coverage.
- `evm/tests/test_evm_rpc_wrapper.py`: Wrapper runtime integration tests.
- `evm/tests/test_user_story_validation.py`: Story validation tests.
