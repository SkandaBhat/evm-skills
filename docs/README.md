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
- `docs/data/execution-api-rpc-methods-2026-02-06.json`: Machine-readable inventory of 69 RPC methods.

### Plans
- `docs/plans/json-rpc-only-skill-plan.md`: End-to-end implementation plan for 100% JSON-RPC method coverage.
- `docs/plans/json-rpc-wrapper-architecture.md`: Detailed wrapper architecture (modules, contracts, policy, errors, testing).

### Skill Package
- `evm-jsonrpc-wallet/SKILL.md`: JSON-RPC-only skill entrypoint.
- `evm-jsonrpc-wallet/scripts/sync_execution_apis_inventory.py`: Inventory sync tooling from execution-apis checkout.
- `evm-jsonrpc-wallet/references/rpc-method-inventory.json`: Source-of-truth method inventory for coverage tracking.
- `evm-jsonrpc-wallet/references/method-manifest.json`: Tier/implementation mapping for all inventory methods.
- `evm-jsonrpc-wallet/references/rpc-methods.md`: Human-readable method list by namespace.
- `evm-jsonrpc-wallet/references/risk-tiers.md`: Initial risk and gating model for method classes.
- `evm-jsonrpc-wallet/references/user-stories.json`: Machine-readable agent user stories.
- `evm-jsonrpc-wallet/references/user-stories.md`: Human-readable user story catalog.
- `evm-jsonrpc-wallet/scripts/build_method_manifest.py`: Regenerates method manifest from inventory.
- `evm-jsonrpc-wallet/scripts/validate_user_stories.py`: Validates story schema, policy alignment, and coverage.
