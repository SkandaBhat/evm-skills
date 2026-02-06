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
- `docs/learnings/2026-02-06-cast-architecture-and-decoupling.md`: Architecture findings from the upstream `cast` crate and decoupling assessment.
- `docs/learnings/2026-02-06-cast-baseline.md`: Baseline command-path inventory for cast coverage.
- `docs/learnings/2026-02-06-initial-skill-implementation.md`: Initial usable skill implementation and verification results.
- `docs/data/cast-command-paths-2026-02-06.json`: Machine-readable command-path snapshot.

### Plans
- `docs/plans/100-percent-cast-coverage-plan.md`: End-to-end implementation plan for full cast command coverage.

### Skill Package
- `evm-cast-wallet/SKILL.md`: Agent Skills package entrypoint.
- `evm-cast-wallet/scripts/`: Discovery, manifest, policy, execution, and coverage tooling.
- `evm-cast-wallet/references/`: Generated discovery snapshot, manifest, and operation guides.
- `evm-cast-wallet/tests/`: Initial automated test suite.
