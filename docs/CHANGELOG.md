# Docs Changelog

## 2026-02-06
- Initialized project documentation structure under `docs/`.
- Added persistent docs maintenance rules (`docs/AGENTS.md`).
- Added Agent Skills spec findings.
- Added cast architecture and decoupling findings.
- Added cast command-path baseline (120 paths) and JSON snapshot.
- Added the first full implementation plan for 100% cast coverage.
- Updated the implementation plan with explicit test order and CI command sequence.
- Added fallback validation path when `skills-ref` is unavailable.
- Added initial implementation learning log for the first usable skill package.
- Linked the implemented skill package from docs index.
- Added `evm-cast-wallet` skill package with spec-compliant `SKILL.md`.
- Added cast wrapper tooling (`discover`, `manifest`, `policy`, `exec`, `coverage`, `validate` scripts).
- Added generated discovery and manifest files under `evm-cast-wallet/references/`.
- Added automated tests for discovery, policy, wrapper execution, coverage, and skill validation.
- Added ready-to-run request examples for read and broadcast execution flows.
