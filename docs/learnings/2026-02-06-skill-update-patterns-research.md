# Skill Update Patterns Research (2026-02-06)

## Scope
Surveyed how currently available skill ecosystems handle updates after a skill is installed, with emphasis on Codex-compatible and Agent-Skills-compatible flows.

## Findings

### 1) OpenAI Codex: local change detection, not remote push propagation
- Codex docs state that skill changes are detected automatically.
- If a change does not appear, restart is the fallback.
- Codex also detects newly installed skills automatically with restart as fallback.
- This is runtime reload/discovery behavior, not remote auto-pull from GitHub.

Implication:
- Pushing to GitHub does not update already-installed snapshots on other machines by itself.

### 2) OpenAI skill-installer behavior is install-oriented
- Official skill-installer guidance emphasizes install flow and restart after install.
- The shipped installer implementation (local sample) aborts if destination already exists.

Implication:
- Out of the box, update is not “silent in-place auto-update”; it is reinstall/replace style.

### 3) Agent Skills spec is format/integration focused, not update-policy focused
- The Agent Skills specification defines folder/schema/validation/progressive-disclosure behavior.
- It does not define a standardized auto-update protocol for installed skills.

Implication:
- Update policy is host/tooling-specific, not spec-level.

### 4) Third-party tools add explicit update commands
- `openskills`: supports `openskills update [name...]` and notes that older installs may need a one-time reinstall to track update sources.
- `skillport`: supports `skillport update` (“update all from original sources”).

Implication:
- Most practical “autoupdate” in the ecosystem is explicit pull/sync/update commands, often driven by stored source metadata.

### 5) Claude plugin workflow indicates install/restart and explicit refresh loops
- Official Claude plugin docs repeatedly instruct restart after install/changes in common workflows.
- Dev loop examples use uninstall/reinstall or restart cycles.

Implication:
- Even in plugin ecosystems, update is typically explicit user/tool action, not universal background auto-update of installed skill bundles.

## Practical conclusion for `evm-jsonrpc-wallet`
Use a predictable update model:
1. Keep repo skill canonical and versioned.
2. Support explicit update workflows (documented commands) rather than implicit remote auto-update assumptions.
3. Prefer host-native discovery/hot-reload for local checked-in skills.
4. For installed snapshots, require refresh/reinstall/update command.

## Sources
- <https://developers.openai.com/codex/skills>
- <https://github.com/openai/skills>
- <https://agentskills.io/specification>
- <https://agentskills.io/integrate-skills>
- <https://github.com/numman-ali/openskills>
- <https://github.com/gotalab/skillport>
- <https://code.claude.com/docs/en/plugins>
