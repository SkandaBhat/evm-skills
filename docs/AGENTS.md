# Docs Maintenance Contract

This file defines how this repo should preserve knowledge over time.

## Core policy
1. Keep all substantive learnings in `docs/`.
2. Update documentation in the same task where the learning happens.
3. Keep the docs index (`docs/README.md`) current.
4. Add an entry in `docs/CHANGELOG.md` for every docs update.
5. Remove obsolete documentation when it no longer matches the active architecture.

## Where to put new information
- Technical discoveries, constraints, and architecture notes: `docs/learnings/<date>-<topic>.md`
- Execution plans and delivery milestones: `docs/plans/<topic>.md`
- Machine-readable snapshots or inventories: `docs/data/`

## Update triggers
Update docs whenever one of these occurs:
- A new external spec or tool behavior is verified.
- A command or API coverage baseline changes.
- A design decision is made or reversed.
- A rollout plan, milestone, or acceptance criterion changes.
- Legacy documentation is superseded and should be removed.

## Quality bar
- Include concrete dates in filenames and headings.
- State what is verified versus inferred.
- Link data and plan files from `docs/README.md`.
- Avoid undocumented decisions.
