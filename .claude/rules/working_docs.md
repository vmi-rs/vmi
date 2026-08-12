# Working Docs Layout

Where working docs (design specs, plans, notes) live and how they are named.
This convention is shared across repositories.

## Location

These docs live under `.claude/`:

- Specs go in `.claude/specs/`, named `YYYY-MM-DD-<topic>-design.md`.
- Plans go in `.claude/plans/`, with the same date prefix.
- Notes go in `.claude/notes/`.

## Git status

The `.claude/` directory is in the global gitignore, so files created under
`.claude/specs/`, `.claude/plans/`, and `.claude/notes/` are local-only by
default and do not show up in `git status`. This is intentional. Do not
`git add -f` them unless the user asks. If a particular doc should be shared,
the user will say so.
