# Agent instructions — agent-skills-public

## Classification

- **PUBLIC only.** No INTERNAL/SENSITIVE content, secrets, or private hostnames.

## Skills discipline

| Intent | Where |
|--------|--------|
| Issue work (plan → checks → close) | **issue-lifecycle** in `agent-skills-private` (INTERNAL process) + ops session |
| New **public** catalog skill | Follow PUBLIC layout (`CLASSIFICATION.yaml` = PUBLIC); do **not** use **new-repo** for public repos |
| New **private** repo | **new-repo** skill (SENSITIVE) — private only |
| Session check-in | `ops-coordination` |

Always load the matching skill from disk when intent matches.

## Issue lifecycle

Document acceptance criteria before code; close only when checks are green; ops session check-in/out for multi-session work. See `ops-coordination/docs/ISSUE_LIFECYCLE.md`.
