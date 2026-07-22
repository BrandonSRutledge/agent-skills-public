# Contributing (public catalog)

## Rules

1. **PUBLIC only** — if in doubt, it belongs in the private repo.
2. Every skill directory needs:
   - `SKILL.md`
   - `CLASSIFICATION.yaml` with `classification: PUBLIC`
3. No secrets, tokens, private hostnames, or customer data.
4. Prefer Apache-2.0 compatible contributions.

## PR checklist

- [ ] Classification is PUBLIC
- [ ] No secret-like files
- [ ] Description is accurate and safe to share
- [ ] CI passes

## CI

On every push/PR to `main`:

- PUBLIC-only classification + non-empty `SKILL.md` per skill
- Forbidden secret-like / sensitive paths
- **Gitleaks** secret content scan

Locally: ensure each skill under `skills/public/*/` has `CLASSIFICATION.yaml` (`classification: PUBLIC`) and a non-empty `SKILL.md`.
