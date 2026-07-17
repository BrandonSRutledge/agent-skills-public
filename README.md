# agent-skills-public

**Classification: PUBLIC**  
**Visibility: Public**

Safe, redistributable Grok skills and templates for Toolhead-Technology and the community.

## Boundary

| Allowed here | Never here |
|--------------|------------|
| Public-safe skills | Secrets, tokens, credentials |
| Generic templates | INTERNAL runbooks |
| Educational examples | SENSITIVE ops playbooks |
| Open documentation | Customer data / PII |

Internal and sensitive assets live only in the private sibling repository (org members):

`Toolhead-Technology/agent-skills-private`

## Layout

```text
skills/public/     # Published skills (each with CLASSIFICATION.yaml = PUBLIC)
templates/         # Starters for new public skills
docs/              # Contributor and security guidance
```

## Contribute

1. Open a PR.
2. Every skill must include `CLASSIFICATION.yaml` with `classification: PUBLIC`.
3. No secret-like filenames (`.env`, `*.pem`, etc.).
4. CI must pass.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately when possible.

## License

Apache-2.0 (see [LICENSE](LICENSE)) unless a skill directory states otherwise.
