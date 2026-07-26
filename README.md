# agent-skills-public

<!-- HOUSE_BADGE:START -->
![house_scan 100%](https://img.shields.io/static/v1?label=house_scan&message=100%25&color=brightgreen)
<!-- HOUSE_BADGE:END -->

<!-- HOUSE_COMPLIANCE:START -->
| Scanner (badge) | Waiver |
|-----------------|--------|
| ![baseline.secret_paths 100%](https://img.shields.io/static/v1?label=secret_paths&message=100%25&color=brightgreen) | — |
| ![baseline.gitleaks 100%](https://img.shields.io/static/v1?label=gitleaks&message=100%25&color=brightgreen) | — |
| ![baseline.waiver_schema 100%](https://img.shields.io/static/v1?label=waiver_schema&message=100%25&color=brightgreen) | — |
| ![baseline.workflow_softfail 100%](https://img.shields.io/static/v1?label=workflow_softfail&message=100%25&color=brightgreen) | — |
| ![house_scan.overall 100%](https://img.shields.io/static/v1?label=Overall&message=100%25&color=brightgreen) | |
<!-- HOUSE_COMPLIANCE:END -->

**Classification: PUBLIC**  
**Visibility: Public**

Safe, redistributable Grok skills and templates for the community.

## Boundary

| Allowed here | Never here |
|--------------|------------|
| Public-safe skills | Secrets, tokens, credentials |
| Generic templates | INTERNAL runbooks |
| Educational examples | SENSITIVE ops playbooks |
| Open documentation | Customer data / PII |

Internal and sensitive assets live only in the private sibling repository (org members):

`BrandonSRutledge/agent-skills-private`

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
