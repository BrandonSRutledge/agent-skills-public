# Public / Private Boundary

```text
                    ┌─────────────────────────────┐
                    │   Repo owner (personal)   │
                    └─────────────┬───────────────┘
                                  │
              ┌───────────────────┴───────────────────┐
              │                                       │
              ▼                                       ▼
   ┌──────────────────────┐             ┌──────────────────────────┐
   │ agent-skills-public  │             │ agent-skills-private     │
   │ visibility: PUBLIC   │             │ visibility: PRIVATE      │
   │ class: PUBLIC only   │             │ class: INTERNAL|SENSITIVE│
   └──────────────────────┘             └────────────┬─────────────┘
                                                     │
                                          mandatory checkout + audit
                                          for SENSITIVE assets
```

## Flow control (NIST AC-4 / SC-7)

- **Public → Private:** not applicable (public has no sensitive data).
- **Private → Public:** only via **reclassification PR** + dual approval + content scrub.
- **Never:** git submodule the private repo into the public repo.

## Tags

Assets should carry classification in `CLASSIFICATION.yaml`.  
Anything tagged `sensitive: true` is forbidden in this repository.
