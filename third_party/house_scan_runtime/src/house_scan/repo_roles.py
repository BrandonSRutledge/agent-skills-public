"""House repo role labels (app, library, ops, …). See ops docs/REPO_CATALOG.md."""
from __future__ import annotations

from pathlib import Path

# dirname -> (kind, shields color)
REPO_ROLES: dict[str, tuple[str, str]] = {
    "ai-nexus-veil-of-awakening": ("app", "purple"),
    "ops-coordination": ("ops", "important"),
    "agent-skills-private": ("skills-library", "blueviolet"),
    "agent-skills-public": ("skills-library", "blueviolet"),
    "house-security-library": ("library", "blue"),
    "house-security-cis-controls": ("compliance-framework", "informational"),
    "house-security-soc2": ("compliance-framework", "informational"),
    "house-security-owasp-asvs": ("compliance-framework", "informational"),
    "house-security-iso27001": ("compliance-framework", "informational"),
    "house-security-iso42001": ("compliance-framework", "informational"),
    "house-security-hipaa": ("compliance-framework", "informational"),
    "house-security-nist": ("compliance-framework", "lightgrey"),
    "house-security-scan": ("tooling", "orange"),
    "house-test-fixtures": ("fixtures", "yellow"),
    "house-legal": ("legal", "red"),
}


def role_for_path(repo: Path) -> tuple[str, str]:
    name = repo.resolve().name
    return REPO_ROLES.get(name, ("unknown", "lightgrey"))
