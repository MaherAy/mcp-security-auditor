"""Règles de détection déterministes (voir docs/DECISIONS.md, D2).

Chaque module expose `check(context) -> list[Finding]`. Ajouter une famille de
risques = ajouter un module et l'inscrire dans `RULE_MODULES`.
"""

from auditor.models import Finding
from auditor.rules import permissions, poisoning, secrets, validation
from auditor.rules.context import AuditContext

RULE_MODULES = [poisoning, permissions, validation, secrets]


def run_all_rules(context: AuditContext) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for module in RULE_MODULES:
        for finding in module.check(context):
            findings.setdefault(finding.id, finding)  # dédoublonnage par id stable
    return list(findings.values())


__all__ = ["AuditContext", "run_all_rules"]
