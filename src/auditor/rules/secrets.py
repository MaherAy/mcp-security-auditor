"""Secrets en clair dans le code source de la cible.

- HS001 : valeur au format d'un jeton connu (OpenAI, AWS, GitHub, Slack,
          Google, clé privée PEM) — détection par expression régulière.
- HS002 : variable au nom sensible (password, secret, token, api_key…)
          affectée à une chaîne littérale — détection par AST.

Les preuves sont MASQUÉES : un rapport d'audit ne doit pas devenir lui-même
une fuite de secrets.
"""

import ast
import re

from auditor.models import Finding, RiskCategory
from auditor.rules import code_analysis as ca
from auditor.rules.context import AuditContext, make_finding

TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "OpenAI API key": re.compile(r"sk-(proj-)?[A-Za-z0-9_-]{20,}"),
    "AWS access key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Private key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}
SENSITIVE_NAME = re.compile(r"pass(word|wd)?|secret|token|api_?key|private_?key|credential", re.IGNORECASE)
MIN_SECRET_LENGTH = 6


def mask(secret: str) -> str:
    """Clé AWS de 20 caractères -> 'AKIA…(20 chars)'.

    (Pas d'exemple de clé réelle ici : notre propre règle HS001 la signalerait,
    à juste titre — voir test_auditor_dogfooding_whole_codebase_is_clean.)
    """
    return f"{secret[:4]}…({len(secret)} chars)"


def _token_findings(path: str, code: str) -> list[Finding]:
    findings = []
    for line_number, line in enumerate(code.splitlines(), start=1):
        for kind, pattern in TOKEN_PATTERNS.items():
            match = pattern.search(line)
            if match:
                findings.append(
                    make_finding(
                        "HS001",
                        RiskCategory.HARDCODED_SECRET,
                        f"Hardcoded {kind}",
                        line.replace(match.group(0), mask(match.group(0))).strip(),
                        file=path,
                        line=line_number,
                        indicators=[kind],
                    )
                )
    return findings


def _assignment_findings(path: str, code: str, already_flagged: set[int]) -> list[Finding]:
    tree = ca.parse(code) if path.endswith(".py") else None
    if tree is None:
        return []
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign) or node.lineno in already_flagged:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        value = node.value
        is_literal = isinstance(value, ast.Constant) and isinstance(value.value, str)
        # Une constante dont la valeur est son propre nom est une étiquette, pas un
        # secret : `PASSWORD = "password"`, `HARDCODED_SECRET = "hardcoded_secret"`.
        is_self_label = is_literal and any(value.value.lower() == n.lower() for n in names)
        if (
            is_literal
            and not is_self_label
            and len(value.value) >= MIN_SECRET_LENGTH
            and any(SENSITIVE_NAME.search(n) for n in names)
        ):
            findings.append(
                make_finding(
                    "HS002",
                    RiskCategory.HARDCODED_SECRET,
                    f"Hardcoded credential in variable '{names[0]}'",
                    f'{names[0]} = "{mask(value.value)}"',
                    file=path,
                    line=node.lineno,
                    indicators=["sensitive variable name", "string literal"],
                )
            )
    return findings


def check(context: AuditContext) -> list[Finding]:
    findings = []
    for path, code in context.sources.items():
        token_findings = _token_findings(path, code)
        findings += token_findings
        findings += _assignment_findings(path, code, {finding.line for finding in token_findings})
    return findings
