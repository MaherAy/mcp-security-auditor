"""Politique de sévérité : règle → (sévérité, score, raison), puis ajustements.

Déterministe et lisible d'un coup d'œil : on doit pouvoir dire à un auditeur
humain POURQUOI un constat est « critical ». Le LLM ne décide jamais de la
sévérité ; il rédige seulement la justification (voir justifier.py).

Échelle inspirée de CVSS (0–10) sans prétendre en être un calcul officiel.
"""

from dataclasses import dataclass

from auditor.models import Finding, RatedFinding, Severity


@dataclass(frozen=True)
class BaseRating:
    severity: Severity
    score: float
    rationale: str


BASE_POLICY: dict[str, BaseRating] = {
    "TP001": BaseRating(
        Severity.HIGH,
        8.0,
        "Hidden instructions in a tool description can make the client LLM act against the user.",
    ),
    "LLM-TP": BaseRating(
        Severity.MEDIUM, 5.0, "Suspicious description flagged by an LLM only (no rule confirmation)."
    ),
    "EP001": BaseRating(
        Severity.CRITICAL, 9.5, "Arbitrary command/code execution reachable from an MCP tool."
    ),
    "EP002": BaseRating(
        Severity.HIGH, 8.0, "Caller-chosen paths give read/write access to the whole filesystem."
    ),
    "EP003": BaseRating(
        Severity.MEDIUM, 5.0, "Without safety annotations, clients cannot ask for user confirmation."
    ),
    "IV001": BaseRating(
        Severity.LOW, 3.0, "Unconstrained string inputs widen the attack surface (defence in depth)."
    ),
    "IV002": BaseRating(Severity.HIGH, 8.5, "SQL built from tool input enables SQL injection."),
    "IV003": BaseRating(
        Severity.HIGH, 8.0, "Untrusted tool input reaches a dangerous function without validation."
    ),
    "HS001": BaseRating(
        Severity.HIGH, 7.5, "A credential with a known token format is committed in source code."
    ),
    "HS002": BaseRating(Severity.MEDIUM, 6.0, "A literal value is assigned to a credential-like variable."),
}
UNKNOWN_RULE = BaseRating(Severity.MEDIUM, 5.0, "Unknown rule: default rating, needs manual review.")

# Indicateurs de tool poisoning qui, ensemble, signent une exfiltration discrète.
EXFILTRATION_INDICATORS = {"reference to sensitive data", "concealment from the user"}


def _bump(severity: Severity) -> Severity:
    return list(Severity)[max(severity.rank - 1, 0)]


def rate(finding: Finding, all_findings: list[Finding]) -> tuple[Severity, float, str]:
    base = BASE_POLICY.get(finding.rule_id, UNKNOWN_RULE)
    severity, score, reasons = base.severity, base.score, [base.rationale]

    # Ajustement 1 : poisoning qui demande des données sensibles ET se cache.
    if finding.rule_id == "TP001" and EXFILTRATION_INDICATORS <= set(finding.indicators):
        severity, score = Severity.CRITICAL, 9.0
        reasons.append("Escalated: asks for sensitive data while hiding it from the user (exfiltration).")

    # Ajustement 2 : la règle est confirmée par la relecture LLM.
    if any(item.startswith("confirmed by LLM review") for item in finding.indicators):
        score = min(score + 0.3, 10.0)
        reasons.append("Confirmed by the LLM second opinion.")

    # Ajustement 3 : entrée non contrainte qui atteint une fonction dangereuse ou
    # une requête SQL dans le même outil (IV001 + IV002/IV003) → ce n'est plus de
    # la simple défense en profondeur.
    sink_rules = {"IV002", "IV003"}
    if finding.rule_id == "IV001" and any(
        other.rule_id in sink_rules and other.tool == finding.tool for other in all_findings
    ):
        severity, score = _bump(severity), score + 2.0
        reasons.append("Escalated: the same tool passes this input to a dangerous sink (IV002/IV003).")

    return severity, round(score, 1), " ".join(reasons)


def rate_all(findings: list[Finding]) -> list[RatedFinding]:
    rated = []
    for finding in findings:
        severity, score, rationale = rate(finding, findings)
        rated.append(
            RatedFinding(
                **finding.model_dump(),
                severity=severity,
                score=score,
                rationale=rationale,
                justification="",  # rempli par le nœud `justify` du graphe
            )
        )
    return sorted(rated, key=lambda item: (item.severity.rank, -item.score, item.id))
