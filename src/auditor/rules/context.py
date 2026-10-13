"""Entrée commune à toutes les règles : le manifeste + le code de la cible."""

from dataclasses import dataclass, field

from auditor.models import Finding, RiskCategory, TargetManifest


@dataclass
class AuditContext:
    manifest: TargetManifest
    sources: dict[str, str] = field(default_factory=dict)  # chemin -> contenu

    @property
    def python_sources(self) -> dict[str, str]:
        return {path: code for path, code in self.sources.items() if path.endswith(".py")}


def make_finding(
    rule_id: str,
    category: RiskCategory,
    title: str,
    evidence: str,
    *,
    tool: str | None = None,
    file: str | None = None,
    line: int | None = None,
    indicators: list[str] | None = None,
) -> Finding:
    """Fabrique un Finding avec un identifiant stable (utile pour dédupliquer et tester)."""
    location = ":".join(str(part) for part in (tool, file, line) if part is not None)
    return Finding(
        id=f"{rule_id}:{location}",
        rule_id=rule_id,
        category=category,
        title=title,
        tool=tool,
        file=file,
        line=line,
        evidence=evidence,
        indicators=indicators or [],
    )
