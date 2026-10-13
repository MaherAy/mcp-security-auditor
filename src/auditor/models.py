"""Modèles de données partagés par tous les composants (Pydantic).

Pydantic sert de « contrat » : les mêmes classes valident ce que renvoie le
serveur MCP (structured output) et ce que les agents s'échangent en A2A
(artefacts JSON). Un seul schéma, sérialisé avec `model_dump(mode="json")`.
"""

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolManifestEntry(BaseModel):
    """Un outil tel que déclaré par le serveur cible dans `tools/list`."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    # Annotations MCP (read_only_hint, destructive_hint…) ; None si absentes.
    annotations: dict[str, Any] | None = None


class TargetManifest(BaseModel):
    """Manifeste complet d'une cible : identité du serveur + ses outils."""

    target: str
    server_name: str
    server_version: str = ""
    tools: list[ToolManifestEntry]


class SourceFile(BaseModel):
    """Un fichier source de la cible, lu en lecture seule."""

    path: str  # relatif à la racine des cibles, séparateurs "/"
    content: str


# --- Constats du Scanner -------------------------------------------------------


class RiskCategory(StrEnum):
    TOOL_POISONING = "tool_poisoning"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    HARDCODED_SECRET = "hardcoded_secret"


class Finding(BaseModel):
    """Un constat brut : « ce motif est présent, voici la preuve ».

    Volontairement SANS sévérité : classer est le travail de l'agent Évaluateur.
    Séparer « constater » et « juger » permet de changer la politique de
    sévérité sans toucher aux détecteurs (et inversement).
    """

    id: str  # stable et unique : "<rule_id>:<tool ou fichier>:<ligne>"
    rule_id: str  # ex. "TP001"
    category: RiskCategory
    title: str
    tool: str | None = None  # outil MCP concerné, si applicable
    file: str | None = None  # fichier source, si constat issu du code
    line: int | None = None
    evidence: str  # extrait prouvant le constat (secrets masqués)
    indicators: list[str] = Field(default_factory=list)  # signaux détaillés
    detector: Literal["rule", "llm"] = "rule"


class ScanResult(BaseModel):
    """Sortie de l'agent Scanner, transmise en A2A à l'Évaluateur."""

    target: str
    manifest: TargetManifest
    files_scanned: list[str]
    findings: list[Finding]


# --- Évaluation (agent Évaluateur) ---------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Ordre de tri : critical=0 … low=3."""
        return list(Severity).index(self)


class RatedFinding(Finding):
    """Un constat classé : sévérité + score + justification, preuve conservée."""

    severity: Severity
    score: float = Field(ge=0, le=10)  # 0–10, pour départager à sévérité égale
    rationale: str  # raison de la sévérité selon la politique (déterministe)
    justification: str  # explication du risque, rédigée (LLM ou gabarit)


class Evaluation(BaseModel):
    """Sortie de l'Évaluateur : constats triés du plus grave au moins grave."""

    target: str
    overall_risk: Severity | Literal["none"]
    counts: dict[Severity, int]
    findings: list[RatedFinding]
    justified_by: Literal["llm", "template"]


# --- Remédiation (agent Remédiation) --------------------------------------------


class Remediation(BaseModel):
    finding_id: str
    severity: Severity
    title: str  # titre du constat traité
    fix: str  # correctif adapté au cas (LLM) ou identique à baseline_fix (hors-ligne)
    baseline_fix: str  # correctif relu du catalogue, toujours conservé : le LLM peut l'affaiblir
    steps: list[str]
    code_example: str = ""
    references: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    target: str
    items: list[Remediation]  # même ordre que l'évaluation (priorité)
    tailored_by: Literal["llm", "template"]


# --- Rapport final (orchestrateur) ------------------------------------------------


class AgentRun(BaseModel):
    """Trace d'une délégation A2A : quel agent, quel framework, quelle Task, quels états."""

    role: str  # "scanner" | "evaluator" | "remediation"
    skill_id: str
    agent_name: str
    framework: str  # déduit des tags de l'Agent Card
    url: str
    task_id: str
    states: list[str]


class ReportItem(BaseModel):
    finding: RatedFinding
    remediation: Remediation | None


class AuditReport(BaseModel):
    target: str
    server_name: str
    tools_count: int
    files_scanned: list[str]
    generated_at: str  # ISO 8601, UTC
    overall_risk: Severity | Literal["none"]
    counts: dict[Severity, int]
    items: list[ReportItem]  # triés par priorité
    agents: list[AgentRun]
    justified_by: Literal["llm", "template"]
    tailored_by: Literal["llm", "template"]
