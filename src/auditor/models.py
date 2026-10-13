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
