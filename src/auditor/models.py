"""Modèles de données partagés par tous les composants (Pydantic).

Pydantic sert de « contrat » : les mêmes classes valident ce que renvoie le
serveur MCP (structured output) et ce que les agents s'échangent en A2A
(artefacts JSON). Un seul schéma, sérialisé avec `model_dump(mode="json")`.
"""

from typing import Any

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
