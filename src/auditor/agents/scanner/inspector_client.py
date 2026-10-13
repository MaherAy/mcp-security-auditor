"""Client MCP du Scanner vers le serveur `mcp-inspector`.

POURQUOI MCP ICI ? Le Scanner n'accède jamais directement au disque : tout
passe par les outils MCP de l'inspecteur, qui appliquent le confinement à
`targets/`. On utilise `McpToolset`, l'intégration MCP native d'ADK : les
outils MCP deviennent des outils ADK, utilisables aussi bien par un LlmAgent
(appel décidé par le modèle) que par du code (appel explicite, comme ici).
"""

import json
import sys
from typing import Any

from google.adk.agents import InvocationContext
from google.adk.agents.context import Context
from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
from mcp import StdioServerParameters

from auditor.models import SourceFile, TargetManifest


class InspectorError(RuntimeError):
    """L'inspecteur a refusé ou échoué (ex. cible inconnue, chemin hors périmètre)."""


def inspector_toolset() -> McpToolset:
    """Toolset ADK connecté à l'inspecteur, lancé en sous-processus stdio."""
    return McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(command=sys.executable, args=["-m", "auditor.mcp_inspector"]),
            timeout=30,  # démarrage de l'inspecteur + démarrage de la cible pour tools/list
        )
    )


class InspectorClient:
    """Façade typée au-dessus des trois outils MCP de l'inspecteur."""

    def __init__(self, toolset: McpToolset, ctx: InvocationContext) -> None:
        self._toolset = toolset
        self._ctx = ctx
        self._tools: dict[str, Any] = {}

    async def _call(self, tool_name: str, **arguments: Any) -> Any:
        if not self._tools:
            self._tools = {tool.name: tool for tool in await self._toolset.get_tools()}
        # ADK 2.x : ToolContext est un alias de Context(invocation_context).
        result = await self._tools[tool_name].run_async(args=arguments, tool_context=Context(self._ctx))
        # ADK renvoie le CallToolResult MCP sous forme de dict, avec les clés
        # « historiques » 1.x (structuredContent, isError) même avec mcp 2.x.
        if result.get("isError") or "error" in result:
            message = result.get("error") or " ".join(
                part.get("text", "") for part in result.get("content", [])
            )
            raise InspectorError(f"{tool_name} failed: {message}")
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    async def fetch_manifest(self, target: str) -> TargetManifest:
        return TargetManifest.model_validate(await self._call("list_tools", target=target))

    async def list_source_files(self, target: str) -> list[str]:
        return (await self._call("list_source_files", target=target))["result"]

    async def read_source(self, path: str) -> SourceFile:
        return SourceFile.model_validate(await self._call("read_source", path=path))
