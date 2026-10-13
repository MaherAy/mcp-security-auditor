"""Serveur MCP « mcp-inspector » : les yeux de l'agent Scanner.

POURQUOI MCP ICI ?
MCP est le protocole standard « agent → outils ». En exposant l'inspection
comme un serveur MCP plutôt que comme des fonctions Python internes :
- n'importe quel agent compatible MCP (ADK, LangGraph, Claude Code…) peut
  l'utiliser sans code d'intégration ;
- la frontière de confiance est explicite : l'agent ne touche jamais le disque
  lui-même, il passe par trois outils en lecture seule, confinés à `targets/`.

Outils exposés :
- list_tools(target)          → manifeste de la cible (via `tools/list`)
- list_source_files(target)   → fichiers source lisibles de la cible
- read_source(path)           → contenu d'un fichier source

(`list_source_files` s'ajoute aux deux outils demandés : sans lui, l'agent
devrait deviner les chemins à lire.)
"""

import sys

import anyio
from mcp import Client, StdioServerParameters
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from auditor.mcp_inspector.sandbox import SandboxError, TargetsSandbox
from auditor.models import SourceFile, TargetManifest, ToolManifestEntry

MANIFEST_TIMEOUT_SECONDS = 20

sandbox = TargetsSandbox()

inspector = MCPServer(
    "mcp-inspector",
    version="0.1.0",
    instructions=(
        "Read-only static inspection of local MCP test servers located in the "
        "auditor's targets/ folder. Never executes the target's tools."
    ),
)

# Tous nos outils sont en lecture seule : on le déclare via les annotations MCP.
# (Le Scanner vérifie justement l'absence de ces annotations chez la cible.)
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)


async def fetch_manifest(target: str) -> TargetManifest:
    """Démarre la cible en sous-processus stdio et lui demande `tools/list`.

    C'est le seul moment où du code de la cible s'exécute : le temps de
    répondre à l'initialisation MCP et à `tools/list`. Aucun `tools/call` n'est
    jamais envoyé. Le sous-processus reçoit l'environnement minimal du SDK
    (PATH, TEMP…) : nos propres secrets (ex. MISTRAL_API_KEY) ne lui sont pas
    transmis.
    """
    entrypoint = sandbox.entrypoint(target)
    params = StdioServerParameters(
        command=sys.executable,  # même interpréteur → le SDK `mcp` est disponible
        args=[str(entrypoint)],
        cwd=str(entrypoint.parent),
    )
    with anyio.fail_after(MANIFEST_TIMEOUT_SECONDS):
        # Ici, l'inspecteur est lui-même CLIENT MCP de la cible.
        async with Client(params) as client:
            listing = await client.list_tools()
            server_info = client.server_info

    return TargetManifest(
        target=target,
        server_name=server_info.name if server_info else "",
        server_version=server_info.version if server_info else "",
        tools=[
            ToolManifestEntry(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.input_schema,
                annotations=tool.annotations.model_dump(exclude_none=True) if tool.annotations else None,
            )
            for tool in listing.tools
        ],
    )


@inspector.tool(
    description="Return the MCP manifest (tools, descriptions, input schemas, annotations) "
    "of a local test target, e.g. target='weak_server'.",
    annotations=READ_ONLY,
)
async def list_tools(target: str) -> TargetManifest:
    try:
        return await fetch_manifest(target)
    except SandboxError as error:
        raise ToolError(str(error)) from error
    except TimeoutError as error:
        raise ToolError(f"target {target!r} did not answer tools/list in time") from error


@inspector.tool(
    description="List the readable source files of a local test target (paths for read_source).",
    annotations=READ_ONLY,
)
def list_source_files(target: str) -> list[str]:
    try:
        return sandbox.list_source_files(target)
    except SandboxError as error:
        raise ToolError(str(error)) from error


@inspector.tool(
    description="Read one source file of a local test target, "
    "path relative to the targets folder, e.g. 'weak_server/server.py'.",
    annotations=READ_ONLY,
)
def read_source(path: str) -> SourceFile:
    try:
        file = sandbox.source_file(path)
    except SandboxError as error:
        raise ToolError(str(error)) from error
    return SourceFile(path=sandbox.relative(file), content=file.read_text(encoding="utf-8", errors="replace"))
