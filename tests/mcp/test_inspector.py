"""Phase 1 — le serveur MCP mcp-inspector, testé via un vrai client MCP."""

import sys

import pytest
from mcp import Client, StdioServerParameters

from auditor.mcp_inspector.server import inspector

pytestmark = pytest.mark.anyio


async def call(client: Client, tool: str, **arguments):
    return await client.call_tool(tool, arguments)


async def test_inspector_exposes_read_only_tools():
    async with Client(inspector) as client:  # connexion en mémoire
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert set(tools) == {"list_tools", "list_source_files", "read_source"}
    assert all(tool.annotations.read_only_hint for tool in tools.values())


async def test_list_tools_returns_weak_target_manifest():
    async with Client(inspector) as client:
        result = await call(client, "list_tools", target="weak_server")
    assert not result.is_error
    manifest = result.structured_content
    assert manifest["server_name"] == "weak-notes-server"
    names = {tool["name"] for tool in manifest["tools"]}
    assert names == {"add", "run_command", "read_file", "search_notes"}
    add = next(tool for tool in manifest["tools"] if tool["name"] == "add")
    assert "<IMPORTANT>" in add["description"]


async def test_list_source_files_and_read_source():
    async with Client(inspector) as client:
        files = (await call(client, "list_source_files", target="weak_server")).structured_content
        # MCP enveloppe une sortie non-objet (ici une liste) dans {"result": ...}.
        assert files == {"result": ["weak_server/server.py"]}
        result = await call(client, "read_source", path="weak_server/server.py")
    assert result.structured_content["path"] == "weak_server/server.py"
    assert "AKIAIOSFODNN7EXAMPLE" in result.structured_content["content"]


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("read_source", {"path": "../pyproject.toml"}),  # sortie de la racine
        ("read_source", {"path": "weak_server/../../src/auditor/models.py"}),
        ("read_source", {"path": "C:/Windows/win.ini"}),  # chemin absolu
        ("list_tools", {"target": "../src"}),
        ("list_tools", {"target": "does_not_exist"}),
        ("list_source_files", {"target": ".."}),
    ],
)
async def test_sandbox_rejects_out_of_scope_access(tool, arguments):
    async with Client(inspector) as client:
        result = await client.call_tool(tool, arguments)
    assert result.is_error


async def test_inspector_over_real_stdio_transport():
    """Bout en bout : l'inspecteur lancé comme sous-processus, comme le fera l'agent."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "auditor.mcp_inspector"])
    async with Client(params) as client:
        result = await call(client, "list_tools", target="safe_server")
    tools = result.structured_content["tools"]
    assert {tool["name"] for tool in tools} == {"add", "read_note", "search_notes"}
    assert all(tool["annotations"]["read_only_hint"] for tool in tools)
