"""Phase 3 — le Scanner ADK exposé en A2A, testé par un client A2A du SDK officiel."""

import httpx
import pytest

from auditor.a2a_common import A2AAgentError, discover_agent, send_task, task_data, text_parts
from auditor.agents.scanner.card import SCAN_SKILL_ID
from auditor.agents.scanner.server import create_app
from tests.a2a.server_helpers import free_port, serve

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
def scanner_url():
    port = free_port()
    with serve(create_app(use_llm=False, url=f"http://127.0.0.1:{port}"), port) as url:
        yield url


async def test_agent_card_is_discoverable(scanner_url):
    async with httpx.AsyncClient() as http:
        card = await discover_agent(http, scanner_url)
    assert card.name == "mcp_scanner"
    assert card.supported_interfaces[0].url == scanner_url
    assert card.supported_interfaces[0].protocol_binding == "JSONRPC"
    assert [skill.id for skill in card.skills] == [SCAN_SKILL_ID]
    assert "application/json" in card.default_output_modes


async def test_scan_task_completes_with_structured_findings(scanner_url):
    async with httpx.AsyncClient(timeout=120) as http:
        card = await discover_agent(http, scanner_url)
        task, trace = await send_task(http, card, text_parts("weak_server"))

    result = task_data(task)
    assert len(result["findings"]) == 15
    # L'artefact voyage comme partie A2A `data` (JSON), pas comme texte.
    assert task.artifacts[-1].parts[0].WhichOneof("content") == "data"
    # Cycle de vie observé côté client : … → working → completed.
    assert trace.states[-1] == "completed"
    assert "working" in trace.states


async def test_unknown_target_makes_the_task_fail(scanner_url):
    async with httpx.AsyncClient(timeout=120) as http:
        card = await discover_agent(http, scanner_url)
        with pytest.raises(A2AAgentError, match="failed"):
            await send_task(http, card, text_parts("does_not_exist"))


async def test_one_http_client_can_send_several_tasks(scanner_url):
    """Régression : a2a-sdk 1.2 ferme le client httpx prêté si on appelle client.close()."""
    async with httpx.AsyncClient(timeout=120) as http:
        card = await discover_agent(http, scanner_url)
        first, _ = await send_task(http, card, text_parts("safe_server"))
        second, _ = await send_task(http, card, text_parts("safe_server"))
    assert first.id != second.id
    assert task_data(first)["findings"] == task_data(second)["findings"] == []
