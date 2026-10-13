"""Phase 4 — agents LangGraph exposés en A2A + chaîne inter-frameworks ADK → LangGraph."""

import httpx
import pytest

from auditor.a2a_common import A2AAgentError, data_part, discover_agent, send_task, task_data, text_parts
from auditor.agents.evaluator.justifier import TemplateJustifier
from auditor.agents.evaluator.server import create_app as create_evaluator_app
from auditor.agents.remediation.server import create_app as create_remediation_app
from auditor.agents.remediation.tailor import TemplateTailor
from auditor.agents.scanner.server import create_app as create_scanner_app
from auditor.models import Evaluation, RemediationPlan
from tests.a2a.server_helpers import free_port, serve

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
def agent_urls():
    ports = {name: free_port() for name in ("scanner", "evaluator", "remediation")}
    urls = {name: f"http://127.0.0.1:{port}" for name, port in ports.items()}
    with (
        serve(create_scanner_app(use_llm=False, url=urls["scanner"]), ports["scanner"]),
        serve(create_evaluator_app(justifier=TemplateJustifier(), url=urls["evaluator"]), ports["evaluator"]),
        serve(create_remediation_app(tailor=TemplateTailor(), url=urls["remediation"]), ports["remediation"]),
    ):
        yield urls


async def test_langgraph_agent_cards(agent_urls):
    async with httpx.AsyncClient() as http:
        evaluator = await discover_agent(http, agent_urls["evaluator"])
        remediation = await discover_agent(http, agent_urls["remediation"])
    assert evaluator.skills[0].id == "rate_findings"
    assert remediation.skills[0].id == "propose_fixes"
    assert "langgraph" in evaluator.skills[0].tags


async def test_evaluator_streams_one_progress_message_per_graph_node(agent_urls, weak_scan):
    async with httpx.AsyncClient(timeout=60) as http:
        card = await discover_agent(http, agent_urls["evaluator"])
        task, trace = await send_task(http, card, [data_part(weak_scan.model_dump(mode="json"))])
    progress = [
        part.text for message in task.history for part in message.parts if part.text.startswith("step")
    ]
    assert progress == ["step 'classify' done", "step 'justify' done", "step 'prioritize' done"]
    assert trace.states == ["submitted", "working", "completed"]


async def test_evaluator_rejects_non_json_input(agent_urls):
    async with httpx.AsyncClient(timeout=60) as http:
        card = await discover_agent(http, agent_urls["evaluator"])
        with pytest.raises(A2AAgentError, match="rejected"):
            await send_task(http, card, text_parts("please rate this"))


async def test_cross_framework_chain_adk_to_langgraph(agent_urls):
    """Interopérabilité : Scanner (ADK) → Évaluateur (LangGraph) → Remédiation (LangGraph),
    uniquement via A2A : chaque sortie `data` devient l'entrée de l'agent suivant."""
    async with httpx.AsyncClient(timeout=120) as http:
        cards = {name: await discover_agent(http, url) for name, url in agent_urls.items()}
        scan_task, _ = await send_task(http, cards["scanner"], text_parts("weak_server"))
        eval_task, _ = await send_task(http, cards["evaluator"], [data_part(task_data(scan_task))])
        plan_task, _ = await send_task(http, cards["remediation"], [data_part(task_data(eval_task))])

    # Revalidation Pydantic côté récepteur : un protobuf Struct transporte les
    # nombres en flottants (53 → 53.0) ; la validation les remet au bon type.
    raw_line = task_data(eval_task)["findings"][0]["line"]
    evaluation = Evaluation.model_validate(task_data(eval_task))
    plan = RemediationPlan.model_validate(task_data(plan_task))
    assert isinstance(raw_line, float)
    assert isinstance(evaluation.findings[0].line, int)
    assert evaluation.overall_risk == "critical"
    assert len(plan.items) == len(evaluation.findings) == 15
