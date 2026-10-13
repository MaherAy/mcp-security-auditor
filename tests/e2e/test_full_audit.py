"""Phase 5 — audit complet : orchestrateur (SDK A2A) → Scanner (ADK) → Évaluateur et
Remédiation (LangGraph), quatre serveurs HTTP réels, LLM désactivé."""

import httpx
import pytest

from auditor.a2a_common import A2AAgentError, data_part, discover_agent, send_task, task_data, text_parts
from auditor.agents.evaluator.justifier import TemplateJustifier
from auditor.agents.evaluator.server import create_app as create_evaluator_app
from auditor.agents.orchestrator.server import create_app as create_orchestrator_app
from auditor.agents.remediation.server import create_app as create_remediation_app
from auditor.agents.remediation.tailor import TemplateTailor
from auditor.agents.scanner.server import create_app as create_scanner_app
from auditor.models import AuditReport
from tests.a2a.server_helpers import free_port, serve

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
def system():
    ports = {name: free_port() for name in ("scanner", "evaluator", "remediation", "orchestrator", "partial")}
    urls = {name: f"http://127.0.0.1:{port}" for name, port in ports.items()}
    delegates = [urls["scanner"], urls["evaluator"], urls["remediation"]]
    with (
        serve(create_scanner_app(use_llm=False, url=urls["scanner"]), ports["scanner"]),
        serve(create_evaluator_app(justifier=TemplateJustifier(), url=urls["evaluator"]), ports["evaluator"]),
        serve(create_remediation_app(tailor=TemplateTailor(), url=urls["remediation"]), ports["remediation"]),
        serve(create_orchestrator_app(agent_urls=delegates, url=urls["orchestrator"]), ports["orchestrator"]),
        # Orchestrateur mal configuré : il ne connaît pas l'agent Remédiation.
        serve(create_orchestrator_app(agent_urls=delegates[:2], url=urls["partial"]), ports["partial"]),
    ):
        yield urls


async def ask(url: str, parts):
    async with httpx.AsyncClient(timeout=300) as http:
        card = await discover_agent(http, url)
        return await send_task(http, card, parts)


async def test_full_audit_of_weak_server(system):
    task, trace = await ask(system["orchestrator"], text_parts("audite weak_server"))
    report = AuditReport.model_validate(task_data(task))

    assert trace.states == ["submitted", "working", "completed"]
    assert report.overall_risk == "critical"
    assert len(report.items) == 15
    assert all(item.remediation for item in report.items)
    severities = [item.finding.severity.rank for item in report.items]
    assert severities == sorted(severities)
    # Interopérabilité démontrée : deux frameworks différents derrière A2A.
    assert {run.role: run.framework for run in report.agents} == {
        "scanner": "google-adk",
        "evaluator": "langgraph",
        "remediation": "langgraph",
    }
    assert all(run.states[-1] == "completed" for run in report.agents)
    # Deux artefacts : JSON pour les machines, Markdown pour les humains.
    assert {artifact.name for artifact in task.artifacts} == {"audit_report", "audit_report.md"}


async def test_progress_is_streamed_as_working_statuses(system):
    _, trace = await ask(system["orchestrator"], [data_part({"target": "safe_server"})])
    assert any(message.startswith("discovered:") for message in trace.messages)
    assert sum("submitted → working → completed" in message for message in trace.messages) == 3


async def test_full_audit_of_safe_server_reports_no_risk(system):
    task, _ = await ask(system["orchestrator"], text_parts("audit safe_server"))
    report = AuditReport.model_validate(task_data(task))
    assert report.overall_risk == "none"
    assert report.items == []


async def test_scanner_failure_propagates_to_the_orchestrator_task(system):
    with pytest.raises(A2AAgentError, match=r"failed: scanner \(mcp_scanner\) failed"):
        await ask(system["orchestrator"], text_parts("audit does_not_exist"))


async def test_missing_skill_fails_with_a_clear_message(system):
    with pytest.raises(A2AAgentError, match="propose_fixes"):
        await ask(system["partial"], text_parts("audit weak_server"))


async def test_request_without_target_is_rejected(system):
    with pytest.raises(A2AAgentError, match="rejected"):
        await ask(system["orchestrator"], text_parts("!!!"))
