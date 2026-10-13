"""Expose le graphe LangGraph de l'Évaluateur en A2A (AgentExecutor écrit à la main)."""

from starlette.applications import Starlette

from auditor.a2a_langgraph import LangGraphA2AExecutor, create_a2a_app
from auditor.agents.evaluator.card import build_evaluator_card
from auditor.agents.evaluator.graph import build_evaluator_graph
from auditor.agents.evaluator.justifier import Justifier
from auditor.models import ScanResult


def create_app(*, justifier: Justifier | None = None, url: str | None = None) -> Starlette:
    executor = LangGraphA2AExecutor(
        build_evaluator_graph(justifier),
        input_key="scan",
        input_model=ScanResult,
        output_key="evaluation",
        artifact_name="evaluation",
    )
    return create_a2a_app(build_evaluator_card(url), executor)
