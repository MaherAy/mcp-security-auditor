"""Expose le graphe LangGraph de Remédiation en A2A (même adaptateur que l'Évaluateur)."""

from starlette.applications import Starlette

from auditor.a2a_langgraph import LangGraphA2AExecutor, create_a2a_app
from auditor.agents.remediation.card import build_remediation_card
from auditor.agents.remediation.graph import build_remediation_graph
from auditor.agents.remediation.tailor import Tailor
from auditor.models import Evaluation


def create_app(*, tailor: Tailor | None = None, url: str | None = None) -> Starlette:
    executor = LangGraphA2AExecutor(
        build_remediation_graph(tailor),
        input_key="evaluation",
        input_model=Evaluation,
        output_key="plan",
        artifact_name="remediation_plan",
    )
    return create_a2a_app(build_remediation_card(url), executor)
