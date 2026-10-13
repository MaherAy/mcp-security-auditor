"""Application A2A de l'orchestrateur."""

from starlette.applications import Starlette

from auditor.a2a_common import agent_url
from auditor.a2a_langgraph import create_a2a_app
from auditor.agents.orchestrator.card import build_orchestrator_card
from auditor.agents.orchestrator.executor import OrchestratorExecutor


def default_agent_urls() -> list[str]:
    """Les seules choses que l'orchestrateur connaît : des URL. Le reste vient des cartes."""
    return [agent_url("scanner"), agent_url("evaluator"), agent_url("remediation")]


def create_app(*, agent_urls: list[str] | None = None, url: str | None = None) -> Starlette:
    executor = OrchestratorExecutor(agent_urls or default_agent_urls())
    return create_a2a_app(build_orchestrator_card(url), executor)
