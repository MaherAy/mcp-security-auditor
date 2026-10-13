"""Agent Évaluateur (LangGraph) : classe chaque constat du Scanner.

Graphe :   START → classify → justify → prioritize → END

- classify   : sévérité + score par la politique déterministe (policy.py) ;
- justify    : justification rédigée (Mistral ou gabarit), avec repli sur le
               gabarit pour tout constat que le LLM aurait oublié ;
- prioritize : comptage par sévérité et risque global.

Pourquoi LangGraph ici ? Un graphe d'états explicite rend chaque étape
inspectable et testable isolément ; l'état (TypedDict) est le contrat entre
les nœuds. Et c'est un framework différent d'ADK : l'interopérabilité passe
uniquement par A2A, pas par du code partagé.
"""

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from auditor.agents.evaluator.justifier import Justifier, TemplateJustifier, default_justifier
from auditor.agents.evaluator.policy import rate_all
from auditor.models import Evaluation, RatedFinding, ScanResult, Severity


class EvaluatorState(TypedDict, total=False):
    scan: ScanResult  # entrée
    rated: list[RatedFinding]
    justified_by: str
    evaluation: Evaluation  # sortie


def build_evaluator_graph(justifier: Justifier | None = None) -> CompiledStateGraph:
    justifier = justifier or default_justifier()
    fallback = TemplateJustifier()

    def classify(state: EvaluatorState) -> dict[str, Any]:
        return {"rated": rate_all(state["scan"].findings)}

    async def justify(state: EvaluatorState) -> dict[str, Any]:
        rated = state["rated"]
        if not rated:
            return {"justified_by": justifier.kind}
        texts = await justifier.justify(rated)
        missing = [finding for finding in rated if not texts.get(finding.id)]
        if missing:  # le LLM a sauté des constats : on complète, on ne perd rien
            texts |= await fallback.justify(missing)
        return {
            "rated": [finding.model_copy(update={"justification": texts[finding.id]}) for finding in rated],
            "justified_by": justifier.kind,
        }

    def prioritize(state: EvaluatorState) -> dict[str, Any]:
        rated = state["rated"]
        counts = {severity: sum(f.severity is severity for f in rated) for severity in Severity}
        overall = rated[0].severity if rated else "none"  # déjà trié par gravité
        evaluation = Evaluation(
            target=state["scan"].target,
            overall_risk=overall,
            counts=counts,
            findings=rated,
            justified_by=state["justified_by"],
        )
        return {"evaluation": evaluation}

    graph = StateGraph(EvaluatorState)
    graph.add_node("classify", classify)
    graph.add_node("justify", justify)
    graph.add_node("prioritize", prioritize)
    graph.add_edge(START, "classify")
    graph.add_edge("classify", "justify")
    graph.add_edge("justify", "prioritize")
    graph.add_edge("prioritize", END)
    return graph.compile()


async def evaluate(scan: ScanResult, justifier: Justifier | None = None) -> Evaluation:
    final_state = await build_evaluator_graph(justifier).ainvoke({"scan": scan})
    return final_state["evaluation"]
