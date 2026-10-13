"""Agent Remédiation (LangGraph) : un correctif par risque, dans l'ordre de priorité.

Graphe :   START → select_fixes → tailor → END

- select_fixes : correctif type du catalogue pour chaque constat évalué ;
- tailor       : phrase « fix » adaptée au cas (Mistral ou gabarit), repli
                 sur la version générique pour tout élément oublié par le LLM.
"""

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from auditor.agents.remediation.catalog import template_for
from auditor.agents.remediation.tailor import Tailor, default_tailor
from auditor.models import Evaluation, Remediation, RemediationPlan


class RemediationState(TypedDict, total=False):
    evaluation: Evaluation  # entrée
    items: list[Remediation]
    plan: RemediationPlan  # sortie


def build_remediation_graph(tailor: Tailor | None = None) -> CompiledStateGraph:
    tailor = tailor or default_tailor()

    def select_fixes(state: RemediationState) -> dict[str, Any]:
        items = []
        for finding in state["evaluation"].findings:  # déjà triés par priorité
            template = template_for(finding.rule_id)
            items.append(
                Remediation(
                    finding_id=finding.id,
                    severity=finding.severity,
                    title=finding.title,
                    fix=template.fix,
                    baseline_fix=template.fix,
                    steps=list(template.steps),
                    code_example=template.code_example,
                    references=list(template.references),
                )
            )
        return {"items": items}

    async def tailor_fixes(state: RemediationState) -> dict[str, Any]:
        items = state["items"]
        evaluation = state["evaluation"]
        if items:
            evidence = {f.id: f.evidence for f in evaluation.findings}
            fixes = await tailor.tailor(items, evidence)
            items = [
                item.model_copy(update={"fix": fixes.get(item.finding_id) or item.fix}) for item in items
            ]
        plan = RemediationPlan(target=evaluation.target, items=items, tailored_by=tailor.kind)
        return {"items": items, "plan": plan}

    graph = StateGraph(RemediationState)
    graph.add_node("select_fixes", select_fixes)
    graph.add_node("tailor", tailor_fixes)
    graph.add_edge(START, "select_fixes")
    graph.add_edge("select_fixes", "tailor")
    graph.add_edge("tailor", END)
    return graph.compile()
