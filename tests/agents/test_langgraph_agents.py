"""Phase 4 — graphes LangGraph de l'Évaluateur et de la Remédiation (sans réseau)."""

import os

import pytest

from auditor.agents.evaluator.graph import build_evaluator_graph, evaluate
from auditor.agents.evaluator.justifier import TemplateJustifier
from auditor.agents.remediation.catalog import CATALOG
from auditor.agents.remediation.graph import build_remediation_graph
from auditor.agents.remediation.tailor import TemplateTailor
from auditor.models import Severity

pytestmark = pytest.mark.anyio


class PartialJustifier:
    """Faux LLM qui « oublie » des constats et invente un identifiant."""

    kind = "llm"

    async def justify(self, findings):
        texts = {f.id: f"LLM says: {f.title}" for f in findings[:3]}
        texts["INVENTED:id"] = "hallucinated"
        return texts


class WeakeningTailor:
    """Faux LLM : réponse vide pour un élément, réponse adaptée pour un autre."""

    kind = "llm"

    async def tailor(self, items, evidence):
        first, second = items[0].finding_id, items[1].finding_id
        return {first: "", second: f"Tailored for {evidence[second][:20]}"}


async def test_evaluator_graph_runs_its_three_nodes_in_order(weak_scan):
    graph = build_evaluator_graph(TemplateJustifier())
    nodes = [
        name async for update in graph.astream({"scan": weak_scan}, stream_mode="updates") for name in update
    ]
    assert nodes == ["classify", "justify", "prioritize"]


async def test_evaluation_summary(weak_scan):
    evaluation = await evaluate(weak_scan, TemplateJustifier())
    assert evaluation.overall_risk == Severity.CRITICAL
    assert evaluation.counts == {Severity.CRITICAL: 2, Severity.HIGH: 6, Severity.MEDIUM: 6, Severity.LOW: 1}
    assert evaluation.justified_by == "template"
    assert all(finding.justification for finding in evaluation.findings)


async def test_missing_llm_justifications_fall_back_to_template(weak_scan):
    evaluation = await evaluate(weak_scan, PartialJustifier())
    texts = [finding.justification for finding in evaluation.findings]
    assert sum(text.startswith("LLM says") for text in texts) == 3
    assert all(texts)  # aucun constat sans justification
    assert "hallucinated" not in texts  # identifiant inventé ignoré


async def test_scan_without_findings_has_no_risk(weak_scan):
    empty_scan = weak_scan.model_copy(update={"findings": []})
    evaluation = await evaluate(empty_scan, TemplateJustifier())
    assert evaluation.overall_risk == "none"
    assert evaluation.findings == []


async def test_remediation_plan_has_one_fix_per_finding_in_priority_order(weak_scan):
    evaluation = await evaluate(weak_scan, TemplateJustifier())
    plan = (await build_remediation_graph(TemplateTailor()).ainvoke({"evaluation": evaluation}))["plan"]
    assert [item.finding_id for item in plan.items] == [f.id for f in evaluation.findings]
    assert all(item.steps and item.references for item in plan.items)
    assert all(item.fix == item.baseline_fix for item in plan.items)


async def test_tailored_fix_never_loses_the_reviewed_baseline(weak_scan):
    evaluation = await evaluate(weak_scan, TemplateJustifier())
    plan = (await build_remediation_graph(WeakeningTailor()).ainvoke({"evaluation": evaluation}))["plan"]
    first, second = plan.items[0], plan.items[1]
    assert first.fix == first.baseline_fix  # réponse vide du LLM → correctif relu
    assert second.fix.startswith("Tailored for")
    assert second.baseline_fix == CATALOG[evaluation.findings[1].rule_id].fix


@pytest.mark.live
async def test_live_mistral_justifier_and_tailor(weak_scan):
    if not os.environ.get("MISTRAL_API_KEY"):
        pytest.skip("MISTRAL_API_KEY not set")
    from auditor.agents.evaluator.justifier import MistralJustifier
    from auditor.agents.remediation.tailor import MistralTailor

    evaluation = await evaluate(weak_scan, MistralJustifier())
    assert evaluation.justified_by == "llm"
    assert all(finding.justification for finding in evaluation.findings)
    plan = (await build_remediation_graph(MistralTailor()).ainvoke({"evaluation": evaluation}))["plan"]
    assert plan.tailored_by == "llm"
    assert all(item.baseline_fix for item in plan.items)
