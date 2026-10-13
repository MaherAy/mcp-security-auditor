"""Phase 5 — parties pures de l'orchestrateur : lecture de la demande, rendu du rapport."""

import json

import pytest
from a2a.helpers.proto_helpers import new_text_part

from auditor.a2a_common import data_part
from auditor.agents.evaluator.graph import evaluate
from auditor.agents.evaluator.justifier import TemplateJustifier
from auditor.agents.orchestrator.card import build_orchestrator_card
from auditor.agents.orchestrator.executor import parse_audit_request
from auditor.agents.orchestrator.pipeline import build_report, framework_of
from auditor.agents.orchestrator.report import render_markdown, write_reports
from auditor.agents.remediation.graph import build_remediation_graph
from auditor.agents.remediation.tailor import TemplateTailor
from auditor.agents.scanner.card import build_scanner_card
from auditor.models import AgentRun


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        ([new_text_part("audit weak_server")], "weak_server"),
        ([new_text_part("audite le serveur safe_server")], "safe_server"),
        ([data_part({"target": "weak_server"})], "weak_server"),
    ],
)
def test_parse_audit_request(parts, expected):
    assert parse_audit_request(parts) == expected


def test_parse_audit_request_without_target():
    with pytest.raises(ValueError):
        parse_audit_request([new_text_part("   ")])


def test_framework_is_read_from_agent_card_tags():
    assert framework_of(build_scanner_card("http://x")) == "google-adk"
    assert framework_of(build_orchestrator_card("http://x")) == "a2a-sdk"


@pytest.fixture
def weak_report(weak_scan):
    import asyncio

    async def build():
        evaluation = await evaluate(weak_scan, TemplateJustifier())
        plan = (await build_remediation_graph(TemplateTailor()).ainvoke({"evaluation": evaluation}))["plan"]
        run = AgentRun(
            role="scanner", skill_id="scan_mcp_server", agent_name="mcp_scanner", framework="google-adk",
            url="http://x", task_id="12345678-abcd", states=["submitted", "working", "completed"],
        )  # fmt: skip
        return build_report(weak_scan, evaluation, plan, [run])

    return asyncio.run(build())


def test_report_merges_each_finding_with_its_fix(weak_report):
    assert len(weak_report.items) == 15
    assert all(
        item.remediation and item.remediation.finding_id == item.finding.id for item in weak_report.items
    )
    assert weak_report.items[0].finding.severity == "critical"


def test_markdown_report_sections(weak_report):
    markdown = render_markdown(weak_report)
    assert markdown.startswith("# MCP security audit — `weak_server`")
    for section in ("## Summary", "## Findings and fixes", "## Agents involved (A2A)", "```python"):
        assert section in markdown
    assert "**Evidence**" in markdown and "**Fix**" in markdown
    assert "AKIAIOSFODNN7EXAMPLE" not in markdown  # secrets masqués jusque dans le rapport


def test_empty_report_says_no_finding(weak_report):
    empty = weak_report.model_copy(update={"items": [], "overall_risk": "none"})
    assert "No finding" in render_markdown(empty)


def test_write_reports(tmp_path, weak_report):
    json_path, markdown_path = write_reports(weak_report, tmp_path)
    assert json.loads(json_path.read_text(encoding="utf-8"))["target"] == "weak_server"
    assert markdown_path.read_text(encoding="utf-8").startswith("# MCP security audit")
