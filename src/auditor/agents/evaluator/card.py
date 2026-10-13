"""Agent Card de l'Évaluateur (LangGraph)."""

from a2a.types import AgentCard, AgentSkill

from auditor.a2a_common import JSON_MEDIA_TYPE, agent_url, build_agent_card

EVALUATE_SKILL_ID = "rate_findings"


def build_evaluator_card(url: str | None = None) -> AgentCard:
    return build_agent_card(
        name="mcp_risk_evaluator",
        description=(
            "Rates raw MCP security findings: severity (critical/high/medium/low), score, "
            "justification and preserved evidence, sorted by priority. Built with LangGraph."
        ),
        url=url or agent_url("evaluator"),
        input_modes=[JSON_MEDIA_TYPE],
        output_modes=[JSON_MEDIA_TYPE],
        skills=[
            AgentSkill(
                id=EVALUATE_SKILL_ID,
                name="Rate findings",
                description=(
                    "Input: a ScanResult JSON data part (as produced by the mcp_scanner agent). "
                    "Output: an Evaluation JSON data part {target, overall_risk, counts, findings[]}. "
                    "Severity comes from a deterministic policy; the LLM only writes justifications."
                ),
                tags=["security", "risk-rating", "langgraph"],
                input_modes=[JSON_MEDIA_TYPE],
                output_modes=[JSON_MEDIA_TYPE],
            )
        ],
    )
