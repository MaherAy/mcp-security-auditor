"""Agent Card de l'agent Remédiation (LangGraph)."""

from a2a.types import AgentCard, AgentSkill

from auditor.a2a_common import JSON_MEDIA_TYPE, agent_url, build_agent_card

REMEDIATE_SKILL_ID = "propose_fixes"


def build_remediation_card(url: str | None = None) -> AgentCard:
    return build_agent_card(
        name="mcp_remediation_advisor",
        description=(
            "Proposes one fix per rated MCP security finding (steps, reviewed code example, CWE/OWASP "
            "references), in priority order. Built with LangGraph."
        ),
        url=url or agent_url("remediation"),
        input_modes=[JSON_MEDIA_TYPE],
        output_modes=[JSON_MEDIA_TYPE],
        skills=[
            AgentSkill(
                id=REMEDIATE_SKILL_ID,
                name="Propose fixes",
                description=(
                    "Input: an Evaluation JSON data part (as produced by mcp_risk_evaluator). "
                    "Output: a RemediationPlan JSON data part {target, items[], tailored_by}. "
                    "Code examples come from a reviewed catalogue, never from the LLM."
                ),
                tags=["security", "remediation", "langgraph"],
                input_modes=[JSON_MEDIA_TYPE],
                output_modes=[JSON_MEDIA_TYPE],
            )
        ],
    )
