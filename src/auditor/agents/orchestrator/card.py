"""Agent Card de l'orchestrateur."""

from a2a.types import AgentCard, AgentSkill

from auditor.a2a_common import JSON_MEDIA_TYPE, TEXT_MEDIA_TYPE, agent_url, build_agent_card

AUDIT_SKILL_ID = "audit_mcp_server"
MARKDOWN_MEDIA_TYPE = "text/markdown"


def build_orchestrator_card(url: str | None = None) -> AgentCard:
    return build_agent_card(
        name="mcp_audit_orchestrator",
        description=(
            "Runs a complete static security audit of a local MCP test server by delegating over A2A "
            "to a scanner, an evaluator and a remediation agent, discovered through their Agent Cards. "
            "Built with the A2A Python SDK only."
        ),
        url=url or agent_url("orchestrator"),
        input_modes=[TEXT_MEDIA_TYPE, JSON_MEDIA_TYPE],
        output_modes=[JSON_MEDIA_TYPE, MARKDOWN_MEDIA_TYPE],
        skills=[
            AgentSkill(
                id=AUDIT_SKILL_ID,
                name="Audit an MCP server",
                description=(
                    "Input: 'audit <target>' (text) or {\"target\": ...} (data). Output: an AuditReport JSON "
                    "data artifact and a Markdown artifact, findings sorted by severity with evidence and fixes."
                ),
                tags=["security", "mcp", "orchestration", "a2a-sdk"],
                examples=["audit weak_server", "audite safe_server", '{"target": "weak_server"}'],
                input_modes=[TEXT_MEDIA_TYPE, JSON_MEDIA_TYPE],
                output_modes=[JSON_MEDIA_TYPE, MARKDOWN_MEDIA_TYPE],
            )
        ],
    )
