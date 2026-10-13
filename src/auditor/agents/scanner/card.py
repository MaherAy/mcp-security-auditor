"""Agent Card du Scanner : ce que l'agent annonce publiquement en A2A.

On écrit la carte à la main plutôt que de laisser ADK la générer : la carte
automatique d'un agent personnalisé ne contient qu'une compétence « custom »,
inutile pour un orchestrateur qui doit savoir QUOI envoyer et QUOI attendre.
"""

from a2a.types import AgentCard, AgentSkill

from auditor.a2a_common import JSON_MEDIA_TYPE, TEXT_MEDIA_TYPE, agent_url, build_agent_card

SCAN_SKILL_ID = "scan_mcp_server"


def build_scanner_card(url: str | None = None) -> AgentCard:
    return build_agent_card(
        name="mcp_scanner",
        description=(
            "Statically inspects a local MCP test server through the mcp-inspector MCP server "
            "(manifest via tools/list + source code) and returns raw, unrated findings. "
            "Built with Google ADK."
        ),
        url=url or agent_url("scanner"),
        input_modes=[TEXT_MEDIA_TYPE],
        output_modes=[JSON_MEDIA_TYPE],
        skills=[
            AgentSkill(
                id=SCAN_SKILL_ID,
                name="Scan an MCP server",
                description=(
                    "Input: a target name from the auditor's targets/ folder (text, e.g. 'weak_server'). "
                    "Output: a ScanResult JSON data part {target, manifest, files_scanned, findings[]}. "
                    "Detects tool poisoning, excessive permissions, missing input validation, "
                    "hardcoded secrets. Never calls the target's tools."
                ),
                tags=["security", "mcp", "static-analysis", "google-adk"],
                examples=["weak_server", '{"target": "safe_server"}'],
                input_modes=[TEXT_MEDIA_TYPE],
                output_modes=[JSON_MEDIA_TYPE],
            )
        ],
    )
