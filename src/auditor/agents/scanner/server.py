"""Expose le Scanner ADK en A2A.

`to_a2a` (fourni par ADK) enveloppe l'agent dans une application Starlette qui :
- sert l'Agent Card sur /.well-known/agent-card.json (découverte) ;
- reçoit les messages JSON-RPC A2A (`SendMessage`, `SendStreamingMessage`, `GetTask`… — noms A2A 1.0) ;
- convertit chaque événement ADK en mise à jour de Task A2A (A2aAgentExecutor).
Aucune ligne de protocole A2A à écrire nous-mêmes : c'est l'intérêt du standard.
"""

from google.adk.a2a.utils.agent_to_a2a import to_a2a
from starlette.applications import Starlette

from auditor.a2a_common import agent_port
from auditor.agents.scanner.agent import build_scanner_agent
from auditor.agents.scanner.card import build_scanner_card


def create_app(*, use_llm: bool | None = None, url: str | None = None) -> Starlette:
    return to_a2a(
        build_scanner_agent(use_llm=use_llm),
        port=agent_port("scanner"),
        agent_card=build_scanner_card(url),
    )
