"""Briques A2A partagées : adresses des agents, Agent Cards, client de Task.

POURQUOI A2A ENTRE LES AGENTS (et pas MCP) ?
MCP relie un agent à des *outils* : appels courts, sans état, pilotés par
l'agent. A2A relie des *agents* entre eux : chacun est un service autonome,
écrit dans le framework de son choix (ADK, LangGraph…), qui annonce ce qu'il
sait faire dans une Agent Card et traite des Tasks ayant un cycle de vie
(submitted → working → completed / failed). L'orchestrateur n'a pas à savoir
comment l'Évaluateur est codé : il lit sa carte et lui envoie une Task.

Note SDK : `a2a-sdk` 1.x génère ses types depuis protobuf (`a2a.types` =
messages protobuf), là où la 0.3 utilisait Pydantic. On construit donc les
cartes et messages avec les constructeurs protobuf, et on les convertit en
dict avec `google.protobuf.json_format`.
"""

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.helpers.proto_helpers import new_message, new_text_part
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    GetTaskRequest,
    Part,
    Role,
    SendMessageRequest,
    Task,
    TaskState,
)
from a2a.utils.constants import PROTOCOL_VERSION_CURRENT, TransportProtocol
from google.protobuf.json_format import MessageToDict
from google.protobuf.struct_pb2 import Value

# --- Adresses des agents (surchargeables par variables d'environnement) -------

DEFAULT_PORTS = {"orchestrator": 10000, "scanner": 10001, "evaluator": 10002, "remediation": 10003}
JSON_MEDIA_TYPE = "application/json"
TEXT_MEDIA_TYPE = "text/plain"


def agent_port(agent: str) -> int:
    return int(os.environ.get(f"AUDITOR_{agent.upper()}_PORT", DEFAULT_PORTS[agent]))


def agent_url(agent: str) -> str:
    host = os.environ.get("AUDITOR_HOST", "localhost")
    return os.environ.get(f"AUDITOR_{agent.upper()}_URL", f"http://{host}:{agent_port(agent)}")


# --- Agent Cards ------------------------------------------------------------------


def build_agent_card(
    *,
    name: str,
    description: str,
    url: str,
    skills: list[AgentSkill],
    input_modes: list[str],
    output_modes: list[str],
    streaming: bool = True,
) -> AgentCard:
    """Carte d'identité publique d'un agent, servie sur /.well-known/agent-card.json."""
    return AgentCard(
        name=name,
        description=description,
        version="0.1.0",
        provider=AgentProvider(organization="MCP Security Auditor (student project)", url=url),
        supported_interfaces=[
            AgentInterface(
                url=url,
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version=PROTOCOL_VERSION_CURRENT,
            )
        ],
        capabilities=AgentCapabilities(streaming=streaming, push_notifications=False),
        default_input_modes=input_modes,
        default_output_modes=output_modes,
        skills=skills,
    )


# --- Parties de message -------------------------------------------------------------


def data_part(payload: dict[str, Any]) -> Part:
    """Partie A2A `data` : du JSON structuré (et non du texte à re-parser)."""
    value = Value()
    value.struct_value.update(payload)
    return Part(data=value, media_type=JSON_MEDIA_TYPE)


def part_payload(part: Part) -> Any:
    """Contenu Python d'une partie : dict pour `data`, str pour `text`."""
    kind = part.WhichOneof("content")
    if kind == "data":
        return MessageToDict(part.data)
    if kind == "text":
        return part.text
    return None


def task_data(task: Task) -> dict[str, Any]:
    """Premier contenu `data` des artefacts d'une Task terminée."""
    for artifact in task.artifacts:
        for part in artifact.parts:
            payload = part_payload(part)
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, str):
                try:  # tolérance : certains agents renvoient du JSON en texte
                    return json.loads(payload)
                except json.JSONDecodeError:
                    continue
    raise ValueError(f"task {task.id} has no structured data artifact")


def task_status_text(task: Task) -> str:
    message = task.status.message
    return " ".join(part.text for part in message.parts if part.WhichOneof("content") == "text")


# --- Client : envoyer une Task et suivre son cycle de vie ---------------------------


@dataclass
class TaskTrace:
    """Ce que l'orchestrateur a observé d'une Task (pour le rapport et le débogage)."""

    agent_name: str
    task_id: str = ""
    states: list[str] = field(default_factory=list)

    def record(self, state: int) -> None:
        name = TaskState.Name(state).removeprefix("TASK_STATE_").lower()
        if not self.states or self.states[-1] != name:
            self.states.append(name)


class A2AAgentError(RuntimeError):
    """La Task distante a fini dans un état d'échec (failed, rejected…)."""


async def discover_agent(http: httpx.AsyncClient, base_url: str) -> AgentCard:
    """Découverte : GET <base_url>/.well-known/agent-card.json."""
    return await A2ACardResolver(http, base_url).get_agent_card()


async def send_task(
    http: httpx.AsyncClient,
    card: AgentCard,
    parts: list[Part],
    *,
    on_update: Callable[[TaskTrace], None] | None = None,
) -> tuple[Task, TaskTrace]:
    """Envoie un message (→ crée une Task), suit les mises à jour en streaming,
    puis relit la Task finale complète avec `tasks/get`."""
    client = ClientFactory(ClientConfig(httpx_client=http, streaming=card.capabilities.streaming)).create(
        card
    )
    message = new_message(parts=parts, role=Role.ROLE_USER)
    trace = TaskTrace(agent_name=card.name)
    # Volontairement PAS de `client.close()` : dans a2a-sdk 1.2, il ferme aussi le
    # client httpx qu'on lui a prêté (JsonRpcTransport.close → httpx.aclose).
    # Le client httpx appartient à l'appelant, qui le ferme lui-même (`async with`).
    async for response in client.send_message(SendMessageRequest(message=message)):
        kind = response.WhichOneof("payload")
        if kind == "task":
            trace.task_id = response.task.id
            trace.record(response.task.status.state)
        elif kind == "status_update":
            trace.task_id = response.status_update.task_id
            trace.record(response.status_update.status.state)
        if on_update:
            on_update(trace)
    task = await client.get_task(GetTaskRequest(id=trace.task_id))
    trace.record(task.status.state)
    if task.status.state != TaskState.TASK_STATE_COMPLETED:
        raise A2AAgentError(f"{card.name} task {task.id} ended {trace.states[-1]}: {task_status_text(task)}")
    return task, trace


def text_parts(text: str) -> list[Part]:
    return [new_text_part(text)]
