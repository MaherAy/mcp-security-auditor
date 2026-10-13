"""Orchestrateur exposé en A2A avec le SDK A2A seul (sans framework d'agent).

Troisième façon d'exposer un agent dans ce projet :
- Scanner      : ADK, `to_a2a` génère tout ;
- Évaluateur   : LangGraph + AgentExecutor générique ;
- Orchestrateur: AgentExecutor écrit pour lui, logique en Python pur.

Il est à la fois SERVEUR A2A (il reçoit « audite weak_server ») et CLIENT
A2A (il délègue aux trois autres agents).
"""

import re

from a2a.helpers.proto_helpers import new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import Part, Task, TaskState, TaskStatus

from auditor.a2a_common import data_part, part_payload
from auditor.agents.orchestrator.pipeline import OrchestrationError, run_audit
from auditor.agents.orchestrator.report import render_markdown
from auditor.models import ProgressEvent

TARGET_NAME = re.compile(r"[A-Za-z0-9_-]+")


def parse_audit_request(parts: list[Part]) -> str:
    """`{"target": "weak_server"}` (data) ou texte libre « audite weak_server » :
    on prend le dernier mot qui ressemble à un nom de cible. Le Scanner (et
    l'inspecteur derrière lui) revalide ce nom : ici on ne fait que l'extraire."""
    for part in parts:
        payload = part_payload(part)
        if isinstance(payload, dict) and isinstance(payload.get("target"), str):
            return payload["target"]
    text = " ".join(p for p in (part_payload(part) for part in parts) if isinstance(p, str))
    words = TARGET_NAME.findall(text)
    if not words:
        raise ValueError("no target name found; send e.g. 'audit weak_server'")
    return words[-1]


class OrchestratorExecutor(AgentExecutor):
    def __init__(self, agent_urls: list[str]) -> None:
        self.agent_urls = agent_urls

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.current_task is None:
            await event_queue.enqueue_event(
                Task(
                    id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                    history=[context.message],
                )
            )
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)

        try:
            target = parse_audit_request(list(context.message.parts))
        except ValueError as error:
            await updater.reject(updater.new_agent_message([new_text_part(str(error))]))
            return

        await updater.start_work(updater.new_agent_message([new_text_part(f"auditing '{target}'")]))

        async def progress(event: ProgressEvent) -> None:
            # Chaque événement devient un statut WORKING visible du client, en double
            # forme : texte (CLI) + partie data structurée (interface d'observabilité).
            parts = [new_text_part(event.message), data_part(event.model_dump(mode="json"))]
            await updater.update_status(TaskState.TASK_STATE_WORKING, updater.new_agent_message(parts))

        try:
            report = await run_audit(target, self.agent_urls, progress=progress)
        except OrchestrationError as error:
            await updater.failed(updater.new_agent_message([new_text_part(str(error))]))
            return
        except Exception as error:  # noqa: BLE001 — ex. sortie d'agent invalide (ValidationError)
            message = f"unexpected {type(error).__name__}: {str(error)[:300]}"
            await updater.failed(updater.new_agent_message([new_text_part(message)]))
            return

        # Deux artefacts : le rapport structuré (machines) et sa version lisible (humains).
        await updater.add_artifact([data_part(report.model_dump(mode="json"))], name="audit_report")
        markdown = new_text_part(render_markdown(report))
        markdown.media_type = "text/markdown"
        await updater.add_artifact([markdown], name="audit_report.md")
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()
