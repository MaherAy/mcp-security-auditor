"""Audit Console : interface web d'observabilité (locale) du système multi-agents.

Ce serveur n'est PAS un agent : c'est un client A2A de l'orchestrateur, comme
la CLI. Il relaie au navigateur, en Server-Sent Events (SSE), les événements
structurés que l'orchestrateur publie dans les statuts de sa Task A2A
(ProgressEvent : découverte, états des Tasks déléguées, étapes internes).

    navigateur ◄─SSE── Audit Console ◄─A2A (SendStreamingMessage)── Orchestrateur ──A2A──► agents

Sécurité : écoute sur 127.0.0.1 uniquement, nom de cible validé, et le
navigateur affiche les données de la cible (descriptions empoisonnées,
preuves) via textContent, jamais innerHTML (voir static/index.html).
"""

import asyncio
import json
import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from auditor.a2a_common import TaskTrace, agent_url, discover_agent, send_task, task_data, text_parts
from auditor.agents.orchestrator.pipeline import framework_of
from auditor.mcp_inspector.sandbox import TargetsSandbox

STATIC_DIR = Path(__file__).parent / "static"
TARGET_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
AGENT_ROLES = ["orchestrator", "scanner", "evaluator", "remediation"]


@dataclass
class AuditRun:
    """Un audit lancé depuis l'interface : historique d'événements + abonnés SSE."""

    id: str
    target: str
    events: list[dict[str, Any]] = field(default_factory=list)
    finished: bool = False
    changed: asyncio.Event = field(default_factory=asyncio.Event)

    def publish(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        self.changed.set()  # réveille les flux SSE en attente


class AuditConsole:
    def __init__(self, orchestrator_url: str, agent_urls: dict[str, str]) -> None:
        self.orchestrator_url = orchestrator_url
        self.agent_urls = agent_urls
        self.runs: dict[str, AuditRun] = {}
        self._tasks: set[asyncio.Task] = set()  # garde une référence aux tâches de fond

    async def agents(self, _: Request) -> JSONResponse:
        """État de chaque agent, lu dans son Agent Card (découverte A2A)."""
        result = []
        async with httpx.AsyncClient(timeout=3) as http:
            for role, url in self.agent_urls.items():
                try:
                    card = await discover_agent(http, url)
                except Exception:  # noqa: BLE001 — agent hors ligne : on l'affiche comme tel
                    result.append({"role": role, "url": url, "online": False})
                    continue
                result.append(
                    {
                        "role": role,
                        "url": url,
                        "online": True,
                        "name": card.name,
                        "framework": framework_of(card),
                        "description": card.description,
                        "skills": [{"id": s.id, "name": s.name} for s in card.skills],
                        "streaming": card.capabilities.streaming,
                    }
                )
        return JSONResponse(result)

    async def targets(self, _: Request) -> JSONResponse:
        root = TargetsSandbox().root
        names = sorted(p.parent.name for p in root.glob("*/server.py"))
        return JSONResponse(names)

    async def start_audit(self, request: Request) -> JSONResponse:
        body = await request.json()
        target = str(body.get("target", ""))
        if not TARGET_NAME.match(target):
            return JSONResponse({"error": "invalid target name"}, status_code=400)
        run = AuditRun(id=uuid.uuid4().hex[:12], target=target)
        self.runs[run.id] = run
        task = asyncio.create_task(self._run(run))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return JSONResponse({"audit_id": run.id})

    async def _run(self, run: AuditRun) -> None:
        """Client A2A de l'orchestrateur : chaque statut reçu est relayé tel quel."""
        sent = {"events": 0, "states": 0}

        def relay(trace: TaskTrace) -> None:
            for state in trace.states[sent["states"] :]:
                run.publish({"type": "orchestrator", "state": state, "task_id": trace.task_id})
            sent["states"] = len(trace.states)
            for event in trace.events[sent["events"] :]:
                run.publish({"type": "progress", **event})
            sent["events"] = len(trace.events)

        try:
            async with httpx.AsyncClient(timeout=600) as http:
                card = await discover_agent(http, self.orchestrator_url)
                task, trace = await send_task(http, card, text_parts(f"audit {run.target}"), on_update=relay)
            relay(trace)
            run.publish({"type": "report", "report": task_data(task)})
        except Exception as error:  # noqa: BLE001 — toute panne est montrée à l'utilisateur
            run.publish({"type": "error", "message": f"{type(error).__name__}: {error}"})
        finally:
            run.finished = True
            run.publish({"type": "done"})

    async def stream(self, request: Request) -> EventSourceResponse | JSONResponse:
        run = self.runs.get(request.path_params["audit_id"])
        if run is None:
            return JSONResponse({"error": "unknown audit"}, status_code=404)

        async def events() -> AsyncIterator[dict[str, str]]:
            index = 0  # un abonné tardif reçoit tout l'historique, puis la suite
            while True:
                while index < len(run.events):
                    event = run.events[index]
                    index += 1
                    yield {"event": event["type"], "data": json.dumps(event)}
                if run.finished and index >= len(run.events):
                    return
                run.changed.clear()
                if index >= len(run.events):
                    await run.changed.wait()

        return EventSourceResponse(events())

    async def index(self, _: Request) -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")


def create_app(orchestrator_url: str | None = None, agent_urls: dict[str, str] | None = None) -> Starlette:
    urls = agent_urls or {role: agent_url(role) for role in AGENT_ROLES}
    console = AuditConsole(orchestrator_url or urls["orchestrator"], urls)
    return Starlette(
        routes=[
            Route("/", console.index),
            Route("/api/agents", console.agents),
            Route("/api/targets", console.targets),
            Route("/api/audits", console.start_audit, methods=["POST"]),
            Route("/api/audits/{audit_id}/events", console.stream),
        ]
    )
