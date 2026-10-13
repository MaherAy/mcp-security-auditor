"""Adaptateur A2A « à la main » pour des graphes LangGraph.

Contrairement à ADK (`to_a2a`), LangGraph ne fournit pas de serveur A2A : on
écrit donc nous-mêmes l'`AgentExecutor` du SDK A2A. C'est la façon standard
d'exposer N'IMPORTE QUEL code en A2A, et elle rend visible ce qu'ADK cachait :

    requête A2A ─► DefaultRequestHandler ─► AgentExecutor.execute(context, event_queue)
                                               │
                                               ├─ Task(SUBMITTED)         (création)
                                               ├─ status WORKING + message (un par nœud du graphe)
                                               ├─ artifact (partie data JSON)
                                               └─ status COMPLETED / FAILED

Le `TaskStore` (en mémoire) garde l'état de chaque Task, ce qui permet au
client de la relire ensuite avec `GetTask`.
"""

from typing import Any

from a2a.helpers.proto_helpers import new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import AgentCard, Task, TaskState, TaskStatus
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette

from auditor.a2a_common import data_part, part_payload


class LangGraphA2AExecutor(AgentExecutor):
    """Exécute un graphe LangGraph pour chaque Task A2A.

    - entrée : la première partie `data` du message, validée par `input_model`,
      placée dans l'état du graphe sous `input_key` ;
    - sortie : l'objet Pydantic trouvé dans l'état final sous `output_key`,
      publié comme artefact `data`.
    """

    def __init__(
        self,
        graph: CompiledStateGraph,
        *,
        input_key: str,
        input_model: type[BaseModel],
        output_key: str,
        artifact_name: str,
    ) -> None:
        self.graph = graph
        self.input_key = input_key
        self.input_model = input_model
        self.output_key = output_key
        self.artifact_name = artifact_name

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # 1) Création de la Task (si c'est un nouveau message, pas une reprise).
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

        # 2) Validation de l'entrée : un message mal formé termine la Task en
        #    REJECTED (l'agent refuse la demande) plutôt qu'en FAILED (il a planté).
        try:
            payload = next(
                part_payload(part) for part in context.message.parts if isinstance(part_payload(part), dict)
            )
            graph_input = self.input_model.model_validate(payload)
        except (StopIteration, ValidationError) as error:
            reason = "expected a JSON data part" if isinstance(error, StopIteration) else str(error)[:500]
            await updater.reject(updater.new_agent_message([new_text_part(f"Invalid input: {reason}")]))
            return

        await updater.start_work()

        # 3) Exécution du graphe en streaming : une mise à jour WORKING par nœud
        #    terminé, visible par le client A2A (suivi de progression).
        final_state: dict[str, Any] = {}
        try:
            async for update in self.graph.astream({self.input_key: graph_input}, stream_mode="updates"):
                for node_name, node_output in update.items():
                    final_state.update(node_output or {})
                    await updater.update_status(
                        TaskState.TASK_STATE_WORKING,
                        updater.new_agent_message([new_text_part(f"step '{node_name}' done")]),
                    )
            result: BaseModel = final_state[self.output_key]
        except Exception as error:  # noqa: BLE001 — on transforme toute panne en Task FAILED explicite
            await updater.failed(
                updater.new_agent_message([new_text_part(f"{type(error).__name__}: {error}")])
            )
            return

        # 4) Résultat structuré, puis état terminal.
        await updater.add_artifact([data_part(result.model_dump(mode="json"))], name=self.artifact_name)
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()


def create_a2a_app(card: AgentCard, executor: AgentExecutor) -> Starlette:
    """Application Starlette servant la carte + l'endpoint JSON-RPC A2A."""
    handler = DefaultRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card)
    return Starlette(
        routes=[
            *create_agent_card_routes(card),  # GET /.well-known/agent-card.json
            *create_jsonrpc_routes(handler, rpc_url="/"),  # POST / (JSON-RPC)
        ]
    )
