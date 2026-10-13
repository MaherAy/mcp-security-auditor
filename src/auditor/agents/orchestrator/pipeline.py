"""Cœur de l'orchestrateur : découvrir les agents, déléguer, assembler le rapport.

POURQUOI A2A ICI ? L'orchestrateur ne connaît que des URL. Il découvre ce que
chaque agent sait faire en lisant son Agent Card, choisit l'agent par
COMPÉTENCE (skill id) et lui délègue une Task. Il ignore que le Scanner est
écrit avec ADK et l'Évaluateur avec LangGraph : remplacer l'un par un autre
agent offrant la même compétence ne demande aucun changement ici.

Déroulé d'un audit :
    1. GET /.well-known/agent-card.json sur chaque URL connue (découverte)
    2. Task « scan_mcp_server »   → ScanResult
    3. Task « rate_findings »     → Evaluation
    4. Task « propose_fixes »     → RemediationPlan
    5. fusion → AuditReport (constat + sévérité + preuve + correctif)
"""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import httpx
from a2a.types import AgentCard

from auditor.a2a_common import TaskTrace, data_part, discover_agent, send_task, task_data, text_parts
from auditor.models import (
    AgentRun,
    AuditReport,
    DiscoveredAgent,
    Evaluation,
    ProgressEvent,
    RemediationPlan,
    ReportItem,
    ScanResult,
)

# Rôle dans le pipeline → compétence A2A attendue.
REQUIRED_SKILLS = {
    "scanner": "scan_mcp_server",
    "evaluator": "rate_findings",
    "remediation": "propose_fixes",
}
KNOWN_FRAMEWORKS = ("google-adk", "langgraph", "a2a-sdk")

ProgressCallback = Callable[[ProgressEvent], Awaitable[None]]


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class OrchestrationError(RuntimeError):
    """Un agent requis est introuvable ou une délégation a échoué."""


def framework_of(card: AgentCard) -> str:
    tags = {tag for skill in card.skills for tag in skill.tags}
    return next((name for name in KNOWN_FRAMEWORKS if name in tags), "unknown")


async def discover_agents(http: httpx.AsyncClient, agent_urls: list[str]) -> dict[str, AgentCard]:
    """Associe chaque rôle à la première carte qui annonce la compétence requise."""
    cards: list[AgentCard] = []
    unreachable: list[str] = []
    for url in agent_urls:
        try:
            cards.append(await discover_agent(http, url))
        except Exception as error:  # noqa: BLE001 — un agent absent ne doit pas masquer les autres
            unreachable.append(f"{url} ({type(error).__name__})")
    by_role: dict[str, AgentCard] = {}
    for role, skill_id in REQUIRED_SKILLS.items():
        match = next((card for card in cards if any(s.id == skill_id for s in card.skills)), None)
        if match is None:
            hint = f"; unreachable: {', '.join(unreachable)}" if unreachable else ""
            raise OrchestrationError(
                f"no reachable agent offers the '{skill_id}' skill (needed for {role}){hint}"
            )
        by_role[role] = match
    return by_role


def build_report(
    scan: ScanResult, evaluation: Evaluation, plan: RemediationPlan, agents: list[AgentRun]
) -> AuditReport:
    fixes = {item.finding_id: item for item in plan.items}
    return AuditReport(
        target=scan.target,
        server_name=scan.manifest.server_name,
        tools_count=len(scan.manifest.tools),
        files_scanned=scan.files_scanned,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        overall_risk=evaluation.overall_risk,
        counts=evaluation.counts,
        items=[ReportItem(finding=f, remediation=fixes.get(f.id)) for f in evaluation.findings],
        agents=agents,
        justified_by=evaluation.justified_by,
        tailored_by=plan.tailored_by,
    )


async def run_audit(
    target: str,
    agent_urls: list[str],
    *,
    progress: ProgressCallback | None = None,
    timeout_seconds: float = 300,
) -> AuditReport:
    async def emit(kind: str, message: str, **fields) -> None:
        if progress:
            await progress(ProgressEvent(kind=kind, message=message, at=now_iso(), **fields))

    agents: list[AgentRun] = []

    async def delegate(role: str, card: AgentCard, parts) -> dict:
        who = {"role": role, "agent_name": card.name, "framework": framework_of(card)}
        await emit("agent_message", f"{role}: sending task to {card.name} ({who['framework']})", **who)
        seen = {"states": 0, "messages": 0}

        async def relay(trace: TaskTrace) -> None:
            """Observabilité en direct : chaque nouvel état de la Task déléguée et
            chaque message de l'agent distant (ex. « step 'classify' done ») est
            republié aussitôt, avant même la fin de la délégation."""
            for state in trace.states[seen["states"] :]:
                message = f"{role}: task {trace.task_id[:8]} {state}"
                await emit("task_state", message, task_id=trace.task_id, state=state, **who)
            seen["states"] = len(trace.states)
            for text in trace.messages[seen["messages"] :]:
                short = text if len(text) <= 160 else text[:157] + "…"  # ex. JSON de la relecture LLM
                await emit("agent_message", f"{role} › {short}", task_id=trace.task_id, **who)
            seen["messages"] = len(trace.messages)

        try:
            task, trace = await send_task(http, card, parts, on_update=relay)
        except Exception as error:
            raise OrchestrationError(f"{role} ({card.name}) failed: {error}") from error
        agents.append(
            AgentRun(
                role=role,
                skill_id=REQUIRED_SKILLS[role],
                agent_name=card.name,
                framework=framework_of(card),
                url=card.supported_interfaces[0].url,
                task_id=task.id,
                states=trace.states,
            )
        )
        # Résumé du cycle de vie (les états eux-mêmes ont déjà été publiés par relay).
        await emit(
            "agent_message", f"{role}: task {task.id[:8]} {' → '.join(trace.states)}", task_id=task.id, **who
        )
        return task_data(task)

    async with httpx.AsyncClient(timeout=timeout_seconds) as http:
        cards = await discover_agents(http, agent_urls)
        await emit(
            "discovered",
            "discovered: " + ", ".join(f"{role}={card.name}" for role, card in cards.items()),
            agents=[
                DiscoveredAgent(
                    role=role,
                    name=card.name,
                    framework=framework_of(card),
                    url=card.supported_interfaces[0].url,
                    skills=[skill.id for skill in card.skills],
                )
                for role, card in cards.items()
            ],
        )

        # Chaque sortie est revalidée par Pydantic avant d'être transmise (DECISIONS D16).
        scan = ScanResult.model_validate(await delegate("scanner", cards["scanner"], text_parts(target)))
        evaluation = Evaluation.model_validate(
            await delegate("evaluator", cards["evaluator"], [data_part(scan.model_dump(mode="json"))])
        )
        plan = RemediationPlan.model_validate(
            await delegate(
                "remediation", cards["remediation"], [data_part(evaluation.model_dump(mode="json"))]
            )
        )

    return build_report(scan, evaluation, plan, agents)
