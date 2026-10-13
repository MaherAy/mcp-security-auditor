"""Ligne de commande `auditor`.

    auditor up                    lance les 4 agents A2A (Ctrl+C pour arrêter)
    auditor audit weak_server     envoie « audit weak_server » à l'orchestrateur (A2A)
    auditor demo weak_server      up + audit + arrêt, en une commande

La CLI est elle-même un simple CLIENT A2A de l'orchestrateur : elle ne connaît
ni le Scanner, ni l'Évaluateur, ni la Remédiation.
"""

import argparse
import asyncio
import contextlib
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
from dotenv import load_dotenv

from auditor.a2a_common import (
    A2AAgentError,
    TaskTrace,
    agent_port,
    agent_url,
    discover_agent,
    send_task,
    task_data,
    text_parts,
)
from auditor.agents.orchestrator.report import write_reports
from auditor.models import AuditReport, Severity

AGENTS = ["scanner", "evaluator", "remediation", "orchestrator"]
# Premier lancement sur un environnement neuf : Python compile le bytecode d'ADK,
# LangChain, LiteLLM… (plus d'une minute mesurée). Les agents démarrent en
# parallèle, chacun avec ce délai (surchargeable).
STARTUP_TIMEOUT_SECONDS = float(os.environ.get("AUDITOR_STARTUP_TIMEOUT", "180"))


def _wait_until_ready(url: str, process: subprocess.Popen, deadline: float) -> None:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"agent at {url} exited with code {process.returncode}")
        with contextlib.suppress(httpx.TransportError):
            if httpx.get(f"{url}/.well-known/agent-card.json", timeout=2).status_code == 200:
                return
        time.sleep(0.3)
    raise RuntimeError(f"agent at {url} did not publish its Agent Card in time")


def _port_in_use(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


@contextlib.contextmanager
def running_agents(log_dir: Path, *, offline: bool = False) -> Iterator[dict[str, str]]:
    """Lance chaque agent dans son propre processus (= services indépendants)."""
    # Sans ce contrôle, un ancien processus sur le même port répondrait à la
    # découverte à la place du nouvel agent (vécu pendant le développement).
    busy = [f"{name}:{agent_port(name)}" for name in AGENTS if _port_in_use(agent_port(name))]
    if busy:
        raise RuntimeError(
            f"port(s) already in use: {', '.join(busy)} — stop the other process or set AUDITOR_<AGENT>_PORT"
        )
    log_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ | {"PYTHONIOENCODING": "utf-8"} | ({"AUDITOR_OFFLINE": "1"} if offline else {})
    processes: list[subprocess.Popen] = []
    log_files = []
    try:
        # Démarrage en parallèle : l'orchestrateur n'a pas besoin des autres pour
        # démarrer, il ne les découvre qu'au moment d'un audit.
        for name in AGENTS:
            log_file = (log_dir / f"{name}.log").open("w", encoding="utf-8")
            log_files.append(log_file)
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-m", f"auditor.agents.{name}"],
                    env=env,
                    stdout=log_file,
                    stderr=log_file,
                )
            )
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        for name, process in zip(AGENTS, processes, strict=True):
            _wait_until_ready(agent_url(name), process, deadline)
            print(f"  ✓ {name:<13} {agent_url(name)}/.well-known/agent-card.json")
        yield {name: agent_url(name) for name in AGENTS}
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=10)
        for log_file in log_files:
            log_file.close()


async def audit(target: str, orchestrator_url: str, output_dir: Path) -> AuditReport:
    printed = 0

    def show_progress(trace: TaskTrace) -> None:
        nonlocal printed
        for message in trace.messages[printed:]:
            print(f"  … {message}")
        printed = len(trace.messages)

    async with httpx.AsyncClient(timeout=600) as http:
        card = await discover_agent(http, orchestrator_url)
        print(f"→ {card.name}: audit {target}")
        task, trace = await send_task(http, card, text_parts(f"audit {target}"), on_update=show_progress)

    report = AuditReport.model_validate(task_data(task))
    json_path, markdown_path = write_reports(report, output_dir)
    counts = ", ".join(f"{s.value}={report.counts[s]}" for s in Severity if report.counts.get(s))
    print(
        f"✓ task {' → '.join(trace.states)} · overall risk: {str(report.overall_risk).upper()} · {counts or 'none'}"
    )
    print(f"  {markdown_path}\n  {json_path}")
    return report


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # console Windows (cp1252) → UTF-8
        with contextlib.suppress(AttributeError):
            stream.reconfigure(encoding="utf-8")
    load_dotenv()  # MISTRAL_API_KEY etc. depuis .env s'il existe

    parser = argparse.ArgumentParser(
        prog="auditor", description="Multi-agent static auditor for MCP servers."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    up = commands.add_parser("up", help="start the four A2A agents")
    run = commands.add_parser("audit", help="ask the running orchestrator to audit a target")
    demo = commands.add_parser("demo", help="start the agents, audit a target, stop the agents")
    for command in (run, demo):
        command.add_argument("target", help="target folder name in targets/, e.g. weak_server")
        command.add_argument(
            "--out", type=Path, default=Path("reports"), help="output folder (default: reports)"
        )
    for command in (up, demo):
        command.add_argument("--offline", action="store_true", help="never call the LLM (templates only)")
    run.add_argument("--url", default=None, help="orchestrator URL (default: from AUDITOR_* env vars)")
    args = parser.parse_args(argv)

    log_dir = Path("reports") / "logs"
    try:
        if args.command == "up":
            print("Starting agents (logs in reports/logs/)…")
            with running_agents(log_dir, offline=args.offline):
                print(
                    f"Ready. Try: auditor audit weak_server   (orchestrator on port {agent_port('orchestrator')})"
                )
                with contextlib.suppress(KeyboardInterrupt):
                    while True:
                        time.sleep(1)
        elif args.command == "audit":
            asyncio.run(audit(args.target, args.url or agent_url("orchestrator"), args.out))
        else:
            print("Starting agents (logs in reports/logs/)…")
            with running_agents(log_dir, offline=args.offline) as urls:
                asyncio.run(audit(args.target, urls["orchestrator"], args.out))
    except (A2AAgentError, RuntimeError, httpx.HTTPError) as error:
        print(f"✗ {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
