"""Audit Console : API + flux SSE d'observabilité, et rendu sûr dans un vrai navigateur."""

import json
import re
from pathlib import Path

import httpx
import pytest

from auditor.agents.evaluator.justifier import TemplateJustifier
from auditor.agents.evaluator.server import create_app as create_evaluator_app
from auditor.agents.orchestrator.server import create_app as create_orchestrator_app
from auditor.agents.remediation.server import create_app as create_remediation_app
from auditor.agents.remediation.tailor import TemplateTailor
from auditor.agents.scanner.server import create_app as create_scanner_app
from auditor.ui.server import create_app as create_console_app
from tests.a2a.server_helpers import free_port, serve

INDEX_HTML = Path(__file__).parents[2] / "src" / "auditor" / "ui" / "static" / "index.html"


@pytest.fixture(scope="module")
def console_url():
    roles = ("scanner", "evaluator", "remediation", "orchestrator")
    ports = {role: free_port() for role in (*roles, "console")}
    urls = {role: f"http://127.0.0.1:{ports[role]}" for role in roles}
    delegates = [urls["scanner"], urls["evaluator"], urls["remediation"]]
    with (
        serve(create_scanner_app(use_llm=False, url=urls["scanner"]), ports["scanner"]),
        serve(create_evaluator_app(justifier=TemplateJustifier(), url=urls["evaluator"]), ports["evaluator"]),
        serve(create_remediation_app(tailor=TemplateTailor(), url=urls["remediation"]), ports["remediation"]),
        serve(create_orchestrator_app(agent_urls=delegates, url=urls["orchestrator"]), ports["orchestrator"]),
        serve(create_console_app(agent_urls=urls), ports["console"], probe_path="/api/targets") as console,
    ):
        yield console


def read_sse(url: str) -> list[tuple[str, dict]]:
    """Lit un flux Server-Sent Events jusqu'à l'événement `done`."""
    events, kind = [], None
    with httpx.stream("GET", url, timeout=120) as response:
        for line in response.iter_lines():
            if line.startswith("event:"):
                kind = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                events.append((kind, json.loads(line.split(":", 1)[1])))
                if kind == "done":
                    break
    return events


def test_console_lists_agents_from_their_cards(console_url):
    agents = {a["role"]: a for a in httpx.get(f"{console_url}/api/agents").json()}
    assert all(agent["online"] for agent in agents.values())
    assert agents["scanner"]["framework"] == "google-adk"
    assert agents["evaluator"]["framework"] == "langgraph"
    assert agents["orchestrator"]["framework"] == "a2a-sdk"
    assert {"safe_server", "weak_server"} <= set(httpx.get(f"{console_url}/api/targets").json())


def test_console_rejects_invalid_target_names(console_url):
    response = httpx.post(f"{console_url}/api/audits", json={"target": "../../etc"})
    assert response.status_code == 400


def test_sse_stream_carries_the_whole_audit(console_url):
    audit_id = httpx.post(f"{console_url}/api/audits", json={"target": "weak_server"}).json()["audit_id"]
    events = read_sse(f"{console_url}/api/audits/{audit_id}/events")

    kinds = [kind for kind, _ in events]
    assert kinds[-1] == "done" and "report" in kinds and "error" not in kinds
    progress = [data for kind, data in events if kind == "progress"]
    assert progress[0]["kind"] == "discovered" and len(progress[0]["agents"]) == 3
    # Chaque agent délégué passe par submitted → working → completed, publié en direct.
    for role in ("scanner", "evaluator", "remediation"):
        states = [e["state"] for e in progress if e["kind"] == "task_state" and e["role"] == role]
        assert states == ["submitted", "working", "completed"]
    # Les étapes internes des agents (nœuds LangGraph, appels MCP du Scanner) remontent aussi.
    messages = [e["message"] for e in progress]
    assert "evaluator › step 'classify' done" in messages
    assert any("MCP tools/list: 4 tools" in m for m in messages)
    report = next(data["report"] for kind, data in events if kind == "report")
    assert len(report["items"]) == 15


def test_failed_audit_is_reported_in_the_stream(console_url):
    audit_id = httpx.post(f"{console_url}/api/audits", json={"target": "does_not_exist"}).json()["audit_id"]
    events = read_sse(f"{console_url}/api/audits/{audit_id}/events")
    error = next(data for kind, data in events if kind == "error")
    assert "scanner" in error["message"]


def test_page_never_injects_html():
    """Garde-fou statique : aucune API qui interprète du HTML dans le script de la page."""
    script = INDEX_HTML.read_text(encoding="utf-8").split("<script>")[1]
    code_without_comments = re.sub(r"//.*", "", script)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in code_without_comments


def test_poisoned_description_is_rendered_as_text_in_a_real_browser(console_url):
    """La description de `add` contient « <IMPORTANT>… » : elle doit apparaître comme
    texte dans le panneau de détail, sans créer d'élément <important> dans le DOM."""
    playwright = pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as error:  # noqa: BLE001
            pytest.skip(f"chromium not installed for Playwright: {error}")
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(console_url)
        page.click("#run")
        page.wait_for_selector("tr.finding", timeout=120_000)
        page.locator("tr.finding", has_text="tool poisoning").click()
        evidence = page.locator("#detail pre").first.inner_text()
        injected = page.locator("#detail important").count()
        rows = page.locator("tr.finding").count()
        browser.close()
    assert "<IMPORTANT>" in evidence
    assert injected == 0
    assert rows == 15
    assert errors == []
