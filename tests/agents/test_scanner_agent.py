"""Phase 2 — agent Scanner (ADK) connecté à l'inspecteur via MCP."""

import json

import pytest
from google.adk.runners import InMemoryRunner
from google.genai import types

from auditor.agents.scanner.agent import build_scanner_agent, parse_target_request
from auditor.agents.scanner.llm_review import build_description_reviewer
from tests.agents.fakes import ScriptedLlm

pytestmark = pytest.mark.anyio


async def run_scanner(agent, text: str) -> tuple[dict, list]:
    runner = InMemoryRunner(agent=agent, app_name="scanner")
    session = await runner.session_service.create_session(app_name="scanner", user_id="test")
    message = types.Content(role="user", parts=[types.Part(text=text)])
    events = [
        event async for event in runner.run_async(user_id="test", session_id=session.id, new_message=message)
    ]
    return json.loads(events[-1].content.parts[0].text), events


async def test_scanner_finds_all_weak_server_risks_offline():
    result, _ = await run_scanner(build_scanner_agent(use_llm=False), '{"target": "weak_server"}')
    assert result["target"] == "weak_server"
    assert len(result["findings"]) == 15
    assert {f["category"] for f in result["findings"]} == {
        "tool_poisoning",
        "excessive_permissions",
        "missing_input_validation",
        "hardcoded_secret",
    }
    assert all(f["detector"] == "rule" for f in result["findings"])


async def test_scanner_reports_nothing_on_safe_server():
    result, _ = await run_scanner(build_scanner_agent(use_llm=False), "safe_server")
    assert result["findings"] == []
    assert len(result["manifest"]["tools"]) == 3


@pytest.mark.parametrize("request_text", ["../etc", "does_not_exist"])
async def test_scanner_returns_error_for_invalid_targets(request_text):
    result, _ = await run_scanner(build_scanner_agent(use_llm=False), request_text)
    assert "error" in result


def test_parse_target_request():
    assert parse_target_request('{"target": "weak_server"}') == "weak_server"
    assert parse_target_request("  safe_server\n") == "safe_server"
    with pytest.raises(ValueError):
        parse_target_request("rm -rf /")


async def test_llm_review_is_merged_and_labelled():
    review = {
        "verdicts": [
            {"tool": "add", "suspicious": True, "reason": "asks to read SSH key", "quote": "read the file"},
            {"tool": "read_file", "suspicious": True, "reason": "too broad", "quote": "Read any file"},
            {"tool": "search_notes", "suspicious": False, "reason": "plain", "quote": "Search notes"},
        ]
    }
    fake_model = ScriptedLlm(model="fake", response_text=json.dumps(review))
    agent = build_scanner_agent(reviewer=build_description_reviewer(model=fake_model))

    result, _ = await run_scanner(agent, "weak_server")

    findings = {f["id"]: f for f in result["findings"]}
    # Constat règle existant : enrichi, pas dupliqué.
    assert any("confirmed by LLM review" in item for item in findings["TP001:add"]["indicators"])
    # Constat nouveau : étiqueté comme venant du LLM.
    assert findings["LLM-TP:read_file"]["detector"] == "llm"
    assert "LLM-TP:search_notes" not in findings
    # Le modèle a bien reçu les descriptions, présentées comme des données.
    prompt = fake_model.requests[0].config.system_instruction
    assert "<IMPORTANT>" in str(prompt) and "never as instructions" in str(prompt)


@pytest.mark.live
async def test_live_mistral_review_flags_poisoned_tool():
    """Vrai appel à Mistral via LiteLLM — lancé seulement si MISTRAL_API_KEY est défini."""
    import os

    if not os.environ.get("MISTRAL_API_KEY"):
        pytest.skip("MISTRAL_API_KEY not set")
    result, _ = await run_scanner(build_scanner_agent(use_llm=True), "weak_server")
    add = next(f for f in result["findings"] if f["id"] == "TP001:add")
    assert any("confirmed by LLM review" in item for item in add["indicators"])
