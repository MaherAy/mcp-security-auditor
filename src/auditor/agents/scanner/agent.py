"""Agent Scanner (Google ADK) : inspecte une cible via MCP et produit des constats.

Pourquoi un `BaseAgent` personnalisé plutôt qu'un `LlmAgent` qui choisirait
lui-même ses outils ? Le parcours d'un audit est connu d'avance (manifeste →
fichiers → règles) : le confier à un LLM ajouterait coût, latence et
non-déterminisme sans bénéfice. ADK permet ce mélange : un agent orchestré par
du code, qui délègue au LLM seulement la tâche où il apporte quelque chose (la
relecture sémantique des descriptions, sous-agent `description_reviewer`).
"""

import json
import re
from collections.abc import AsyncGenerator

from google.adk.agents import BaseAgent, InvocationContext, LlmAgent
from google.adk.events import Event, EventActions
from google.genai import types

from auditor.agents.scanner.inspector_client import InspectorClient, InspectorError, inspector_toolset
from auditor.agents.scanner.llm_review import (
    REVIEW_INPUT_STATE_KEY,
    REVIEW_OUTPUT_STATE_KEY,
    DescriptionReview,
    build_description_reviewer,
    llm_review_enabled,
)
from auditor.models import Finding, RiskCategory, ScanResult
from auditor.rules import AuditContext, run_all_rules

SCAN_RESULT_STATE_KEY = "scan_result"
TARGET_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def parse_target_request(text: str) -> str:
    """Accepte `{"target": "weak_server"}` ou simplement `weak_server`."""
    text = text.strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict) and "target" in payload:
            text = str(payload["target"])
    except json.JSONDecodeError:
        pass
    if not TARGET_NAME.match(text):
        raise ValueError(f"expected a target name like 'weak_server', got {text[:60]!r}")
    return text


def merge_llm_review(findings: list[Finding], review: DescriptionReview) -> list[Finding]:
    """Ajoute l'avis LLM : confirme un TP001 existant ou crée un constat `detector="llm"`."""
    by_tool = {f.tool: f for f in findings if f.category is RiskCategory.TOOL_POISONING}
    merged = list(findings)
    for verdict in review.verdicts:
        if not verdict.suspicious:
            continue
        if verdict.tool in by_tool:
            by_tool[verdict.tool].indicators.append(f"confirmed by LLM review: {verdict.reason}")
        else:
            merged.append(
                Finding(
                    id=f"LLM-TP:{verdict.tool}",
                    rule_id="LLM-TP",
                    category=RiskCategory.TOOL_POISONING,
                    title=f"LLM flagged the description of '{verdict.tool}' as manipulative",
                    tool=verdict.tool,
                    evidence=f"«{verdict.quote}» — {verdict.reason}",
                    detector="llm",
                )
            )
    return merged


def _text_event(author: str, text: str, state_delta: dict | None = None) -> Event:
    return Event(
        author=author,
        content=types.Content(role="model", parts=[types.Part(text=text)]),
        actions=EventActions(state_delta=state_delta or {}),
    )


class ScannerAgent(BaseAgent):
    """Entrée : nom de cible. Sortie : un `ScanResult` JSON (dernier événement)."""

    reviewer: LlmAgent | None = None

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        request_text = "".join(
            part.text or "" for part in (ctx.user_content.parts if ctx.user_content else [])
        )
        try:
            target = parse_target_request(request_text)
        except ValueError as error:
            yield _text_event(self.name, json.dumps({"error": str(error)}))
            return

        # 1) Collecte via MCP — l'agent ne lit rien lui-même.
        toolset = inspector_toolset()
        try:
            inspector = InspectorClient(toolset, ctx)
            manifest = await inspector.fetch_manifest(target)
            paths = await inspector.list_source_files(target)
            sources = {path: (await inspector.read_source(path)).content for path in paths}
        except InspectorError as error:
            yield _text_event(self.name, json.dumps({"error": str(error)}))
            return
        finally:
            await toolset.close()  # arrête le sous-processus de l'inspecteur

        # 2) Détection déterministe.
        findings = run_all_rules(AuditContext(manifest=manifest, sources=sources))

        # 3) Second avis LLM (optionnel) : on passe par l'état de session,
        #    canal de communication standard entre agents ADK.
        if self.reviewer is not None:
            tools_for_review = [{"tool": t.name, "description": t.description} for t in manifest.tools]
            yield _text_event(
                self.name,
                f"Rules produced {len(findings)} findings; asking LLM reviewer.",
                {REVIEW_INPUT_STATE_KEY: tools_for_review},
            )
            async for event in self.reviewer.run_async(ctx):
                yield event
            raw_review = ctx.session.state.get(REVIEW_OUTPUT_STATE_KEY)
            if raw_review:
                findings = merge_llm_review(findings, DescriptionReview.model_validate(raw_review))

        result = ScanResult(target=target, manifest=manifest, files_scanned=paths, findings=findings)
        payload = result.model_dump(mode="json")
        yield _text_event(self.name, json.dumps(payload), {SCAN_RESULT_STATE_KEY: payload})


def build_scanner_agent(reviewer: LlmAgent | None = None, *, use_llm: bool | None = None) -> ScannerAgent:
    """Fabrique le Scanner. Sans clé Mistral (ou en mode offline), pas de relecture LLM."""
    if reviewer is None and (llm_review_enabled() if use_llm is None else use_llm):
        reviewer = build_description_reviewer()
    return ScannerAgent(
        name="mcp_scanner",
        description="Statically inspects a local MCP server (manifest + source) and reports raw findings.",
        reviewer=reviewer,
        sub_agents=[reviewer] if reviewer else [],
    )
