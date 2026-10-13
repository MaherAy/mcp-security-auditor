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

from google.adk.a2a.converters.part_converter import (
    A2A_DATA_PART_END_TAG,
    A2A_DATA_PART_START_TAG,
    A2A_DATA_PART_TEXT_MIME_TYPE,
)
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


def data_part(payload: dict) -> types.Part:
    """Partie ADK qui deviendra une partie A2A `data` (JSON structuré).

    POURQUOI : en A2A, un résultat structuré doit voyager comme `data`, pas comme
    du texte à re-parser. ADK n'a pas de type « data » natif ; son convertisseur
    A2A reconnaît un blob encadré par ces balises et le transforme en partie
    `data` (convention de google.adk.a2a.converters.part_converter).
    """
    raw = json.dumps(payload).encode("utf-8")
    return types.Part(
        inline_data=types.Blob(
            mime_type=A2A_DATA_PART_TEXT_MIME_TYPE,
            data=A2A_DATA_PART_START_TAG + raw + A2A_DATA_PART_END_TAG,
        )
    )


def read_data_part(part: types.Part) -> dict | None:
    """Inverse de `data_part` (utile aux tests en mémoire, sans passer par A2A)."""
    blob = part.inline_data
    if blob is None or not blob.data or not blob.data.startswith(A2A_DATA_PART_START_TAG):
        return None
    return json.loads(blob.data[len(A2A_DATA_PART_START_TAG) : -len(A2A_DATA_PART_END_TAG)])


def _error_event(author: str, message: str) -> Event:
    # Un `error_code` fait passer la Task A2A à l'état FAILED (et non COMPLETED).
    return Event(author=author, error_code="SCAN_FAILED", error_message=message)


class ScannerAgent(BaseAgent):
    """Entrée : nom de cible (texte). Sortie : un `ScanResult` en partie `data` (dernier événement)."""

    reviewer: LlmAgent | None = None

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        request_text = "".join(
            part.text or "" for part in (ctx.user_content.parts if ctx.user_content else [])
        )
        try:
            target = parse_target_request(request_text)
        except ValueError as error:
            yield _error_event(self.name, str(error))
            return

        # 1) Collecte via MCP — l'agent ne lit rien lui-même.
        toolset = inspector_toolset()
        try:
            inspector = InspectorClient(toolset, ctx)
            manifest = await inspector.fetch_manifest(target)
            paths = await inspector.list_source_files(target)
            sources = {path: (await inspector.read_source(path)).content for path in paths}
        except InspectorError as error:
            yield _error_event(self.name, str(error))
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
        yield Event(
            author=self.name,
            content=types.Content(role="model", parts=[data_part(payload)]),
            actions=EventActions(state_delta={SCAN_RESULT_STATE_KEY: payload}),
        )


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
