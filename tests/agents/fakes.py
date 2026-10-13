"""Faux LLM pour tester les agents ADK sans appel réseau ni clé d'API."""

from collections.abc import AsyncGenerator

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field


class ScriptedLlm(BaseLlm):
    """Renvoie toujours la même réponse texte et garde les requêtes reçues."""

    response_text: str
    requests: list[LlmRequest] = Field(default_factory=list)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self.requests.append(llm_request)
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=self.response_text)]))
