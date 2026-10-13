"""Catalogue de correctifs : un correctif type par règle, avec exemple de code.

Les exemples de code sont écrits ici, relus, et jamais générés par le LLM :
un correctif de sécurité halluciné serait pire que pas de correctif. Le LLM
(tailor.py) adapte seulement la phrase « fix » au cas précis.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FixTemplate:
    fix: str
    steps: list[str]
    code_example: str = ""
    references: list[str] = field(default_factory=list)


CWE = "https://cwe.mitre.org/data/definitions/{}.html"
OWASP_LLM01 = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
TOOL_POISONING_ARTICLE = "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"

POISONING_FIX = FixTemplate(
    fix="Rewrite the tool description so it only describes what the tool does, for the user and the model alike.",
    steps=[
        "Remove hidden tags (<IMPORTANT>, <SYSTEM>…), instructions to the model and references to files or secrets.",
        "Remove any parameter that only exists to carry exfiltrated data (e.g. a free-text 'notes').",
        "Review tool descriptions in code review like code: they are executed by the client LLM.",
        "Ask MCP clients to show full descriptions and to alert when a description changes.",
    ],
    code_example='@server.tool(description="Adds two numbers.")\ndef add(a: int, b: int) -> int:\n    return a + b',
    references=[TOOL_POISONING_ARTICLE, OWASP_LLM01],
)

CATALOG: dict[str, FixTemplate] = {
    "TP001": POISONING_FIX,
    "LLM-TP": POISONING_FIX,
    "EP001": FixTemplate(
        fix="Remove arbitrary command execution; expose only the specific operations that are needed.",
        steps=[
            "Replace the generic command tool by one tool per allowed operation.",
            "If a subprocess is unavoidable: fixed executable, argument list, shell=False, allowlisted arguments.",
            "Mark remaining risky tools destructive_hint=True so clients ask the user for confirmation.",
        ],
        code_example=(
            'ALLOWED = {"disk_usage": ["df", "-h"], "uptime": ["uptime"]}\n\n'
            '@server.tool(description="Run one allowlisted maintenance check.",\n'
            "             annotations=ToolAnnotations(destructive_hint=False, read_only_hint=True))\n"
            'def run_check(name: Literal["disk_usage", "uptime"]) -> str:\n'
            "    return subprocess.run(ALLOWED[name], shell=False, capture_output=True, text=True,\n"
            "                          check=True, timeout=10).stdout"
        ),
        references=[CWE.format(78), CWE.format(250)],
    ),
    "EP002": FixTemplate(
        fix="Confine file access to a dedicated base directory.",
        steps=[
            "Define a base directory for the tool.",
            "Resolve the requested path and reject it unless it stays inside the base directory.",
            "Prefer opaque identifiers (note names) over raw paths in the tool's parameters.",
        ],
        code_example=(
            'BASE_DIR = Path(__file__).parent / "data"\n\n'
            "def safe_path(name: str) -> Path:\n"
            "    path = (BASE_DIR / name).resolve()\n"
            "    if not path.is_relative_to(BASE_DIR.resolve()):\n"
            '        raise ToolError("path outside the allowed folder")\n'
            "    return path"
        ),
        references=[CWE.format(22)],
    ),
    "EP003": FixTemplate(
        fix="Declare MCP safety annotations on every tool.",
        steps=[
            "read_only_hint=True for tools without side effects.",
            "destructive_hint=True for tools that modify or delete, so clients ask for confirmation.",
            "open_world_hint=True for tools that reach external systems.",
        ],
        code_example=(
            "@server.tool(description=...,\n"
            "             annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))"
        ),
        references=["https://modelcontextprotocol.io/specification"],
    ),
    "IV001": FixTemplate(
        fix="Constrain string parameters in the tool's input schema.",
        steps=[
            "Add pattern, max_length or an enum (Literal) to each string parameter.",
            "Remove parameters the tool does not need.",
            "Keep server-side validation: the schema documents, the code enforces.",
        ],
        code_example=(
            "def read_note(\n"
            '    name: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$", max_length=64)],\n'
            ") -> str: ..."
        ),
        references=[CWE.format(20)],
    ),
    "IV002": FixTemplate(
        fix="Use a parameterized SQL query instead of string formatting.",
        steps=[
            "Pass values as query parameters (?), never inside the SQL string.",
            "Constrain the input length in the tool schema.",
        ],
        code_example='connection.execute("SELECT * FROM notes WHERE title = ?", (title,))',
        references=[CWE.format(89)],
    ),
    "IV003": FixTemplate(
        fix="Validate the parameter before it reaches the dangerous function.",
        steps=[
            "Apply an allowlist (enum, regex) or a containment check to the value.",
            "Reject anything else with a ToolError, without echoing the value.",
        ],
        code_example=(
            'if not re.fullmatch(r"[a-z0-9_-]{1,64}", value):\n    raise ToolError("invalid value")'
        ),
        references=[CWE.format(20), CWE.format(78), CWE.format(22)],
    ),
    "HS001": FixTemplate(
        fix="Remove the credential from the code, rotate it, and load it from the environment.",
        steps=[
            "Revoke/rotate the exposed credential: it must be considered compromised (git history keeps it).",
            "Read it at runtime from an environment variable or a secret manager.",
            "Add a secret scanner (pre-commit hook / CI) to block future commits.",
        ],
        code_example='API_KEY = os.environ["SERVICE_API_KEY"]  # injected at deploy time, never committed',
        references=[CWE.format(798)],
    ),
    "HS002": FixTemplate(
        fix="Move the credential out of the source code into the environment or a secret manager.",
        steps=[
            "Rotate the value if it was ever used for real.",
            "Read it with os.environ / a secret manager at startup.",
        ],
        code_example='DB_PASSWORD = os.environ.get("NOTES_DB_PASSWORD", "")',
        references=[CWE.format(798)],
    ),
}

GENERIC_FIX = FixTemplate(
    fix="Review this finding manually and apply the principle of least privilege.",
    steps=["Confirm the finding.", "Reduce the tool's capabilities to what is strictly needed."],
)


def template_for(rule_id: str) -> FixTemplate:
    return CATALOG.get(rule_id, GENERIC_FIX)
