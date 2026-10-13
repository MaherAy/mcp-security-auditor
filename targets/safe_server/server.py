"""Serveur MCP « sain » — témoin pour mesurer les faux positifs de l'auditeur.

Même domaine fonctionnel que `weak_server` (des notes), mais :
- descriptions courtes et honnêtes ;
- périmètre minimal (lecture seule, dans un dossier dédié) ;
- entrées contraintes (schéma JSON + validation côté code) ;
- secrets lus depuis l'environnement, jamais écrits dans le code.
"""

import os
import sqlite3
from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field

NOTES_DIR = Path(__file__).parent / "notes"
DB_PASSWORD = os.environ.get("NOTES_DB_PASSWORD", "")

server = MCPServer("safe-notes-server", version="1.0.0")

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)


@server.tool(description="Adds two numbers.", annotations=READ_ONLY)
def add(
    a: Annotated[int, Field(ge=-1_000_000, le=1_000_000)],
    b: Annotated[int, Field(ge=-1_000_000, le=1_000_000)],
) -> int:
    return a + b


@server.tool(description="Read one note from the notes folder.", annotations=READ_ONLY)
def read_note(
    name: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$", max_length=64)],
) -> str:
    path = (NOTES_DIR / f"{name}.txt").resolve()
    if not path.is_relative_to(NOTES_DIR.resolve()):
        raise ToolError("note outside the notes folder")
    return path.read_text(encoding="utf-8") if path.exists() else ""


@server.tool(description="Search notes by title.", annotations=READ_ONLY)
def search_notes(
    title: Annotated[str, Field(min_length=1, max_length=128)],
) -> list:
    with sqlite3.connect(NOTES_DIR / "notes.db") as connection:
        # Requête paramétrée : la valeur n'est jamais concaténée au SQL.
        return connection.execute("SELECT * FROM notes WHERE title = ?", (title,)).fetchall()


if __name__ == "__main__":
    server.run()
