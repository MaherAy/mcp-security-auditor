"""Analyse statique du code Python d'un serveur MCP, via le module `ast`.

Pourquoi l'AST plutôt que des regex sur le texte ? L'AST comprend la structure :
il sait qu'un appel `subprocess.run(..., shell=True)` est bien un appel avec le
mot-clé `shell` à True, quels sont les paramètres d'une fonction, et quelle
fonction est déclarée comme outil MCP (`@server.tool(...)`). Les commentaires
et chaînes qui *ressemblent* à du code dangereux ne déclenchent rien.
"""

import ast
from collections.abc import Iterator
from dataclasses import dataclass

# Fonctions qui exécutent des commandes ou du code.
EXEC_SINKS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "os.system", "os.popen", "eval", "exec",
}  # fmt: skip
# Fonctions qui touchent au système de fichiers à partir d'un chemin.
FILE_SINKS = {"open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "Path", "pathlib.Path"}
# Appels qui montrent que le code confine un chemin avant de l'utiliser.
PATH_CONTAINMENT_CHECKS = {"is_relative_to", "commonpath", "realpath", "relative_to"}
SQL_EXECUTE_METHODS = {"execute", "executemany", "executescript"}


@dataclass
class ToolFunction:
    """Une fonction Python enregistrée comme outil MCP (décorateur `.tool`)."""

    name: str
    params: set[str]
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass
class CallSite:
    call: ast.Call
    qualified_name: str  # ex. "subprocess.run"
    tool: ToolFunction | None  # outil englobant, None si hors outil


def qualified_name(node: ast.expr) -> str:
    """`subprocess.run` -> "subprocess.run", `open` -> "open", sinon ""."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_tool_decorator(decorator: ast.expr) -> bool:
    # Accepte `@server.tool`, `@server.tool()`, `@server.tool(description=...)`, `@tool`.
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return qualified_name(target).split(".")[-1] == "tool"


def find_tool_functions(tree: ast.Module) -> list[ToolFunction]:
    tools = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
            _is_tool_decorator(decorator) for decorator in node.decorator_list
        ):
            params = {arg.arg for arg in node.args.args + node.args.kwonlyargs}
            tools.append(ToolFunction(name=node.name, params=params, node=node))
    return tools


def iter_call_sites(tree: ast.Module) -> Iterator[CallSite]:
    """Tous les appels du module, rattachés à leur outil MCP englobant."""
    tools = find_tool_functions(tree)
    owner_of: dict[int, ToolFunction] = {}
    for tool in tools:
        for child in ast.walk(tool.node):
            owner_of[id(child)] = tool
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield CallSite(call=node, qualified_name=qualified_name(node.func), tool=owner_of.get(id(node)))


def call_has_true_keyword(call: ast.Call, keyword: str) -> bool:
    return any(
        kw.arg == keyword and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def params_used_directly(call: ast.Call, tool: ToolFunction | None) -> list[str]:
    """Paramètres de l'outil passés tels quels (sans transformation) à l'appel."""
    if tool is None:
        return []
    arguments = list(call.args) + [kw.value for kw in call.keywords]
    return [arg.id for arg in arguments if isinstance(arg, ast.Name) and arg.id in tool.params]


def has_path_containment_check(tool: ToolFunction) -> bool:
    return any(
        isinstance(node, ast.Call) and qualified_name(node.func).split(".")[-1] in PATH_CONTAINMENT_CHECKS
        for node in ast.walk(tool.node)
    )


def is_formatted_string(node: ast.expr) -> bool:
    """f-string, concaténation `+`, formatage `%` ou `.format()`."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def source_line(code: str, line: int) -> str:
    lines = code.splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def parse(code: str) -> ast.Module | None:
    try:
        return ast.parse(code)
    except SyntaxError:
        return None  # fichier non analysable : on ne plante pas l'audit
