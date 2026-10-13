"""Confinement des accès disque de l'inspecteur.

L'inspecteur est un outil exposé à un LLM : son argument `path` est donc une
entrée non fiable (le LLM peut halluciner, ou être manipulé par une description
empoisonnée — exactement le risque que l'on audite !). On applique donc à notre
propre serveur MCP les règles que l'on reproche à la cible de ne pas suivre :
liste blanche de répertoire, d'extensions, et taille maximale.
"""

import os
from pathlib import Path

# Racine des cibles autorisées ; surchargeable pour les tests.
DEFAULT_TARGETS_ROOT = Path(__file__).resolve().parents[3] / "targets"

ALLOWED_SUFFIXES = {".py", ".json", ".toml", ".yaml", ".yml", ".md", ".txt", ".cfg", ".ini", ".env"}
IGNORED_DIRS = {"__pycache__", ".venv", "venv", "node_modules", ".git"}
MAX_FILE_BYTES = 256 * 1024
TARGET_ENTRYPOINT = "server.py"


class SandboxError(ValueError):
    """Accès refusé : chemin hors racine, extension interdite, fichier trop gros…"""


class TargetsSandbox:
    def __init__(self, root: Path | None = None) -> None:
        env_root = os.environ.get("AUDITOR_TARGETS_ROOT")
        self.root = (root or (Path(env_root) if env_root else DEFAULT_TARGETS_ROOT)).resolve()

    def _inside_root(self, candidate: Path) -> Path:
        resolved = candidate.resolve()  # résout "..", liens symboliques, etc.
        if not resolved.is_relative_to(self.root):
            raise SandboxError("path escapes the targets root")
        return resolved

    def target_dir(self, target: str) -> Path:
        """Dossier d'une cible : un nom simple, jamais un chemin."""
        if not target or "/" in target or "\\" in target or target.startswith("."):
            raise SandboxError(f"invalid target name: {target!r}")
        directory = self._inside_root(self.root / target)
        if not (directory / TARGET_ENTRYPOINT).is_file():
            raise SandboxError(f"unknown target: {target!r}")
        return directory

    def entrypoint(self, target: str) -> Path:
        return self.target_dir(target) / TARGET_ENTRYPOINT

    def source_file(self, relative_path: str) -> Path:
        path = self._inside_root(self.root / relative_path)
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            raise SandboxError(f"file type not allowed: {path.suffix!r}")
        if not path.is_file():
            raise SandboxError(f"no such file: {relative_path!r}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise SandboxError("file too large")
        return path

    def list_source_files(self, target: str) -> list[str]:
        directory = self.target_dir(target)
        files = [
            path
            for path in directory.rglob("*")
            if path.is_file()
            and path.suffix.lower() in ALLOWED_SUFFIXES
            and not IGNORED_DIRS.intersection(path.relative_to(directory).parts)
        ]
        return sorted(self.relative(path) for path in files)

    def relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()
