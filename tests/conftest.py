"""Fixtures partagées."""

import asyncio

import pytest

from auditor.mcp_inspector.server import fetch_manifest, sandbox
from auditor.models import ScanResult
from auditor.rules import AuditContext, run_all_rules


@pytest.fixture
def anyio_backend():
    return "asyncio"


def load_target_context(target: str) -> AuditContext:
    """Manifeste réel (via tools/list) + sources, comme les verra le Scanner."""
    manifest = asyncio.run(fetch_manifest(target))
    sources = {
        path: sandbox.source_file(path).read_text(encoding="utf-8")
        for path in sandbox.list_source_files(target)
    }
    return AuditContext(manifest=manifest, sources=sources)


@pytest.fixture(scope="session")
def weak_context() -> AuditContext:
    return load_target_context("weak_server")


@pytest.fixture(scope="session")
def safe_context() -> AuditContext:
    return load_target_context("safe_server")


@pytest.fixture(scope="session")
def weak_scan(weak_context) -> ScanResult:
    """ScanResult de weak_server, construit sans passer par l'agent Scanner."""
    return ScanResult(
        target="weak_server",
        manifest=weak_context.manifest,
        files_scanned=list(weak_context.sources),
        findings=run_all_rules(weak_context),
    )
