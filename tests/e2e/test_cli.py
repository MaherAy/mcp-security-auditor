"""Phase 5 — la commande du démarrage rapide (`auditor demo`), avec de vrais processus."""

import json

from auditor.cli import main
from tests.a2a.server_helpers import free_port


def test_cli_demo_audits_a_target_with_four_agent_processes(tmp_path, monkeypatch, capsys):
    for agent in ("orchestrator", "scanner", "evaluator", "remediation"):
        monkeypatch.setenv(f"AUDITOR_{agent.upper()}_PORT", str(free_port()))
    monkeypatch.chdir(tmp_path)  # logs et rapports dans un dossier temporaire

    exit_code = main(["demo", "weak_server", "--offline", "--out", "out"])

    output = capsys.readouterr().out
    assert exit_code == 0, output
    assert "overall risk: CRITICAL" in output
    report = json.loads((tmp_path / "out" / "weak_server.report.json").read_text(encoding="utf-8"))
    assert len(report["items"]) == 15
    assert report["justified_by"] == "template"  # --offline : aucun appel LLM


def test_cli_refuses_to_start_when_a_port_is_taken(tmp_path, monkeypatch, capsys):
    import socket

    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        monkeypatch.setenv("AUDITOR_SCANNER_PORT", str(blocker.getsockname()[1]))
        monkeypatch.chdir(tmp_path)
        exit_code = main(["demo", "weak_server", "--offline"])
    assert exit_code == 1
    assert "already in use" in capsys.readouterr().err
