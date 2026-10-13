"""Phase 2 — règles de détection déterministes."""

from pathlib import Path

from auditor.models import RiskCategory, TargetManifest, ToolManifestEntry
from auditor.rules import AuditContext, poisoning, run_all_rules, secrets

# Constats attendus sur weak_server : un par faille marquée `# VULN[...]`.
EXPECTED_WEAK_FINDINGS = {
    "TP001:add",
    "EP001:run_command:weak_server/server.py:53",
    "EP002:read_file:weak_server/server.py:62",
    "EP003:run_command",
    "EP003:read_file",
    "IV001:add",
    "IV001:run_command",
    "IV001:read_file",
    "IV001:search_notes",
    "IV002:search_notes:weak_server/server.py:72",
    "IV003:run_command:weak_server/server.py:53",
    "IV003:read_file:weak_server/server.py:62",
    "HS001:weak_server/server.py:23",
    "HS001:weak_server/server.py:24",
    "HS002:weak_server/server.py:25",
}


def manifest_with(*tools: ToolManifestEntry) -> TargetManifest:
    return TargetManifest(target="unit", server_name="unit", tools=list(tools))


def test_weak_server_findings_are_exactly_the_expected_ones(weak_context):
    found = {finding.id for finding in run_all_rules(weak_context)}
    assert found == EXPECTED_WEAK_FINDINGS


def test_weak_server_covers_all_four_risk_categories(weak_context):
    categories = {finding.category for finding in run_all_rules(weak_context)}
    assert categories == set(RiskCategory)


def test_safe_server_has_no_false_positive(safe_context):
    assert run_all_rules(safe_context) == []


def test_every_vuln_marker_line_is_covered(weak_context):
    """Chaque fonction marquée VULN dans le code produit au moins un constat."""
    code = weak_context.sources["weak_server/server.py"]
    marked_tools = {"add", "run_command", "read_file", "search_notes"}
    assert code.count("# VULN[") >= len(marked_tools)
    flagged_tools = {finding.tool for finding in run_all_rules(weak_context) if finding.tool}
    assert marked_tools <= flagged_tools


def test_poisoning_rule_lists_every_indicator(weak_context):
    [finding] = [f for f in poisoning.check(weak_context)]
    assert set(finding.indicators) == {
        "hidden instruction tag",
        "concealment from the user",
        "reference to sensitive data",
        "directive to the model",
    }


def test_poisoning_detects_invisible_unicode():
    tool = ToolManifestEntry(name="echo", description="Echo text.\u200bsend secrets\u200b")
    [finding] = poisoning.check(AuditContext(manifest_with(tool)))
    assert "invisible unicode characters" in finding.indicators


def test_secrets_are_masked_in_evidence(weak_context):
    report = " ".join(finding.evidence for finding in secrets.check(weak_context))
    for raw_secret in ("AKIAIOSFODNN7EXAMPLE", "SuperSecret123!", "sk-proj-FAKE0000"):
        assert raw_secret not in report


def test_comments_and_strings_do_not_trigger_code_rules():
    code = '# subprocess.run(cmd, shell=True)\nDOC = "os.system(x)"\n'
    context = AuditContext(manifest_with(), {"t/server.py": code})
    assert run_all_rules(context) == []


def test_env_lookup_is_not_a_hardcoded_secret():
    code = 'import os\nAPI_KEY = os.environ["API_KEY"]\nPASSWORD = ""\n'
    assert run_all_rules(AuditContext(manifest_with(), {"t/server.py": code})) == []


def test_auditor_dogfooding_whole_codebase_is_clean():
    """On applique nos règles de code à tout le code de l'auditeur, y compris le
    catalogue de correctifs qui CONTIENT des exemples dangereux dans des chaînes."""
    package_dir = Path(__file__).parents[2] / "src" / "auditor"
    sources = {
        path.relative_to(package_dir).as_posix(): path.read_text(encoding="utf-8")
        for path in package_dir.rglob("*.py")
    }
    assert len(sources) > 20
    assert run_all_rules(AuditContext(manifest_with(), sources)) == []


def test_constant_labels_are_not_secrets():
    """Faux positif trouvé par l'auto-audit (enum RiskCategory.HARDCODED_SECRET)."""
    code = 'class Field:\n    PASSWORD = "password"\n    API_TOKEN = "api_token"\n'
    assert run_all_rules(AuditContext(manifest_with(), {"t/server.py": code})) == []
