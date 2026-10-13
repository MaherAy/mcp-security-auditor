"""Phase 4 — politique de sévérité déterministe."""

from auditor.agents.evaluator.policy import BASE_POLICY, rate_all
from auditor.models import Finding, RiskCategory, Severity

EXPECTED_SEVERITIES = {
    "EP001:run_command:weak_server/server.py:53": Severity.CRITICAL,
    "TP001:add": Severity.CRITICAL,  # escaladé : données sensibles + dissimulation
    "IV002:search_notes:weak_server/server.py:72": Severity.HIGH,
    "EP002:read_file:weak_server/server.py:62": Severity.HIGH,
    "IV003:read_file:weak_server/server.py:62": Severity.HIGH,
    "IV003:run_command:weak_server/server.py:53": Severity.HIGH,
    "HS001:weak_server/server.py:23": Severity.HIGH,
    "HS001:weak_server/server.py:24": Severity.HIGH,
    "HS002:weak_server/server.py:25": Severity.MEDIUM,
    "EP003:read_file": Severity.MEDIUM,
    "EP003:run_command": Severity.MEDIUM,
    "IV001:read_file": Severity.MEDIUM,  # escaladé : alimente open()
    "IV001:run_command": Severity.MEDIUM,  # escaladé : alimente subprocess
    "IV001:search_notes": Severity.MEDIUM,  # escaladé : alimente une requête SQL
    "IV001:add": Severity.LOW,  # reste de la défense en profondeur
}


def test_weak_server_severities(weak_scan):
    rated = {finding.id: finding.severity for finding in rate_all(weak_scan.findings)}
    assert rated == EXPECTED_SEVERITIES


def test_rated_findings_are_sorted_by_priority(weak_scan):
    rated = rate_all(weak_scan.findings)
    keys = [(finding.severity.rank, -finding.score) for finding in rated]
    assert keys == sorted(keys)
    assert rated[0].id == "EP001:run_command:weak_server/server.py:53"


def test_every_rule_has_a_policy_entry():
    rule_ids = {"TP001", "LLM-TP", "EP001", "EP002", "EP003", "IV001", "IV002", "IV003", "HS001", "HS002"}
    assert rule_ids == set(BASE_POLICY)


def test_evidence_is_preserved_and_rationale_explains_escalation(weak_scan):
    rated = {finding.id: finding for finding in rate_all(weak_scan.findings)}
    poisoning = rated["TP001:add"]
    original = next(f for f in weak_scan.findings if f.id == "TP001:add")
    assert poisoning.evidence == original.evidence
    assert "Escalated" in poisoning.rationale


def test_llm_confirmation_raises_score_but_not_severity():
    base = Finding(
        id="TP001:x",
        rule_id="TP001",
        category=RiskCategory.TOOL_POISONING,
        title="t",
        evidence="e",
        indicators=["hidden instruction tag"],
    )
    confirmed = base.model_copy(update={"indicators": [*base.indicators, "confirmed by LLM review: x"]})
    [plain], [boosted] = rate_all([base]), rate_all([confirmed])
    assert plain.severity == boosted.severity == Severity.HIGH
    assert boosted.score > plain.score
