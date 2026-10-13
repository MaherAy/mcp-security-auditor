"""Rendu du rapport d'audit : JSON (machines) et Markdown (humains)."""

import json
from pathlib import Path

from auditor.models import AuditReport, ReportItem, Severity

SEVERITY_LABEL = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
}


def _location(item: ReportItem) -> str:
    finding = item.finding
    parts = []
    if finding.tool:
        parts.append(f"tool `{finding.tool}`")
    if finding.file:
        parts.append(f"`{finding.file}:{finding.line}`" if finding.line else f"`{finding.file}`")
    return ", ".join(parts) or "—"


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: AuditReport) -> str:
    lines = [
        f"# MCP security audit — `{report.target}`",
        "",
        (
            f"- **Server**: `{report.server_name}` ({report.tools_count} tools, "
            f"{len(report.files_scanned)} source file(s) scanned)"
        ),
        f"- **Overall risk**: **{str(report.overall_risk).upper()}**",
        f"- **Generated**: {report.generated_at}",
        f"- **Justifications**: {report.justified_by} · **Fix wording**: {report.tailored_by}",
        "- **Scope**: static audit (manifest via `tools/list` + source code); no target tool was called.",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {SEVERITY_LABEL[severity]} | {report.counts.get(severity, 0)} |" for severity in Severity],
        "",
    ]

    if report.items:
        lines += [
            "| # | Severity | Finding | Location |",
            "|---:|---|---|---|",
            *[
                f"| {index} | {SEVERITY_LABEL[item.finding.severity]} | {_md_cell(item.finding.title)} "
                f"| {_md_cell(_location(item))} |"
                for index, item in enumerate(report.items, start=1)
            ],
            "",
            "## Findings and fixes",
            "",
        ]
    else:
        lines += ["No finding: the rules detected none of the audited risk patterns.", ""]

    for index, item in enumerate(report.items, start=1):
        finding, fix = item.finding, item.remediation
        detector = " · *detected by LLM second opinion*" if finding.detector == "llm" else ""
        lines += [
            f"### {index}. {SEVERITY_LABEL[finding.severity]} — {finding.title}",
            "",
            f"`{finding.rule_id}` · {finding.category.value} · score {finding.score}/10 · {_location(item)}{detector}",
            "",
            f"**Evidence**: `{_md_cell(finding.evidence)}`",
            "",
        ]
        if finding.indicators:
            lines += [f"**Indicators**: {', '.join(finding.indicators)}", ""]
        lines += [
            f"**Why it matters**: {finding.justification}",
            "",
            f"**Severity rationale**: {finding.rationale}",
            "",
        ]
        if fix:
            lines += [f"**Fix**: {fix.fix}", ""]
            if fix.fix != fix.baseline_fix:
                lines += [f"**Reviewed baseline fix**: {fix.baseline_fix}", ""]
            lines += [*[f"1. {step}" for step in fix.steps], ""]
            if fix.code_example:
                lines += ["```python", fix.code_example, "```", ""]
            if fix.references:
                lines += ["References: " + " · ".join(f"<{ref}>" for ref in fix.references), ""]

    lines += [
        "## Agents involved (A2A)",
        "",
        "| Role | Agent | Framework | Task | Lifecycle |",
        "|---|---|---|---|---|",
        *[
            f"| {run.role} | `{run.agent_name}` | {run.framework} | `{run.task_id[:8]}` | {' → '.join(run.states)} |"
            for run in report.agents
        ],
        "",
    ]
    return "\n".join(lines)


def write_reports(report: AuditReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{report.target}.report.json"
    markdown_path = output_dir / f"{report.target}.report.md"
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path
