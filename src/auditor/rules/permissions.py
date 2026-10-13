"""Permissions excessives : l'outil peut faire beaucoup plus que nécessaire.

- EP001 (code)      : exécution de commandes shell ou de code arbitraire.
- EP002 (code)      : accès disque à un chemin choisi par l'appelant, sans confinement.
- EP003 (manifeste) : outil sensible (nom/description) qui ne déclare aucune
                      annotation MCP (`destructive_hint`, `read_only_hint`) :
                      le client ne peut pas demander de confirmation à l'utilisateur.
"""

import re

from auditor.models import Finding, RiskCategory
from auditor.rules import code_analysis as ca
from auditor.rules.context import AuditContext, make_finding

SENSITIVE_TOOL_NAME = re.compile(
    r"(^|_)(run|exec|execute|shell|command|cmd|delete|remove|kill|eval|write)(_|$)", re.IGNORECASE
)
BROAD_SCOPE_DESCRIPTION = re.compile(
    r"\bany (file|command|path|url)|arbitrary|entire (disk|file ?system)", re.IGNORECASE
)


def _check_code(context: AuditContext) -> list[Finding]:
    findings = []
    for path, code in context.python_sources.items():
        tree = ca.parse(code)
        if tree is None:
            continue
        for site in ca.iter_call_sites(tree):
            line = site.call.lineno
            tool_name = site.tool.name if site.tool else None
            name = site.qualified_name

            is_shell = name.startswith("subprocess.") and ca.call_has_true_keyword(site.call, "shell")
            if is_shell or name in {"os.system", "os.popen", "eval", "exec"}:
                findings.append(
                    make_finding(
                        "EP001",
                        RiskCategory.EXCESSIVE_PERMISSIONS,
                        f"Arbitrary command/code execution via {name}()",
                        ca.source_line(code, line),
                        tool=tool_name,
                        file=path,
                        line=line,
                        indicators=["shell=True"] if is_shell else [name],
                    )
                )

            if name in ca.FILE_SINKS and site.tool and not ca.has_path_containment_check(site.tool):
                params = ca.params_used_directly(site.call, site.tool)
                if params:
                    findings.append(
                        make_finding(
                            "EP002",
                            RiskCategory.EXCESSIVE_PERMISSIONS,
                            f"Unrestricted filesystem access: caller-chosen path passed to {name}()",
                            ca.source_line(code, line),
                            tool=tool_name,
                            file=path,
                            line=line,
                            indicators=[f"parameter '{param}'" for param in params],
                        )
                    )
    return findings


def _check_manifest(context: AuditContext) -> list[Finding]:
    findings = []
    for tool in context.manifest.tools:
        annotations = tool.annotations or {}
        declares_risk = "destructive_hint" in annotations or "read_only_hint" in annotations
        reasons = []
        if SENSITIVE_TOOL_NAME.search(tool.name):
            reasons.append(f"sensitive tool name '{tool.name}'")
        broad = BROAD_SCOPE_DESCRIPTION.search(tool.description)
        if broad:
            reasons.append(f"broad scope in description «{broad.group(0)}»")
        if reasons and not declares_risk:
            findings.append(
                make_finding(
                    "EP003",
                    RiskCategory.EXCESSIVE_PERMISSIONS,
                    f"Sensitive tool '{tool.name}' declares no MCP safety annotations",
                    f"annotations={tool.annotations}",
                    tool=tool.name,
                    indicators=reasons,
                )
            )
    return findings


def check(context: AuditContext) -> list[Finding]:
    return _check_code(context) + _check_manifest(context)
