"""Absence de validation des entrées : les arguments d'outils sont des données
non fiables (elles viennent d'un LLM, lui-même influençable par du contenu
externe). Elles doivent être contraintes avant usage.

- IV001 (manifeste) : paramètre texte sans aucune contrainte de schéma JSON
                      (pattern, enum, maxLength, format, const).
- IV002 (code)      : requête SQL construite par formatage de chaîne (injection SQL).
- IV003 (code)      : paramètre transmis tel quel à une fonction dangereuse
                      (shell, eval, fichier) sans contrôle préalable.
"""

from auditor.models import Finding, RiskCategory
from auditor.rules import code_analysis as ca
from auditor.rules.context import AuditContext, make_finding

STRING_CONSTRAINTS = {"pattern", "enum", "maxLength", "format", "const"}


def _check_manifest(context: AuditContext) -> list[Finding]:
    findings = []
    for tool in context.manifest.tools:
        properties = tool.input_schema.get("properties", {})
        unconstrained = [
            name
            for name, schema in properties.items()
            if schema.get("type") == "string" and not STRING_CONSTRAINTS.intersection(schema)
        ]
        if unconstrained:
            findings.append(
                make_finding(
                    "IV001",
                    RiskCategory.MISSING_INPUT_VALIDATION,
                    f"Unconstrained string parameters in '{tool.name}'",
                    ", ".join(f"{name}: {properties[name]}" for name in unconstrained),
                    tool=tool.name,
                    indicators=[f"parameter '{name}'" for name in unconstrained],
                )
            )
    return findings


def _check_code(context: AuditContext) -> list[Finding]:
    findings = []
    for path, code in context.python_sources.items():
        tree = ca.parse(code)
        if tree is None:
            continue
        for site in ca.iter_call_sites(tree):
            line = site.call.lineno
            tool_name = site.tool.name if site.tool else None
            method = site.qualified_name.split(".")[-1]

            if (
                method in ca.SQL_EXECUTE_METHODS
                and site.call.args
                and ca.is_formatted_string(site.call.args[0])
            ):
                findings.append(
                    make_finding(
                        "IV002",
                        RiskCategory.MISSING_INPUT_VALIDATION,
                        "SQL query built with string formatting (SQL injection)",
                        ca.source_line(code, line),
                        tool=tool_name,
                        file=path,
                        line=line,
                        indicators=["formatted SQL string"],
                    )
                )

            dangerous = site.qualified_name in ca.EXEC_SINKS or site.qualified_name in ca.FILE_SINKS
            if dangerous and site.tool:
                is_file_sink = site.qualified_name in ca.FILE_SINKS
                if is_file_sink and ca.has_path_containment_check(site.tool):
                    continue
                params = ca.params_used_directly(site.call, site.tool)
                if params:
                    findings.append(
                        make_finding(
                            "IV003",
                            RiskCategory.MISSING_INPUT_VALIDATION,
                            f"Unvalidated tool parameter reaches {site.qualified_name}()",
                            ca.source_line(code, line),
                            tool=tool_name,
                            file=path,
                            line=line,
                            indicators=[f"parameter '{param}'" for param in params],
                        )
                    )
    return findings


def check(context: AuditContext) -> list[Finding]:
    return _check_manifest(context) + _check_code(context)
