"""Tool poisoning : instructions malveillantes cachées dans les descriptions d'outils.

Le risque : le LLM client lit la description COMPLÈTE de chaque outil (c'est
son « mode d'emploi »), alors que l'utilisateur n'en voit souvent que le nom.
Une description peut donc donner des ordres au modèle à l'insu de
l'utilisateur : lire un fichier sensible, exfiltrer des données via un
argument, ignorer ses consignes…

Règle TP001 : on cherche plusieurs indicateurs dans chaque description et on
produit UN constat par outil, qui liste tous les indicateurs trouvés (plus il y
en a, plus l'Évaluateur pourra juger le cas grave).
"""

import re

from auditor.models import Finding, RiskCategory
from auditor.rules.context import AuditContext, make_finding

# (nom de l'indicateur, motif) — insensible à la casse.
INDICATORS: list[tuple[str, re.Pattern[str]]] = [
    (
        "hidden instruction tag",
        re.compile(
            r"<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>|\[INST\]|<!--", re.IGNORECASE
        ),
    ),
    (
        "concealment from the user",
        re.compile(
            r"(do not|don't|never)\s+(tell|mention|inform|reveal|show)[^.]{0,40}\buser"
            r"|without\s+(telling|informing|notifying)[^.]{0,20}\buser",
            re.IGNORECASE,
        ),
    ),
    (
        "reference to sensitive data",
        re.compile(
            r"~/\.ssh|id_rsa|id_ed25519|\.env\b|/etc/(passwd|shadow)|private key"
            r"|credentials?\b|api[_ -]?key|password",
            re.IGNORECASE,
        ),
    ),
    (
        "directive to the model",
        re.compile(
            r"before using this tool|ignore (all |any )?(previous|prior|above) instructions"
            r"|you must (first|always)|instead of (using|calling)",
            re.IGNORECASE,
        ),
    ),
]

# Caractères invisibles : zéro-largeur, contrôle bidirectionnel, « tag characters ».
INVISIBLE_CHARS = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")

# Au-delà, une description cache plus facilement des instructions.
MAX_REASONABLE_DESCRIPTION = 1000


def check(context: AuditContext) -> list[Finding]:
    findings = []
    for tool in context.manifest.tools:
        description = tool.description
        indicators: list[str] = []
        evidence: list[str] = []
        for name, pattern in INDICATORS:
            match = pattern.search(description)
            if match:
                indicators.append(name)
                evidence.append(match.group(0))
        if INVISIBLE_CHARS.search(description):
            indicators.append("invisible unicode characters")
        if len(description) > MAX_REASONABLE_DESCRIPTION:
            indicators.append(f"unusually long description ({len(description)} chars)")
        if indicators:
            findings.append(
                make_finding(
                    "TP001",
                    RiskCategory.TOOL_POISONING,
                    f"Possible tool poisoning in the description of '{tool.name}'",
                    evidence="; ".join(f"«{item}»" for item in evidence) or description[:200],
                    tool=tool.name,
                    indicators=indicators,
                )
            )
    return findings
