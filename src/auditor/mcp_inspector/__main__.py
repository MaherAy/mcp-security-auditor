"""`python -m auditor.mcp_inspector` : lance l'inspecteur en transport stdio.

stdio = le client (l'agent) lance l'inspecteur comme sous-processus local.
Pas de port réseau ouvert : c'est le transport le plus sûr pour un outil local.
"""

from auditor.mcp_inspector.server import inspector

if __name__ == "__main__":
    inspector.run(transport="stdio")
