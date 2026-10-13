# Cibles de test

Serveurs MCP **locaux** utilisés uniquement pour tester l'auditeur.

| Dossier | Rôle |
|---|---|
| `weak_server/` | Volontairement vulnérable. Chaque faille est marquée `# VULN[<catégorie>]`. Outils inertes sauf si `WEAK_SERVER_LIVE=1`. **Ne jamais déployer.** |
| `safe_server/` | Témoin sain, pour vérifier l'absence de faux positifs. |

L'inspecteur MCP (`src/auditor/mcp_inspector`) refuse toute cible située hors de ce dossier.
