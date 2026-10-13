# Décisions techniques

Chaque entrée : **contexte → décision → raison → compromis**.

---

## D1. Gestion du projet avec `uv` et layout `src/`

- **Décision** : paquet Python `auditor` sous `src/`, dépendances gérées par `uv`.
- **Raison** : `uv` est rapide et produit un lockfile reproductible (`uv.lock`) ;
  le layout `src/` évite d'importer par accident le code non installé.
- **Compromis** : un outil de plus à installer pour qui ne connaît que `pip`.

## D2. Détection déterministe, LLM en complément

- **Décision** : les constats sont produits par des règles déterministes
  (regex / AST) ; le LLM (Mistral) ne sert qu'à rédiger justifications et
  correctifs. Un mode hors-ligne remplace le LLM par des gabarits.
- **Raison** : un audit de sécurité doit être reproductible et testable ; un LLM
  seul peut halluciner ou rater un constat. Les tests tournent sans clé d'API.
- **Compromis** : les règles ne détectent que les motifs connus ; le LLM
  n'élargit pas la couverture de détection (évolution possible : « second avis »
  LLM marqué comme tel dans le rapport).

## D3. SDK MCP 2.x : `MCPServer` (ex-`FastMCP`) et `Client` unifié

- **Constat** : la version installée est `mcp` 2.3.0. `mcp.server.fastmcp`
  n'existe plus (le module lève une erreur qui pointe vers le guide de
  migration) : la classe s'appelle désormais `mcp.server.mcpserver.MCPServer`.
  Les champs des types sont en snake_case (`input_schema`, `read_only_hint`).
- **Décision** : on suit l'API v2 telle qu'elle est, sans épingler `mcp<2`.
  Côté client, `mcp.Client` accepte une instance `MCPServer` (connexion en
  mémoire, idéale pour les tests unitaires) ou des `StdioServerParameters`
  (sous-processus, utilisé en conditions réelles et en test de bout en bout).
- **Compromis** : la plupart des tutoriels en ligne utilisent encore
  `FastMCP` ; le code de ce dépôt ne s'y copie-colle pas tel quel.
- **À savoir** : une sortie d'outil qui n'est pas un objet (ex. une liste) est
  enveloppée dans `{"result": [...]}` dans `structured_content`.

## D4. Inspecteur MCP en transport stdio, confiné à `targets/`

- **Décision** : `mcp-inspector` tourne en stdio (lancé comme sous-processus
  par l'agent) et n'accède qu'au dossier `targets/` : liste blanche
  d'extensions, taille max 256 Ko, noms de cibles sans séparateur, résolution
  des `..` et liens avant contrôle (`Path.resolve()` + `is_relative_to`).
- **Raison** : stdio n'ouvre aucun port réseau. L'argument `path` d'un outil
  MCP vient d'un LLM, donc c'est une entrée non fiable : on s'applique à
  soi-même les règles qu'on audite chez les autres (« eat your own dog food »).
  Les outils déclarent `read_only_hint=True`.
- **Compromis** : on ne peut pas auditer un serveur ailleurs sur le disque
  sans le copier dans `targets/` (ou définir `AUDITOR_TARGETS_ROOT`) : c'est
  voulu, puisque le périmètre est limité à nos propres serveurs de test.

## D5. Manifeste obtenu via `tools/list`, jamais via `tools/call`

- **Décision** : pour lire le manifeste, l'inspecteur démarre la cible et
  envoie uniquement `initialize` puis `tools/list`.
- **Raison** : le manifeste réel (descriptions, schémas générés à partir des
  annotations de type) est ce que voit le LLM client ; le reconstruire par
  analyse du code serait fragile. C'est l'approche des scanners MCP existants.
- **Compromis** : le code d'initialisation de la cible s'exécute. Atténuations :
  cibles locales uniquement, environnement minimal du SDK (nos clés d'API ne
  sont pas transmises au sous-processus), délai maximal de 20 s, aucun appel
  d'outil, et outils dangereux de la cible inertes par défaut.
- **Ajout** : un troisième outil `list_source_files(target)` complète
  `list_tools` et `read_source`, sinon l'agent devrait deviner les chemins.
