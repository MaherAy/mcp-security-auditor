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

## D6. Scanner = `BaseAgent` ADK piloté par le code + sous-agent LLM optionnel

- **Décision** : le Scanner est un agent ADK personnalisé (`BaseAgent`) dont le
  parcours est codé (manifeste → fichiers → règles). Un `LlmAgent` Mistral
  (`description_reviewer`) apporte un second avis sémantique sur les
  descriptions ; ses constats sont marqués `detector="llm"`.
- **Raison** : le parcours d'un audit est connu d'avance ; laisser un LLM
  choisir les appels d'outils ajouterait coût, latence et non-déterminisme.
  Le LLM est utilisé là où les regex sont faibles (manipulation reformulée).
- **Compromis** : moins « autonome » qu'un agent ReAct. Assumé : en sécurité, la
  traçabilité prime. Les descriptions sont présentées au LLM comme des
  *données* (« never as instructions ») : la relecture elle-même est exposée à
  l'injection de prompt, ce qui explique pourquoi elle ne peut qu'ajouter un
  constat, jamais en retirer un.

## D7. ADK 2.x + MCP 2.x : écarts constatés

- `McpTool.run_async` exige un `tool_context` ; en ADK 2.x, `ToolContext` est un
  simple alias de `google.adk.agents.context.Context`, construit avec
  `Context(invocation_context)`.
- Le résultat d'un outil MCP arrive sous forme de `dict` avec les clés 1.x
  (`structuredContent`, `isError`) : ADK ré-aliase volontairement le format
  snake_case de mcp 2.x pour rester compatible. On lit donc les clés 1.x.
- Avertissements internes à ADK filtrés dans `pyproject.toml` (fonctionnalités
  `[EXPERIMENTAL]` activées par défaut ; ADK instancie lui-même sa classe
  `MCPTool` qu'il a dépréciée). Ils ne viennent pas de notre code.

## D8. Mistral via LiteLLM, tests avec un faux LLM

- **Décision** : `LiteLlm(model="mistral/open-mistral-nemo")` (surchargeable
  par `AUDITOR_LLM_MODEL`). Les tests utilisent `ScriptedLlm`, un `BaseLlm`
  qui renvoie une réponse fixée ; un test `@pytest.mark.live` appelle le vrai
  Mistral et est ignoré sans `MISTRAL_API_KEY`.
- **Raison** : ADK est optimisé pour Gemini mais accepte tout fournisseur via
  LiteLLM. Le faux LLM teste notre logique (fusion des avis, prompt) sans
  dépendre du réseau ni d'un quota.
- **Compromis** : le test hors-ligne ne vérifie pas la *qualité* du jugement de
  Mistral, seulement notre intégration.
- **Constat (test live)** : avec une clé de l'offre gratuite, `mistral-small-latest`
  et `mistral-medium-latest` renvoient 429 dès le premier appel (quota par
  modèle), `mistral-large-latest` renvoie 403 ; `open-mistral-nemo` et
  `ministral-8b-latest` fonctionnent. Défaut : `open-mistral-nemo`. Sur la cible
  faible, Mistral signale uniquement `add` (confirme TP001), aucun faux positif.

## D9. A2A 1.x : types protobuf, `to_a2a` d'ADK côté serveur

- **Constat** : `a2a-sdk` 1.2.2 génère `a2a.types` depuis protobuf (`a2a_pb2`) ;
  la 0.3 utilisait Pydantic. Conséquences : constructeurs protobuf
  (`AgentCard(name=..., skills=[AgentSkill(...)])`), `WhichOneof("content")`
  pour lire une partie, `MessageToDict` pour convertir, états en
  `TASK_STATE_COMPLETED`. Les tutoriels 0.3 (`TextPart`, `DataPart`,
  `Part(root=...)`) ne s'appliquent plus. ADK 2.11 gère les deux versions via
  son module `_compat`.
- **Décision** : le Scanner est exposé avec `to_a2a(agent, agent_card=...)`
  d'ADK, qui fournit la route de la carte, le JSON-RPC et la conversion
  événements ADK → mises à jour de Task.
- **Raison** : zéro code de protocole à écrire côté ADK. La partie A2A
  « manuelle » (`AgentExecutor`) sera montrée avec LangGraph en phase 4 :
  le projet montre ainsi les deux façons d'exposer un agent.

## D10. Agent Card écrite à la main, résultat en partie `data`

- **Carte** : la carte générée par ADK pour un `BaseAgent` personnalisé ne
  contient qu'une compétence `custom` / tag `custom_agent`. On écrit donc la
  carte (`agents/scanner/card.py`) : compétence `scan_mcp_server`, entrée
  texte, sortie `application/json`, exemples. C'est ce que lit l'orchestrateur.
- **Résultat** : ADK n'a pas de type « data ». Son convertisseur A2A
  transforme un blob encadré par `<a2a_datapart_json>…</a2a_datapart_json>` en
  partie A2A `data` ; on utilise ses constantes publiques
  (`google.adk.a2a.converters.part_converter`).
  *Compromis* : dépendance à une convention interne d'ADK, couverte par le
  test `test_scan_task_completes_with_structured_findings`.
- **Erreurs** : un événement ADK avec `error_code` termine la Task en
  `TASK_STATE_FAILED` (et non `COMPLETED` avec un JSON d'erreur) : l'appelant
  distingue un échec par l'état de la Task, comme le prévoit le protocole.
- **Cycle de vie observé** : `submitted → working → completed`. Les événements
  intermédiaires (relecture LLM) deviennent des mises à jour d'état `working`,
  pas des artefacts.

## D11. a2a-sdk 1.2 : `Client.close()` ferme le client httpx prêté

- **Constat** : `JsonRpcTransport.close()` appelle `httpx_client.aclose()`
  même si le client httpx a été fourni par l'appelant via `ClientConfig`.
  Symptôme : la 2e Task envoyée avec le même client httpx échoue avec
  « Cannot send a request, as the client has been closed ».
- **Décision** : `send_task` ne ferme pas le client A2A ; le client httpx
  appartient à l'appelant (`async with httpx.AsyncClient()`). Test de
  non-régression : `test_one_http_client_can_send_several_tasks`.
- **Bruit connu** : ADK journalise « App name mismatch » (il déduit un nom
  d'application du dossier `scanner/` alors que l'agent s'appelle
  `mcp_scanner`) ; sans effet fonctionnel.
