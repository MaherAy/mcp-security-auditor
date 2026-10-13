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

## D12. Évaluateur et Remédiation en LangGraph, exposés par un `AgentExecutor` écrit à la main

- **Décision** : deux graphes LangGraph (`StateGraph` + état `TypedDict`) et
  un adaptateur générique `LangGraphA2AExecutor` (`src/auditor/a2a_langgraph.py`)
  monté avec `DefaultRequestHandler`, `create_agent_card_routes` et
  `create_jsonrpc_routes` du SDK A2A.
- **Raison** : LangGraph ne fournit pas de serveur A2A. Écrire l'exécuteur
  montre le protocole « à nu » : création de la Task (`SUBMITTED`),
  `start_work`, un statut `WORKING` par nœud terminé (via
  `graph.astream(stream_mode="updates")`), artefact `data`, état terminal.
  Le même adaptateur sert aux deux agents (aucune duplication).
- **États terminaux distingués** : entrée invalide → `REJECTED` (l'agent refuse
  la demande) ; exception pendant le graphe → `FAILED` (l'agent a échoué).
- **Compromis** : `InMemoryTaskStore` : les Tasks disparaissent au
  redémarrage (suffisant pour un audit local ; `DatabaseTaskStore` existe).

## D13. La sévérité est décidée par une politique déterministe, pas par le LLM

- **Décision** : `policy.py` = table règle → (sévérité, score, raison) +
  3 ajustements explicites (poisoning d'exfiltration → critical ; confirmation
  LLM → +0,3 au score ; IV001 alimentant IV002/IV003 → +1 cran). Le LLM
  (Mistral via `langchain-mistralai`, sortie structurée par tool calling) rédige
  seulement les justifications, en un seul appel pour tous les constats.
- **Garde-fous** : identifiants inventés par le LLM ignorés ; constat oublié →
  justification gabarit ; la preuve d'origine est conservée telle quelle.
- **Compromis** : la politique ne connaît pas le contexte métier (un outil
  shell peut être légitime dans un serveur d'administration). Elle est lisible et
  modifiable en un endroit, ce qui rend ce compromis discutable et ajustable.

## D14. Correctifs : code relu dans un catalogue, LLM limité à une phrase

- **Décision** : le catalogue (`remediation/catalog.py`) contient, par règle,
  correctif, étapes, exemple de code et références CWE/OWASP. Le LLM réécrit
  uniquement la phrase `fix` pour le cas précis ; `baseline_fix` conserve
  toujours la version relue.
- **Constat (test live)** : malgré la consigne, Mistral Nemo a écrit du code
  dans une phrase (IV002) et a **affaibli** le correctif EP001 (« retirer
  `shell=True` et valider » au lieu de « supprimer l'exécution arbitraire »).
  D'où `baseline_fix` : le lecteur voit toujours le correctif de référence.

## D15. Une seule variable de modèle pour deux frameworks

- `AUDITOR_LLM_MODEL` est au format LiteLLM (`mistral/open-mistral-nemo`) pour
  ADK ; côté LangChain on retire le préfixe (`mistral_model_name()`).

## D16. Les nombres deviennent des flottants dans une partie `data` A2A

- **Constat** : en A2A 1.x, une partie `data` est un `google.protobuf.Value`
  (Struct) ; comme en JSON-Schema protobuf, tout nombre est un `double` :
  `line: 53` arrive `53.0`, `counts: {"high": 6}` arrive `6.0`.
- **Décision** : chaque agent **revalide** son entrée avec le modèle Pydantic
  attendu (`input_model` dans l'exécuteur, `model_validate` dans
  l'orchestrateur) ; Pydantic reconvertit `53.0` en `int`. Test :
  `test_cross_framework_chain_adk_to_langgraph`.
- **Leçon** : un contrat d'interface entre agents doit être validé à la
  réception, jamais supposé.

## D17. Orchestrateur en SDK A2A seul, découverte par compétence

- **Décision** : l'orchestrateur n'utilise aucun framework d'agent : un
  `AgentExecutor` + du Python. Il ne connaît que des URL ; il lit chaque Agent
  Card et choisit l'agent par **identifiant de compétence**
  (`scan_mcp_server`, `rate_findings`, `propose_fixes`).
- **Raison** : (1) son travail est un enchaînement fixe, sans besoin de LLM ;
  (2) le projet montre ainsi trois façons d'exposer un agent en A2A (ADK
  `to_a2a`, LangGraph + exécuteur générique, SDK seul) ; (3) remplacer un agent
  par un autre offrant la même compétence ne change pas l'orchestrateur.
- **Compromis** : demande en texte libre interprétée simplement (dernier mot
  ressemblant à un nom de cible) ; un LLM pourrait comprendre des demandes plus
  riches, mais le Scanner revalide de toute façon le nom.
- **Propagation des erreurs** : une Task déléguée en échec fait échouer la
  Task de l'orchestrateur avec un message qui nomme le rôle et l'agent ; une
  compétence introuvable est signalée avant toute délégation.

## D18. Rapport : deux artefacts, chaque étape revalidée

- Artefact `audit_report` (partie `data`, `application/json`) pour les
  machines ; artefact `audit_report.md` (partie texte, `text/markdown`) pour
  les humains. La CLI écrit les deux dans `reports/`.
- Le rapport contient la trace A2A de chaque délégation (agent, framework lu
  dans la carte, id de Task, états observés).

## D19. Un processus par agent ; refus de démarrer sur un port occupé

- **Décision** : `auditor up/demo` lance chaque agent dans son propre processus
  (services réellement indépendants, journaux séparés dans `reports/logs/`).
- **Incident vécu** : un prototype de la phase 3 occupait encore le port 10001.
  Le nouveau Scanner n'a pas pu démarrer, mais la vérification « la carte
  répond » a réussi… grâce à l'ancien processus, qui servait une carte sans la
  compétence `scan_mcp_server`. L'orchestrateur a alors échoué (proprement).
- **Correction** : la CLI refuse de démarrer si un port est déjà pris.
- **Leçon A2A** : la découverte fait confiance à ce qui répond à une URL. En
  production il faudrait authentifier les agents (TLS, schémas de sécurité de
  la carte) et vérifier les signatures de carte (`AgentCard.signatures`,
  `signature_verifier` du résolveur, présents dans a2a-sdk 1.x).

## D20. L'auto-audit trouve de vrais faux positifs

- **Décision** : un test applique les règles de code à tout `src/auditor`.
- **Résultat** : deux constats. (1) HS002 sur `HARDCODED_SECRET =
  "hardcoded_secret"` (membre d'enum) : vrai défaut de la règle, corrigé (une
  constante dont la valeur est son propre nom est une étiquette) + test.
  (2) HS001 sur un exemple de clé AWS dans une docstring : comportement voulu
  (les scanners de secrets signalent aussi la documentation) ; c'est la
  docstring qui a été changée.

## D21. Noms des méthodes JSON-RPC : A2A 1.0 ≠ 0.3

- **Constat** : en A2A 1.0 (a2a-sdk 1.x), les méthodes JSON-RPC sont
  `SendMessage`, `SendStreamingMessage`, `GetTask`, `CancelTask`… Les noms
  `message/send`, `message/stream`, `tasks/get` sont ceux de la 0.3 (encore
  acceptés par le serveur si `enable_v0_3_compat=True`, ce que fait ADK).
- **Correction** : nos commentaires et diagrammes utilisaient les noms 0.3,
  écrits de mémoire ; ils ont été alignés sur le code du SDK installé.

**Ajout (vérification sur clone propre, phase 6)** : le démarrage rapide
échouait au premier lancement : la compilation du bytecode d'ADK/LangChain
consommait presque tout le délai de 60 s partagé entre les quatre agents. Les
agents démarrent désormais en parallèle, avec un délai de 180 s
(`AUDITOR_STARTUP_TIMEOUT`). Mesure sur clone neuf : ~60 s de bout en bout.
