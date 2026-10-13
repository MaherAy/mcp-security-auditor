# Architecture

Ce document décrit comment les composants de MCP Security Auditor communiquent.
Deux protocoles coexistent, avec des rôles distincts :

- **A2A** (Agent2Agent) relie des **agents** autonomes entre eux : HTTP + JSON-RPC,
  découverte par Agent Card, travail suivi sous forme de **Task** avec cycle de vie.
- **MCP** (Model Context Protocol) relie **un agent à ses outils** : ici en stdio,
  entre le Scanner et le serveur `mcp-inspector`, puis entre l'inspecteur et la cible.

Les choix détaillés sont justifiés dans [DECISIONS.md](DECISIONS.md) (références `Dxx`).

---

## 1. Vue d'ensemble

```mermaid
flowchart LR
    user(["Utilisateur / CLI<br/><code>auditor audit weak_server</code>"])

    subgraph a2a ["Réseau A2A — HTTP JSON-RPC sur localhost"]
        direction TB
        orch["<b>Orchestrateur</b><br/>SDK A2A seul<br/>:10000"]
        scan["<b>Scanner</b><br/>Google ADK<br/>:10001"]
        eval["<b>Évaluateur</b><br/>LangGraph<br/>:10002"]
        rem["<b>Remédiation</b><br/>LangGraph<br/>:10003"]
    end

    subgraph mcp ["MCP — stdio, sous-processus locaux"]
        direction TB
        insp["<b>mcp-inspector</b><br/>serveur MCP (lecture seule)"]
        target["<b>Serveur MCP cible</b><br/>targets/weak_server"]
        files[("Code source<br/>targets/")]
    end

    llm[("API Mistral<br/>(optionnelle)")]

    user ==>|"A2A : Task « audit »"| orch
    orch ==>|"A2A : scan_mcp_server"| scan
    orch ==>|"A2A : rate_findings"| eval
    orch ==>|"A2A : propose_fixes"| rem

    scan -.->|"MCP : list_tools · list_source_files · read_source"| insp
    insp -.->|"MCP : initialize + tools/list uniquement"| target
    insp -->|"lecture confinée"| files

    scan -->|"2e avis descriptions"| llm
    eval -->|"justifications"| llm
    rem -->|"phrase de correctif"| llm

    classDef agent fill:#e8f0fe,stroke:#1a73e8,color:#0b2b5c
    classDef mcpnode fill:#e6f4ea,stroke:#188038,color:#0d3b1e
    classDef ext fill:#fef7e0,stroke:#b06000,color:#4a2800
    class orch,scan,eval,rem agent
    class insp,target,files mcpnode
    class llm,user ext
```

**Lecture du schéma.** Les flèches épaisses (`==>`) sont des échanges **A2A** :
l'orchestrateur délègue chaque étape à un agent choisi par sa compétence, quel
que soit son framework (ADK pour le Scanner, LangGraph pour l'Évaluateur et la
Remédiation). Les flèches pointillées (`-.->`) sont des échanges **MCP** : le
Scanner n'accède jamais au disque, il appelle les outils en lecture seule de
`mcp-inspector`, qui lui-même ne fait qu'**une** chose avec la cible : lui
demander son manifeste (`tools/list`). Aucun outil de la cible n'est appelé.
Les flèches fines vers Mistral sont optionnelles : sans clé (ou avec
`--offline`), tout fonctionne avec des gabarits, et les constats comme les
sévérités restent identiques, car ils viennent de règles déterministes (D2, D13).

| Composant | Framework | Exposé via | Code |
|---|---|---|---|
| Orchestrateur | aucun (SDK A2A) | `AgentExecutor` dédié | [orchestrator/](../src/auditor/agents/orchestrator/) |
| Scanner | Google ADK (`BaseAgent` + sous-agent `LlmAgent`) | `to_a2a` d'ADK | [scanner/](../src/auditor/agents/scanner/) |
| Évaluateur | LangGraph (`StateGraph`) | `LangGraphA2AExecutor` | [evaluator/](../src/auditor/agents/evaluator/) |
| Remédiation | LangGraph (`StateGraph`) | `LangGraphA2AExecutor` | [remediation/](../src/auditor/agents/remediation/) |
| mcp-inspector | SDK MCP (`MCPServer`) | stdio | [mcp_inspector/](../src/auditor/mcp_inspector/) |

---

## 2. Déroulé d'un audit complet

```mermaid
sequenceDiagram
    autonumber
    actor U as CLI (auditor)
    participant O as Orchestrateur<br/>(SDK A2A)
    participant S as Scanner<br/>(ADK)
    participant I as mcp-inspector<br/>(MCP)
    participant T as Cible MCP<br/>(weak_server)
    participant E as Évaluateur<br/>(LangGraph)
    participant R as Remédiation<br/>(LangGraph)

    rect rgb(232, 240, 254)
    Note over U,O: Découverte puis Task de l'utilisateur
    U->>O: GET /.well-known/agent-card.json
    O-->>U: Agent Card (skill audit_mcp_server)
    U->>O: SendStreamingMessage « audit weak_server »
    O-->>U: Task SUBMITTED, puis status WORKING
    end

    rect rgb(243, 243, 243)
    Note over O,R: Découverte des agents par compétence
    O->>S: GET /.well-known/agent-card.json
    O->>E: GET /.well-known/agent-card.json
    O->>R: GET /.well-known/agent-card.json
    O-->>U: status WORKING « discovered: scanner=…, evaluator=…, remediation=… »
    end

    rect rgb(230, 244, 234)
    Note over O,T: Étape 1 — scan (A2A vers ADK, puis MCP)
    O->>S: SendStreamingMessage (texte « weak_server »)
    S-->>O: Task SUBMITTED, puis WORKING
    S->>I: lance l'inspecteur (stdio) + list_tools("weak_server")
    I->>T: lance la cible (stdio) : initialize + tools/list
    T-->>I: manifeste (outils, descriptions, schémas)
    I-->>S: TargetManifest
    S->>I: list_source_files + read_source(…)
    I-->>S: code source (confiné à targets/)
    Note over S: 9 règles déterministes (AST + regex)<br/>+ 2e avis Mistral optionnel
    S-->>O: artefact data ScanResult, puis COMPLETED
    O->>S: GetTask (relecture de la Task finale)
    end

    rect rgb(254, 247, 224)
    Note over O,R: Étapes 2 et 3 — évaluation puis remédiation (A2A vers LangGraph)
    O->>E: SendStreamingMessage (data ScanResult)
    E-->>O: SUBMITTED, puis WORKING « step classify / justify / prioritize »
    E-->>O: artefact data Evaluation, puis COMPLETED
    O->>R: SendStreamingMessage (data Evaluation)
    R-->>O: SUBMITTED, puis WORKING « step select_fixes / tailor »
    R-->>O: artefact data RemediationPlan, puis COMPLETED
    end

    O-->>U: artefacts audit_report (JSON) + audit_report.md, puis COMPLETED
    U->>U: écrit reports/weak_server.report.{md,json}
```

**Lecture du schéma.** Chaque échange A2A suit le même motif : **découverte**
(lecture de l'Agent Card), **message** qui crée une **Task**, mises à jour
d'état en streaming (`SUBMITTED → WORKING → COMPLETED`), **artefact** contenant
le résultat, puis relecture de la Task finale avec `GetTask`. Les états
d'échec existent aussi : une entrée invalide donne `REJECTED`, une panne
`FAILED`, et un échec délégué fait échouer la Task de l'orchestrateur avec un
message qui nomme l'agent fautif (D12, D17). Les messages `WORKING`
intermédiaires (« step classify done »…) sont ce qui permet à la CLI d'afficher
la progression en direct. Les données circulent en **parties `data`** (JSON
structuré) et sont revalidées par Pydantic à chaque réception (D10, D16).

---

## 3. Frontières de confiance

```mermaid
flowchart TB
    subgraph trusted ["Code de l'auditeur (confiance)"]
        rules["Règles + politique de sévérité<br/>(déterministes)"]
        agents["Agents A2A"]
    end
    subgraph untrusted ["Données non fiables"]
        desc["Descriptions d'outils de la cible"]
        code["Code source de la cible"]
        llmout["Réponses du LLM"]
    end
    desc -->|"analysées comme données, jamais exécutées"| rules
    code -->|"lu par l'inspecteur, confiné à targets/"| rules
    llmout -->|"validées par Pydantic,<br/>ne peuvent ni retirer un constat ni changer une sévérité"| agents
```

**Lecture du schéma.** Un auditeur de tool poisoning manipule par définition
des textes écrits pour tromper un LLM. Trois règles en découlent :
1. les descriptions et le code de la cible sont des **données** : seules des
   règles déterministes en tirent des constats ;
2. l'argument `path` des outils de l'inspecteur est traité comme hostile
   (confinement, liste blanche d'extensions, taille maximale, D4) ;
3. le LLM peut **ajouter** un constat (étiqueté `detector="llm"`) ou rédiger du
   texte, mais jamais retirer un constat, changer une sévérité ou fournir le
   code d'un correctif (D6, D13, D14).
