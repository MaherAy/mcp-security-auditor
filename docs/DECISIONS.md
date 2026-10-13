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
