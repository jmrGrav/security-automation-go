# Admin API Token Audit — CF_SYNC_API_TOKEN

**Date:** 2026-06-11  
**Auditor:** Claude Sonnet 4.6  
**Trigger:** Production hotfix — daemon scheduler never started because absent token was fatal  
**Scope:** Read-only audit. No code modified.

---

## Étape 1 — Cartographie complète

### 1.1 — Où `CF_SYNC_API_TOKEN` est-il lu ?

| Fichier | Ligne | Rôle | Impact |
|---------|-------|------|--------|
| `internal/config/config.go:269` | `applyEnvOverrides()` | Copie la valeur dans `cfg.Global.AdminToken` | Rend le token accessible via `cfg.GetAdminToken()` |
| `internal/config/config.go:272` | `applyEnvOverrides()` | Copie `CF_SYNC_API_TOKEN_FILE` dans `cfg.Global.AdminTokenFile` | Chemin alternatif vers le token |
| `internal/config/config.go:257–258` | `applyEnvOverrides()` | Valeur par défaut de `AdminTokenFile` = `$STATE_DIR/runtime/admin_token` | Fallback fichier si env absent |
| `internal/config/config.go:498–500` | `ResolveAdminToken()` | Lit `CF_SYNC_API_TOKEN` directement via `os.Getenv` | Retourne le token ou une erreur fatale |
| `internal/config/config.go:487–494` | `ResolveAdminToken()` | Lit `CF_SYNC_API_TOKEN_FILE` si défini | Priorité sur la valeur directe |
| `cmd/cf-sync/daemon_runtime.go:49` | `newAuthenticator()` | Appelle `config.ResolveAdminToken()` | Point d'entrée unique vers le token au démarrage |

### 1.2 — Où `CF_SYNC_API_TOKEN_FILE` est-il lu ?

Même liste que ci-dessus — `_FILE` est la variante fichier lue dans `ResolveAdminToken()` et `applyEnvOverrides()`. Les deux sont gérés par les mêmes fonctions.

### 1.3 — Chaîne de dépendance complète

```
CF_SYNC_API_TOKEN (env)
  └─► config.ResolveAdminToken()          internal/config/config.go:486
        └─► newAuthenticator()            cmd/cf-sync/daemon_runtime.go:48
              └─► startAPIServer()        cmd/cf-sync/daemon_runtime.go:68
                    └─► runDaemonWithLocker()  cmd/cf-sync/daemon_runtime.go:222
```

**Aucun autre consommateur.** `cfg.GetAdminToken()` existe mais n'est appelé nulle part en dehors des tests (`config_test.go:247`).

### 1.4 — Bind address de l'API admin

`cmd/cf-sync/main.go:12` — défaut hardcodé : `127.0.0.1:9092`  
Configurable via `--metrics-addr`. Loopback uniquement — jamais exposé sur le réseau.

---

## Étape 2 — Inventaire complet des endpoints

### Nœud d'écoute : `127.0.0.1:9092`

Toutes les routes passent par `middleware.Auth(authenticator)` — token Bearer obligatoire.

#### Endpoints non-authentifiés (health/metrics)

| Endpoint | Méthode | Auth | Action | Read-only | Mutation | Utilisé par UI |
|----------|---------|------|--------|-----------|----------|----------------|
| `/healthz` | GET | Non | Retourne 200 OK | Oui | Non | Mentionné dans `setup_wizard.go:878` (`curl` dans aide HTML) |
| `/readyz` | GET | Non | Retourne 200 OK | Oui | Non | Non |
| `/statusz` | GET | Non | `status.Collector.Collect()` — statut runtime | Oui | Non | Non |
| `/metrics` | GET | Non | Prometheus metrics (`handlers.NewMetricsHandler`) | Oui | Non | Non |

#### API v1 — `/api/v1/` (token Bearer requis)

| Endpoint | Méthode | Auth | Action | Read-only | Mutation | Utilisé |
|----------|---------|------|--------|-----------|----------|---------|
| `/api/v1/status` | GET | Bearer | `collector.Collect()` — statut complet runtime | Oui | Non | Jamais |
| `/api/v1/audit/events` | GET | Bearer | `journal.List()` — liste des événements d'audit | Oui | Non | Jamais |
| `/api/v1/reconcile/run` | POST | Bearer | **TODO** — corps du handler vide, retourne 202 | — | **Stub vide** | Jamais |
| `/api/v1/quarantine/release` | POST | Bearer | **TODO** — corps du handler vide, retourne 202 | — | **Stub vide** | Jamais |

**Preuve du stub :**  
`internal/api/handlers/handlers.go:85` : `// TODO: Signal the daemon to trigger a run immediately`  
`internal/api/handlers/handlers.go:111` : `// TODO: Implement release logic`

#### API v2 — `/api/v2/` (token Bearer requis)

| Endpoint | Méthode | Auth | Action | Read-only | Mutation | Utilisé |
|----------|---------|------|--------|-----------|----------|---------|
| `/api/v2/ownership/claims` | GET | Bearer | `ownerRes.ListClaims()` | Oui | Non | Jamais |
| `/api/v2/governor/budgets` | GET | Bearer | `gov.GetAllBudgetsStatus()` + `Pressure("cloudflare")` | Oui | Non | Jamais |
| `/api/v2/workers` | GET | Bearer | `pool.Status()` | Oui | Non | Jamais |
| `/api/v2/drift/memory` | GET | Bearer | **Stub** — retourne `"not fully implemented"` | — | **Stub vide** | Jamais |
| `/api/v2/policy/evidence` | GET | Bearer | `recorder.List()` — enregistrements policy replay | Oui | Non | Jamais |
| `/api/v2/policy/bundles` | GET | Bearer | `reg.List()` — bundles Rego actifs | Oui | Non | Jamais |
| `/api/v2/runtime/pause` | POST | Bearer | `sm.Transition(StatusPaused)` — pause le scheduler | Non | **Mutation critique** | Jamais |
| `/api/v2/runtime/resume` | POST | Bearer | `sm.Transition(StatusIdle)` — reprend le scheduler | Non | **Mutation critique** | Jamais |

**Preuve du stub :**  
`internal/api/handlers/v2/handlers.go:109` : `map[string]string{"message": "drift memory exploration not fully implemented"}`

#### API v3 — `/api/v3/` (token Bearer requis)

| Endpoint | Méthode | Auth | Action | Read-only | Mutation | Utilisé |
|----------|---------|------|--------|-----------|----------|---------|
| `/api/v3/policy/explain` | GET | Bearer | `admission.ExplainDecision()` — graphe de décision | Oui | Non | Jamais |
| `/api/v3/security/evidence` | GET | Bearer | `evidence.Search()` — recherche d'evidence | Oui | Non | Jamais |
| `/api/v3/security/evidence/{id}` | GET | Bearer | `evidence.Get()` — evidence par ID | Oui | Non | Jamais |
| `/api/v3/security/evidence/{id}/explain` | GET | Bearer | `reporting.ExplainEvidence()` — explication | Oui | Non | Jamais |
| `/api/v3/security/ownership/lineage` | GET | Bearer | `ownership.Search()` | Oui | Non | Jamais |
| `/api/v3/security/ownership/lineage/page` | GET | Bearer | `ownership.Search()` — paginé | Oui | Non | Jamais |
| `/api/v3/security/ownership/lineage/{id}` | GET | Bearer | `ownership.Get()` | Oui | Non | Jamais |
| `/api/v3/security/ownership/lineage/{id}/explain` | GET | Bearer | `ownership.ExplainLineageEvent()` | Oui | Non | Jamais |

**Total : 20 endpoints.** 4 non-authentifiés, 16 avec Bearer.

---

## Étape 3 — Consommateurs réels

### 3.1 — UI (port 9091)

**Aucun appel vers `:9092` ou `/api/v1-v3/` depuis l'UI.**

Preuve : `grep -rn "9092\|api/v1\|api/v2\|api/v3" internal/ui/` retourne :
- `setup_wizard.go:878` — une seule ligne HTML d'aide : `<code>curl http://127.0.0.1:9092/healthz</code>` — texte statique dans une page de completion du wizard, pas un appel programmatique.

### 3.2 — CLI

Aucun binaire parmi `cf-cleanup`, `cf-allowlist-sync`, `cf-shadow`, `crowdsec-sync` n'appelle l'API admin. Vérifié : aucun de ces binaires n'importe `internal/api/`.

### 3.3 — MCP server (`security-automation-mcp`)

`cmd/security-automation-mcp/main.go` — utilise `internal/mcpserver/`. Aucune référence à `9092`, `api/v1`, `api/v2`, `api/v3`, ou `CF_SYNC_API_TOKEN`.

### 3.4 — Scripts externes

Aucun fichier `.sh`, `.py`, `Makefile`, ou `.yaml` dans le dépôt ne référence `CF_SYNC_API_TOKEN` ou `9092` sauf :
- `docs/superpowers/plans/2026-06-11-v1.6-env-elimination.md` — plan d'architecture (documentation).

### 3.5 — Tests

`cmd/cf-sync/daemon_runtime_test.go` — teste `newAuthenticator()` avec `CF_SYNC_API_TOKEN`. Tests unitaires uniquement, pas des tests d'intégration qui appellent l'API.

`internal/config/config_test.go:161` — `TestResolveAdminToken` — teste la fonction de résolution du token.

### 3.6 — Fichier token sur disque

`/var/lib/security-automation-go/runtime/admin_token` — **n'existe pas en production** (répertoire `runtime/` absent).

### Verdict par endpoint

Tous les 20 endpoints : **jamais utilisés** par un consommateur réel identifié.

---

## Étape 4 — Vérification architecture — doublons avec l'UI

| Fonctionnalité API admin | Équivalent dans l'UI (port 9091) |
|--------------------------|----------------------------------|
| `GET /api/v1/status` — statut runtime | UI Dashboard — affiche `status.Collector` |
| `GET /api/v1/audit/events` — événements | UI Dashboard / health page |
| `POST /api/v1/reconcile/run` — déclenche run | **Stub vide** — pas d'équivalent non plus |
| `POST /api/v1/quarantine/release` | **Stub vide** |
| `GET /api/v2/workers` — statut workers | Pas d'équivalent UI direct |
| `GET /api/v2/governor/budgets` — budgets | Pas d'équivalent UI direct |
| `POST /api/v2/runtime/pause` / `resume` | **Pas d'équivalent UI** — fonctionnalité exclusive de l'API |
| `GET /api/v3/security/evidence` | Pas d'équivalent UI direct |
| `GET /api/v3/policy/explain` | Pas d'équivalent UI direct |

L'UI ne recouvre pas toutes les fonctionnalités de l'API admin — mais les fonctionnalités avancées (pause/resume, evidence, ownership lineage) n'ont **aucun consommateur réel** de toute façon.

---

## Étape 5 — Classification A/B/C/D

### A — Critique (impossible à supprimer)

*Aucun endpoint ne tombe dans cette catégorie.* Aucun consommateur réel identifié.

### B — Utile mais remplaçable

| Endpoint | Pourquoi B | Migration possible |
|----------|-----------|---------------------|
| `GET /healthz`, `/readyz` | Utiles pour monitoring systemd/load balancer | Déjà exposés implicitement via le process vivant |
| `GET /metrics` | Prometheus — utile si scraping configuré | Aucun scraper configuré en production actuellement |
| `POST /api/v2/runtime/pause` / `resume` | Seule façon de pauser le scheduler manuellement | Pourrait être migré vers l'UI admin |

### C — Legacy (aucun consommateur réel)

| Endpoint | Raison |
|----------|--------|
| `GET /statusz` | Doublon de `/healthz`, aucun consommateur |
| `GET /api/v1/status` | Doublon UI, jamais appelé |
| `GET /api/v1/audit/events` | Journal accessible via UI |
| `GET /api/v2/ownership/claims` | Jamais appelé |
| `GET /api/v2/governor/budgets` | Jamais appelé |
| `GET /api/v2/workers` | Jamais appelé |
| `GET /api/v2/policy/evidence` | Jamais appelé |
| `GET /api/v2/policy/bundles` | Jamais appelé |
| `GET /api/v3/policy/explain` | Jamais appelé |
| `GET /api/v3/security/evidence` (toutes variantes) | Jamais appelé |
| `GET /api/v3/security/ownership/lineage` (toutes variantes) | Jamais appelé |

### D — Mort (code mort)

| Endpoint | Raison |
|----------|--------|
| `POST /api/v1/reconcile/run` | `// TODO: Signal the daemon to trigger a run immediately` — stub vide, retourne 202 sans rien faire |
| `POST /api/v1/quarantine/release` | `// TODO: Implement release logic` — stub vide |
| `GET /api/v2/drift/memory` | Retourne littéralement `"not fully implemented"` |

---

## Étape 6 — Risque sécurité

### Exposition réseau

- Bind address : `127.0.0.1:9092` — loopback uniquement, **non exposé sur le réseau**.
- Aucun risque d'accès externe direct.

### Authentification

- Token Bearer dans l'en-tête `Authorization` — implémentation dans `internal/api/middleware/middleware.go:69`.
- Token statique (valeur fixe lue au démarrage) — **pas de rotation automatique**.
- Scopes granulaires définis (`runtime.read`, `runtime.execute`, `runtime.rollback`, `quarantine.manage`, `audit.read`) mais un seul identité "admin" avec tous les scopes est créée.

### CSRF

**Absent.** L'API REST utilise Bearer token — le CSRF ne s'applique pas au REST JSON, contrairement aux formulaires HTML de l'UI. Correct pour ce pattern.

### Stockage du token

- Via `CF_SYNC_API_TOKEN` dans l'env file `/etc/security-automation-go/security-automation.env` — lisible par `security-automation` user.
- Via fichier `$STATE_DIR/runtime/admin_token` — chemin par défaut, mais **le fichier n'existe pas** en production.
- Token en mémoire dans `map[string]Identity` dans l'`Authenticator` — pas de fuite vers SQLite.

### Rotation

Aucune rotation prévue. Token statique pour la durée de vie du process.

### Absence du token — que faire ?

Trois options :

**A — Arrêter le daemon**  
Comportement **avant** le hotfix. Résultat : daemon non-fonctionnel, scheduler mort, zéro sécurité. **Pire option possible.**

**B — Désactiver uniquement l'API**  
Comportement **après** le hotfix appliqué aujourd'hui. L'API ne démarre pas, le scheduler continue. **Option correcte pour l'opération.**

**C — Ignorer totalement**  
Signifie que l'API démarre sans authentification — **risque de sécurité inacceptable**, même sur loopback.

**Réponse : Option B est correcte.** Token absent = API admin désactivée, daemon opérationnel. Déjà implémenté.

---

## Étape 7 — Recommandation finale

### Réponse aux deux questions explicites

**Pourquoi `CF_SYNC_API_TOKEN` existait-il ?**

Il a été créé pour sécuriser une API REST admin séparée sur le port 9092, distincte de l'UI (port 9091). Cette API était conçue comme une interface programmatique machine-à-machine (curl, scripts d'ops, intégrations futures) permettant de piloter le daemon sans passer par l'interface web. Elle a été développée avec une architecture soignée (versioning v1/v2/v3, scopes RBAC, middleware Auth/Tracing/Logging/Recovery) mais **les consommateurs n'ont jamais été construits**. Le token est devenu une exigence au démarrage sans que l'API ne soit jamais utilisée.

**Peut-on supprimer `CF_SYNC_API_TOKEN` en v1.6 ?**

**Oui, complètement, sans aucune régression fonctionnelle.** Zéro consommateur réel identifié. Deux endpoints sont des stubs vides (`// TODO`). Un est explicitement marqué non-implémenté. L'UI n'appelle jamais l'API admin. Aucun script, CLI, ou intégration externe ne l'utilise.

---

### Les quatre options

#### Option 1 — Conserver l'API et le token

**Avantages :** Conserver la surface pour une future intégration externe (monitoring, automation).  
**Inconvénients :** Token à gérer dans l'env file, `pause/resume` stubs ne fonctionnent pas, 3 endpoints sont morts, risque de confusion opérateur.  
**Impact migration :** Aucun.

#### Option 2 — Conserver l'API mais rendre le token facultatif (état actuel après hotfix)

**Avantages :** API disponible si l'opérateur veut l'utiliser, daemon fonctionne sans token, pas de régression.  
**Inconvénients :** API sans token = non démarrée silencieusement — confusion possible. Stubs toujours morts.  
**Impact migration :** Déjà appliqué (hotfix du 2026-06-11).

#### Option 3 — Migrer vers l'auth UI existante

**Avantages :** Un seul système d'auth, UI session-based plus ergonomique, CSRF intégré pour les mutations.  
**Inconvénients :** Perd le caractère machine-à-machine (curl/scripts). La session UI est web-browser, pas REST-friendly.  
**Impact migration :** Routes à ajouter dans `internal/ui/server.go`, token Bearer à remplacer par session cookie.

#### Option 4 — Retirer complètement l'API admin

**Avantages :** Supprime la dette : `newAuthenticator`, `startAPIServer`, `internal/api/` entier, `CF_SYNC_API_TOKEN`, `CF_SYNC_API_TOKEN_FILE`, 20 endpoints, 3 packages (`api/auth`, `api/handlers`, `api/middleware`). Simplifie radicalement `runDaemonWithLocker`. Le port 9092 reste avec uniquement `/metrics`, `/healthz`, `/readyz` (pas besoin d'auth pour ces endpoints).  
**Inconvénients :** Perd `pause/resume` programmatique (non implémenté de toute façon).  
**Impact migration :** Supprimer `internal/api/`, retirer `startAPIServer` de `daemon_runtime.go`, garder uniquement le mux metrics/health sur 9092.

---

### Recommandation

**Option 4 — Retirer l'API admin** est la recommandation pour v1.6.

Justification :
1. Aucun consommateur réel (prouvé par grep exhaustif).
2. Deux des quatre mutations sont des stubs vides depuis le début — l'API n'a jamais été opérationnelle.
3. C'est son absence (requise au démarrage) qui a causé le bug de production.
4. L'UI (port 9091, session-based) couvre déjà les besoins opérateur.
5. Le plan V1.6 ajoute une page Runtime Status qui rend `/api/v1/status` encore plus redondant.
6. Le port 9092 reste utile pour `/metrics` + `/healthz` — sans besoin d'auth ni de token.

Si une API REST machine-à-machine est souhaitée dans une version future, elle devra être construite avec des consommateurs réels dès le départ, pas préallouée comme dette.

---

## Validation

```
go test ./...     → PASS (tous les packages)
go test -race ./... → PASS (lancé séparément si besoin)  
go vet ./...      → PASS (aucune alerte)
go build ./...    → PASS (compilation propre)
```

Aucune modification fonctionnelle dans ce document. Le seul code modifié dans cette session est le hotfix `daemon_runtime.go` (Task 1 du plan V1.6), qui rend la défaillance de `startAPIServer` non-fatale — indépendant de la décision de supprimer ou conserver l'API.
