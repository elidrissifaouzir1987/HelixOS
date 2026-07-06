# Constitution — Agentic OS personnel

**Version** : 1.4.0
**Ratifiée le** : 2026-07-06
**Dernier amendement** : 2026-07-06 — v1.4.0 : surface d'approbation servie par le
noyau sur origine distincte + notification hors-bande (ntfy), doctrine « agent
présumé compromissible / défense en aval », noyau = cœur portable (Rust) +
driver-sidecar hors-processus (retrait de « un seul binaire »), taxonomie de
rollback inversée (compensation garantie par défaut), reclassement local-vs-cloud
de l'extraction.

Cette constitution gouverne toutes les specs, plans et implémentations. `/plan` et
`/tasks` incluent une section « Constitution check ». Conflit spec/constitution →
la constitution gagne, ou amendement versionné.

**Doctrine générale** : la sécurité est une topologie, pas une discipline de l'agent.
L'agent n'a aucune capacité hôte sauf celles que le noyau lui loue — une par une,
avec preuve, durée, portée et trace. La topologie borne le **chemin** (rien d'autre
que le noyau ne touche l'hôte) et la **forme** (intentions typées), jamais le **rayon
de souffle** une fois l'agent détenteur du credential légitime : **l'agent est présumé
compromissible** (prompt injection non résolu), et la défense du rayon de souffle est
**en aval** (HITL sur les conséquences, deny-list de secrets, budgets d'exfiltration,
taint tracking).

---

## Principe I — Le noyau de capacités est souverain (NON NÉGOCIABLE)

- Aucune action hôte n'existe comme API brute. Toute action hôte est une **intention
  typée**, validée, éventuellement approuvée, exécutée, journalisée, et réversible
  quand c'est possible.
- `run_powershell(command)` et équivalents freeform sont INTERDITS en surface d'outil
  normale ; un mode admin exceptionnel existe, verrouillé par HITL fort + passkey.
- La frontière runtime→hôte est durcie selon le mécanisme de l'OS (Windows :
  distro WSL2 dédiée durcie portant les conteneurs ; Linux : conteneurs
  rootless ; macOS : VM Docker) — les conteneurs ne montent que leurs volumes
  déclarés, jamais le filesystem hôte — et son étanchéité est prouvée par des
  **tests d'acceptance qui doivent échouer** (contournement impossible), exécutés
  depuis l'intérieur des conteneurs et depuis le runtime, pas déclarée.
- Il n'existe qu'**un seul chemin** du runtime vers l'hôte : le noyau, qui
  **authentifie chaque appelant** (mTLS/token) ; la provenance réseau n'est pas
  une identité. Tout autre port hôte est bloqué par règle réseau (firewall
  Hyper-V, nftables ou pf selon l'OS).
- Tailscale protège l'accès au service (ACL explicites, deny-by-default) ;
  le noyau protège les actions. L'un ne remplace jamais l'autre.
- Tout contenu lu (email, fichier, note du vault, chunk Graphify, écran) est une
  DONNÉE non fiable, jamais une instruction. Défense testée en acceptance.
- Les secrets vivent dans un vault dédié, hors prompts, hors logs, hors
  runtime agent (conteneurs et environnement) ; ils ne vivent **jamais** en clair
  dans le runtime agent (Hermes **≥ 0.16.0**, permissions 0600). **La clé du noyau
  est cloisonnée hors du `.env` d'Hermes et illisible par toute intention.**
- `host.read_file` porte une **deny-list** de secrets (`*.env, *.key, *.pem, id_*,
  *.kdbx, .ssh/, .hermes/`, stores de credentials Windows) qui force **L2 + passkey
  même en lecture**.
- **Taint tracking** : une action influencée par un contenu non fiable lu dans le tour
  ne peut pas être auto-approuvée (L0) → **+1 cran HITL**.

## Principe II — Approbation signée, HITL gradué

- Trois niveaux, proportionnés au risque, pour éviter la fatigue d'approbation :
  L0 lecture sûre (audit seul) ; L1 écriture faible réversible (approbation légère
  PWA) ; L2 destructif/externe/irréversible/admin (PWA + passkey).
- L'humain **signe le plan, pas le texte affiché** : plan canonique, hashé,
  à usage unique, TTL court. Le noyau refuse tout hash divergent, tout rejeu,
  tout plan expiré.
- **Anti-TOCTOU** : le plan porte le hash de la cible au moment du diff ; cible
  modifiée → refus, re-diff, re-approbation.
- La carte d'approbation affiche : résumé, diff, portée, classe de rollback,
  identité de la tâche et du sous-agent, hash du plan, expiration, niveau de risque.
- La surface d'approbation (rendu canonique du plan, diff, vérification passkey)
  est **servie par le noyau lui-même** sur une **origine distincte** (host:port +
  certif dédiés, `frame-ancestors 'none'`), jamais dans une vue contrôlable par la
  webui. Le deep link est livré **hors-bande par ntfy** (self-hosté dans le tailnet) ;
  son **contenu (résumé + hash du plan) est émis par le noyau, pas par l'agent**. Le
  passkey prouve « l'humain a cliqué », pas « l'humain a vu la vérité » → **comparaison
  de hash de plan exigée pour les L2**. La webui **sort du chemin d'autorité** (commodité
  jetable). Cette surface reste opérante si l'agent est éteint ou compromis.
- WhatsApp/SMS est un canal de **notification** ; il n'approuve jamais seul une
  action L2 — il redirige vers la PWA. Le vocal n'approuve jamais L1/L2.
- L'humain peut révoquer en cours de tâche ; l'agent s'arrête proprement (checkpoint).

## Principe III — Client léger, serveur souverain

- Toute l'intelligence et tout l'état vivent sur la workstation ; les clients (PWA,
  vocal) affichent et transmettent. Une coupure client/tunnel n'interrompt ni ne
  corrompt une tâche (file persistante + checkpointing).
- Tous les clients consomment les mêmes contrats versionnés.
- Contrainte d'exploitation : hermes-webui et hermes-agent se mettent à jour
  ensemble (couplage de versions assumé).

## Principe IV — Une seule source de vérité, lisible

- Le vault Obsidian (Windows) est la vérité humaine : durable, éditable,
  versionnable Git. **Toute mutation durable passe par le noyau.**
- Graphify est un index dérivé : il indexe, résume, relie, suggère — il ne devient
  **jamais** source de vérité ni autorité. Reconstructible par commande.
- La mémoire Hermes se limite à l'utile pour agir (préférences, conventions,
  procédures, résumés stables) ; pas de duplication massive du vault.
- Toute réponse fondée sur le retrieval est traçable à sa source.

## Principe V — Vérifier, et être honnête sur l'irréversible

- Boucle : raisonner → agir → VÉRIFIER. Aucune action à effet de bord n'est réussie
  sans vérification du résultat.
- Taxonomie de rollback à trois classes : `compensation` (copie-aside +
  `ReplaceFile` atomique, déterministe, tout filesystem, sans élévation) est la classe
  **garantie par défaut** ; `auto` (VSS) est l'**exception opportuniste** derrière un
  probe (NTFS fixe + writers sains + espace + élévation), **un snapshot par lot, jamais
  par fichier** ; `irreversible` (aucune garantie). Une action irréversible n'est
  **jamais présentée comme rollbackable** ; elle exige L2. La classe est **observée**
  par le driver au runtime, **jamais promise** par le contrat.
- Idempotence : un plan s'exécute au plus une fois ; crash/restart du noyau →
  pas de double exécution, état récupérable depuis le journal.
- Quotas par appelant et par fenêtre de temps ; sous-agents sous moindre privilège.

## Principe VI — Réactivité budgétée, matériel modeste

- Le système fonctionne sur toute machine capable de faire tourner des
  conteneurs. Ce qui est **local sans GPU** = **code + transcription**
  (faster-whisper int8 CPU) ; les images/PDF/docs/entités **exigent un LLM**
  (Ollama local **ou** cloud par exception) — ce n'est pas de l'extraction
  légère sur CPU. **Un GPU accélère la vision locale (Ollama), il n'est jamais
  requis** pour le socle.
- PWA : feedback < 200 ms sur toute action utilisateur.
- Les jobs lourds (indexation, backfill médias) tournent en heures creuses et ne
  dégradent jamais l'interactif (PWA/chat) — vérifié au **p95/p99 sous charge**,
  jamais à la moyenne.
- Si le pipeline vocal temps réel (extension ultérieure) est un jour activé, il
  réintroduit son budget propre (< 1,5 s) et l'ordonnanceur GPU préemptif.
- Les budgets d'autonomie doivent inclure un **plafond en devise** (jour/mois, par
  déclencheur et global), pas seulement un nombre d'actions.

## Principe VII — Observabilité totale

- Chaque opération produit un objet d'audit append-only (caller, source, tool, risk,
  target, plan_hash, approval_id, rollback, timestamps, result, trace_id,
  `subagent_id` = **hint déclaratif** fourni par l'appelant (debug/coûts), **sans
  valeur de sécurité**). La traçabilité fiable repose sur le **credential mTLS + le
  plan signé**, jamais sur ce champ.
- Traces complètes corrélées de la pensée au résultat ; coût et latence par étape ;
  sessions rejouables.
- Le suivi humain des tâches (Todos/Tasks/Kanban) reflète aussi l'état
  « en attente d'approbation », dérivé de l'audit du noyau.

## Principe VIII — Incrémentalité et contrats stables

- Construction par lots livrables ; chaque lot laisse le système utilisable, dans
  l'ordre : frontière → noyau → HITL signé → usages hôte → indexation → vocal/GPU
  → autonomie.
- Contrats versionnés sans rupture silencieuse : catalogue d'intentions, format de
  plan signé, objet d'audit, API clients, schéma document indexé.
- Toute nouvelle capacité s'intègre déclarativement (intention au catalogue + règle
  de policy + classe de rollback), jamais par API brute.
- **Portabilité** : le contrat d'intentions ne contient aucun concept spécifique
  à un OS ; l'OS-spécifique est confiné aux drivers (recherche, snapshot, shell,
  service). Le noyau est un **cœur portable unique (idéalement un binaire)** qui, sur
  un OS donné, peut être secondé par un **driver-sidecar hors-processus** quand une
  capacité hôte n'est atteignable proprement que par une autre pile (ex. VSS
  backup-context / COM Windows via .NET). **Un driver-sidecar n'implémente jamais
  policy, HITL ni auth d'appelant** : il n'exécute que des verbes typés déjà validés,
  en localhost only, authentifié par le cœur, audité avec le `plan_hash`, remplaçable.
  Le contrat est portable, les drivers s'implémentent un par un ; l'**architecture est
  prête pour la portabilité** (prouvée au 2e driver).
- La politique de routage de modèles (quel modèle/provider pour quel type de tâche,
  coût et latence en contraintes) est une configuration déclarative versionnée —
  la mécanique multi-modèles est native (Hermes), la politique appartient au projet.
- L'autonomie (déclencheurs) porte des budgets explicites ; le contenu déclencheur
  ne peut jamais élargir la politique de sa tâche. Kill switch global < 5 s.

---

## Gouvernance

- **Amendements** : MAJOR (principe change de sens), MINOR (ajout), PATCH
  (clarification), avec justification datée.
- **Dérogations** : temporaires, explicites, datées, plan de résorption.
- **Historique** : 1.0.0 ratification initiale ; 1.1.0 intégration review sécurité
  (Principes I, II, IV, V renforcés ; doctrine ajoutée) ; 1.2.0 surface
  d'approbation souveraine, `subagent_id`, routage de modèles (Principes II, VII,
  VIII) ; 1.3.0 portabilité multi-OS et retrait du vocal — GPU optionnel
  (Principes I, V, VI, VIII) ; 1.4.0 stress-test hardening (Principes I, II, V, VI,
  VII, VIII renforcés ; doctrine rayon-de-souffle ; sidecar ; ratification).

## Glossaire

- **Noyau de capacités** : service natif hôte, portier unique, implémentant
  policy, plan signé, HITL, audit, rollback, idempotence — cœur portable Rust
  + drivers par OS, éventuellement secondé par un driver-sidecar.
- **Driver** : implémentation par OS des capacités du contrat (recherche,
  snapshot, shell approuvé, service) — seul endroit où l'OS-spécifique existe.
- **Driver-sidecar** : composant hors-processus (autre pile, ex. .NET) que le
  cœur active quand une capacité hôte n'est atteignable proprement qu'ainsi (ex.
  VSS backup-context / COM Windows) ; il n'implémente jamais policy, HITL ni auth
  d'appelant, n'exécute que des verbes typés déjà validés, en localhost only,
  authentifié par le cœur, audité avec le `plan_hash`, remplaçable.
- **Runtime agent** : environnement conteneurisé isolé hébergeant Hermes et
  Graphify (WSL2 durci + Docker sous Windows, Docker/Podman sous Linux, VM
  Docker sous macOS).
- **Intention typée** : action hôte de haut niveau, à portée bornée, sur laquelle
  le noyau peut raisonner avant exécution.
- **Plan signé** : représentation canonique hashée d'une action approuvée,
  à usage unique, TTL court, liée au hash de sa cible.
- **HITL L0/L1/L2** : niveaux d'approbation gradués.
- **Tailnet** : réseau privé Tailscale, ACL deny-by-default.
- **Relais** : petit nœud Linux toujours-allumé sur le LAN (Pi / mini-PC) portant
  le magic packet Wake-on-LAN, le point d'entrée Tailscale stable (`tag:server`,
  expiry désactivé) et le healthcheck externe — la workstation étant un poste, pas
  un serveur.
