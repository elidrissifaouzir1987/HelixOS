# Constitution — HelixOS

**Version** : 2.0.0
**Date d'adoption documentaire** : 2026-07-10
**Statut** : norme de conception applicable aux nouvelles specs ; conformité de
release non acquise tant que les gates ne sont pas prouvées
**Changement majeur** : architecture Mac-first, frontière VM sans partage hôte,
leases par tâche, egress/secrets médiés, workflow durable, récupération honnête et
portabilité par conformance.

Cette constitution gouverne l'architecture, les specs, le code, les runbooks et les
releases. Un conflit est résolu en faveur de la constitution ou par un amendement
versionné. Chaque plan et chaque release contiennent un **Constitution Check**
automatisable.

HelixOS est un plan de contrôle de capacités, pas un noyau matériel. Sa doctrine est :

> L'agent est présumé totalement compromis. La sécurité vient de frontières,
> contrats et décisions déterministes situés en aval du modèle, jamais de sa
> docilité, de son prompt ou de sa capacité à détecter une injection.

---

## Principe I — Frontières et modèle de menace (NON NÉGOCIABLE)

1. Hermes, ses sous-agents et skills, les modèles, MCPs, outils, moteurs de
   connaissance, webui et contenus lus sont **non fiables**.
2. Le runtime agent s'exécute dans une VM dédiée pour le profil de production :
   aucun partage du filesystem hôte, socket/API du runtime **hôte**, device hôte
   ou egress direct. Root guest contrôle le runtime guest par hypothèse.
3. Le moteur de connaissance n'a aucun lien direct avec l'agent en Tier 1. Les
   domaines de confidentialité distincts utilisent des compartiments/VM distincts
   ou des projections éphémères ; une VM compromise est réputée lire tous ses
   disques.
4. Tout flux traverse un plan explicite : ingress client, capacité hôte, modèle/
   egress, projection de connaissance ou maintenance. Un réseau privé n'est pas une
   identité et un port unique n'est pas un modèle de sécurité.
   En Tier 1, l'absence de NIC généraliste ou le filtre hôte/hyperviseur est le
   contrôle egress primaire ; un firewall guest n'est qu'une seconde couche.
5. Une compromission totale de la VM agent est un scénario d'acceptance. Elle ne
   donne aucun **nouvel** accès hôte, effet ou egress hors bail, policy et approval
   valides, ni secret brut. Tout octet déjà matérialisé dans cette zone est en
   revanche réputé divulgué jusqu'à destruction du compartiment.
6. Le compromis administrateur/root de l'hôte, du firmware ou de la chaîne de build
   souveraine est hors du périmètre de prévention. Les preuves hors hôte doivent
   rendre certaines altérations détectables.
7. Le profil de confiance, les menaces exclues et les hypothèses sont versionnés.
   Toute nouvelle intégration modifie le threat model avant d'être activée.

## Principe II — Autorité minimale, typée et liée à la tâche

1. Il n'existe aucune API hôte brute. Toute action agentique est une **intention
   typée** connue, validée et bornée.
2. Une identité de workload authentifie un compartiment réellement isolé ; root
   VM peut voler toute clé guest et impersonner ses conteneurs jusqu'à rotation.
   Elle n'accorde aucune portée.
   Un `TaskLease` signé par le cœur accorde à une tâche des intentions,
   racines, budgets, compteurs et une durée précis.
3. Le cœur, à partir d'un `HumanRequestGrant` one-shot signé par un ingress
   humain authentifié ou d'un déclencheur enregistré, est le seul émetteur de bail.
   Un message déclaré par Hermes n'est pas une preuve humaine. L'agent ne peut ni
   s'autoriser, ni élargir, ni renouveler silencieusement.
4. Une délégation ne peut que réduire portée, budget, durée et catalogue. Un
   sous-agent n'hérite jamais de l'union des privilèges du parent ou de tâches
   précédentes.
5. Toute version ou intention inconnue est **refusée**, pas envoyée à
   l'approbation. Une approbation humaine ne rend pas un contrat incompris sûr.
6. Les ressources sont des identifiants opaques `root_id + composants relatifs`,
   jamais des chemins bruts choisis par l'agent. Résolution par handle, validation
   de file ID/volume ID et défense contre traversal, symlink, hardlink, reparse,
   ADS, casse et Unicode sont obligatoires.
7. Les binaires/policies du cœur, credentials, audit, backups, UI d'approbation,
   configuration du superviseur et stores souverains sont des cibles
   non autorisables.
8. Un shell break-glass est un outil humain local, séparé, désactivé par défaut. Il
   n'est jamais accessible à un credential agent. Un script automatisable est un
   package immuable signé avec paramètres, environnement, réseau, limites et
   vérification déclarés.
9. Roots, policies, packages, triggers, provider allowlists et trust stores ne sont
   modifiés que par `helixctl admin` ou une UI souveraine : principal humain
   fort, révision signée, audit et rollback.

## Principe III — Autorisation humaine souveraine

1. Trois niveaux existent : L0 déterministe et borné ; L1 effet faible/récupérable
   avec session authentifiée ; L2 nouvelle destination/provider, effet externe
   visible, donnée sensible, administrateur, dépense hors enveloppe ou absence de
   récupération, avec WebAuthn user verification. L'inférence routinière dans une
   enveloppe pré-autorisée n'est pas L2 par nature.
2. Certaines opérations sont toujours refusées, même L2 : lecture brute de secret,
   extension de bail par l'agent, contrat inconnu ou mutation d'une cible souveraine.
3. Le plan est canonique, haché et signé. Il lie versions, tâche/bail, cible,
   préconditions, effets, budget, profil de récupération, vérification, expiry,
   nonce et fencing epoch.
4. L'assertion WebAuthn est liée au digest complet, à la décision,
   `operation_id`, au nonce et à l'expiration. Le fingerprint visuel est une
   aide, jamais le contrôle cryptographique.
5. La surface d'approbation est servie depuis un **hostname dédié** sans cookie,
   CORS, frame ou service worker partagé avec la webui. Un port différent sur le
   même hostname ne suffit pas.
6. L'UI rend les données canoniques stockées par le cœur ; elle n'affiche pas un
   diff ou résumé fourni comme vérité par l'agent.
7. ntfy, email, messagerie et vocal sont des canaux de notification. Un lien est
   opaque, court et non-bearer ; aucun de ces canaux n'approuve seul une action.
8. Enrôlement, seconde passkey, perte, révocation et récupération sont testés avant
   le mode autonome.
9. La révocation est possible pendant une tâche. Le résultat peut devenir
   `OUTCOME_UNKNOWN` ; le système ne prétend pas annuler un effet déjà commis.

## Principe IV — Effets durables, vérification et récupération honnête

1. Le cycle normatif est :

   `receive → validate → plan → authorize → prepare → execute → verify → settle`.

   Chaque transition significative est persistée avant l'action suivante.
2. L'état de reprise appartient à une machine d'état durable et une transactional
   outbox, pas au seul audit ni à la mémoire du process.
3. Il n'existe pas de garantie `exactly once` universelle entre DB,
   filesystem, processus et API. Les effets utilisent des idempotency keys quand
   le provider les garantit ; sinon un crash ambigu devient
   `OUTCOME_UNKNOWN / RECONCILIATION_REQUIRED` et n'est pas rejoué
   automatiquement.
4. Toute action à effet de bord a un prédicat de vérification. Sans résultat
   vérifiable, elle n'est pas déclarée réussie.
5. Atomicité, compensation préparée, snapshot vérifié et irréversibilité sont des
   propriétés observées séparément. Aucun label de rollback n'est promis par le nom
   de l'OS.
6. Une compensation n'est annoncée qu'après pré-image durable, hash vérifié,
   métadonnées supportées et espace réservé. Échec de préparation → refus ou
   reclassification irréversible + L2.
7. Un rollback automatique vérifie le post-hash. Une modification humaine
   concurrente produit un conflit/merge, jamais un écrasement.
8. Un plan multi-cibles déclare ordre, point de commit, effet partiel et stratégie
   de compensation ; à défaut il est refusé.
9. Le superviseur de PAUSE/ABORT/HALT est indépendant du scheduler et du pool du
   cœur. Chaque exécution porte un fencing epoch ; après HALT le redémarrage est
   PAUSED.
   Une primitive process-group macOS est best-effort ; du code potentiellement
   hostile exige une VM éphémère. Un descendant survivant échoue Tier 1.
10. Un `ExecutionGrant` est inscrit dans un inbox durable avant consommation
    et produit un receipt adapter durable. L'état DISPATCHING est persisté avant
    l'envoi ; replay ou échec de transport ne crée pas un second effet.

## Principe V — Données, secrets et vie privée

1. La vérité documentaire est le vault/fichier humain. Toute mutation **issue de
   l'agent** passe par le cœur ; les modifications humaines ou faites par
   l'application native restent autoritaires et sont réconciliées.
2. La DB du cœur est la vérité des opérations, plans, approvals et budgets.
   Hermes est la mémoire conversationnelle non souveraine ; le knowledge provider
   est un index dérivé et reconstructible.
3. Aucun moteur non fiable ne monte le filesystem hôte, même en lecture seule. Le
   cœur matérialise une projection filtrée, immutable, hachée et accompagnée de
   manifests/tombstones. Projeter est une **déclassification** : toute donnée sur
   le disque d'une VM non fiable est réputée divulguée à cette VM.
4. En Tier 1, Hermes ne parle jamais directement au moteur de connaissance. Le
   moteur renvoie uniquement des IDs candidats/scores bornés ; le cœur filtre les
   IDs par bail, relit lui-même les contenus autorisés et construit les extraits.
   Les domaines de confidentialité sont physiquement séparés.
5. Les secrets ne résident jamais en clair dans le runtime agent, ses
   environnements, volumes, prompts ou logs. Des permissions `0600` ne sont
   pas un store de secrets.
6. Les secrets sont détenus par Keychain/DPAPI/store Linux. L'agent utilise des
   verbes tels que signer, authentifier ou injecter dans un package approuvé ; il
   ne reçoit jamais les octets bruts.
   Un package credential-capable possède un signer/trust tier dédié, digest,
   purpose, destination et réseau liés au plan ; aucune sortie agent-readable.
7. Modèles, web, notifications et connecteurs sortants passent par une gateway
   sandboxée distincte du cœur. Elle détient les credentials, n'a aucune capacité
   hôte et contrôle DNS/destinations/redirections, tailles, octets, coût et
   classification. Tout label fourni par l'agent est réputé le plus restrictif.
8. Les données sont classées public/interne/confidentiel/secret. Le secret ne part
   jamais au cloud ; le confidentiel exige une policy/consentement explicite.
9. Coûts et quotas sont réservés avant l'appel, comptés en micro-unités entières
   avec table de prix versionnée, puis réconciliés. Un budget dépassé coupe avant
   dispatch et met l'autonomie en pause.
10. Toute tâche agent démarre non fiable/sticky car mémoire, skills et données
    VM-locales peuvent déjà l'avoir influencée. Les chemins médiés ajoutent de la
    provenance ; un modèle ne peut pas s'auto-déclarer fiable ni déclassifier.
11. Rétention, export, suppression, redaction, télémétrie et localisation cloud
    sont explicites et testables.

## Principe VI — Portabilité par contrat et conformance

1. Le cœur souverain et ses **verbes/policies** n'exposent aucun concept Windows,
   Linux ou macOS. `os`/`arch` peuvent apparaître comme métadonnées de
   preuve dans `CapabilityReport` ; les primitives de filesystem, service,
   credential, processus, watcher, snapshot et compute résident dans des
   adaptateurs.
2. L'adaptateur publie un `CapabilityReport` observé. Les plans se fondent
   sur les capacités présentes à cet instant, pas sur le nom de l'OS.
3. L'adaptateur n'implémente ni policy, ni approbation, ni auth de l'appelant agent.
   Il accepte un `ExecutionGrant` signé, court, one-shot et lié au plan,
   au verb, aux arguments et à l'epoch.
4. macOS Apple Silicon est la référence d'implémentation, pas une permission
   d'introduire Metal, launchd, APFS ou Keychain dans le contrat commun.
5. La portabilité est **prouvée au deuxième driver** par la même suite de
   conformance inchangée. Avant cela, seule l'intention de portabilité peut être
   revendiquée.
6. Les fonctionnalités ont des tiers : socle portable, amélioration native
   opportuniste, extension privilégiée/session. Une fonctionnalité absente est
   signalée/refusée, jamais simulée par un fallback plus dangereux.
7. Les fichiers partagés suivent un profil de noms portable et sont testés sur
   APFS sensible/insensible à la casse, ext4/Btrfs et NTFS. Réseau, cloud drive,
   placeholders et supports amovibles sont des classes séparées.
8. Images et binaires sont natifs à l'architecture. Sur M4, `arm64` est le
   défaut ; Rosetta/émulation n'est jamais une preuve de performance ou de support.

## Principe VII — Performance, disponibilité et budgets

1. Tout objectif de performance précise hardware, OS/runtime, corpus, concurrence,
   échantillon, percentile et artefact de mesure. Les moyennes seules sont
   insuffisantes.
2. Le contrôle et l'urgence ont des lanes réservées. Files bornées, backpressure,
   deadlines, limites de concurrence et circuit breakers empêchent OOM,
   starvation et boucle.
3. Les jobs interactifs et background sont isolés par quotas CPU, mémoire, PIDs et
   I/O. Sur Apple Silicon, la mémoire unifiée est budgétée avec une marge hôte et
   le compute Metal reste natif.
4. SLO minimaux provisoires : acquittement UI p95 ≤ 200 ms ; décision L0 p95
   ≤ 250 ms ; dégradation interactive p95 ≤ 10 % sous un worker d'indexation ;
   PAUSE persistée < 5 s. Ils sont ratifiés par benchmark M4.
5. Chaque déclencheur autonome a budget d'actions, octets, fichiers, coût,
   concurrence et durée, plus un plafond global. Le contenu déclencheur ne peut
   jamais l'élargir.
6. Une panne de policy, identité, budget, audit durable ou stockage de receipt
   **avant dispatch** fait échouer la mutation en mode fermé. Après un effet
   possible, un échec de persistance produit `OUTCOME_UNKNOWN/AUDIT_PENDING`
   et PAUSE globale, jamais une fausse affirmation fail-closed. Des lectures
   explicitement sûres peuvent se dégrader selon une règle versionnée.
7. Liveness, readiness et dependency health sont distincts. Sleep/wake, session
   verrouillée, FileVault, reboot, perte réseau et power failure sont exercés sur
   le matériel réel.
8. Un relais est une option de récupération/healthcheck hors bande, pas une
   dépendance obligatoire ni une promesse de haute disponibilité.

## Principe VIII — Observabilité vérifiable et sobre

1. État opérationnel, audit sécurité, logs, métriques, traces et journal humain sont
   des flux distincts avec leurs propres accès, rétention et sauvegarde.
2. Chaque effet porte séquence, tâche/lease/workload, policy/catalog versions,
   plan hash, décision, receipt, résultat, coût, latence et trace ID.
3. Le ledger d'audit est hash-chainé, segmenté, checkpointé par signature et copié
   chiffré hors hôte. Append-only local seul n'est pas une preuve anti-altération.
4. Redaction et classification ont lieu avant sérialisation. Secrets, credentials,
   contenu sensible complet et tokens d'approbation ne sont jamais loggés.
5. Les traces stockent événements, outils, provenance, résumés de décision et
   vérifications. Elles ne stockent ni ne réclament la chaîne de pensée privée du
   modèle.
6. Wall clock et horloge monotone sont conservées selon leur rôle ; sleep/resume,
   correction d'heure, fuseau et DST ne doivent pas invalider leases ou mesures.
7. Toute alerte a un owner, un seuil et un runbook. Les métriques sans décision
   opérationnelle associée sont optionnelles.

## Principe IX — Chaîne d'approvisionnement et cycle de vie

1. Dépendances, images et composants tiers sont épinglés. Releases natives et OCI
   sont signées, accompagnées de SBOM/provenance et vérifiées avant installation.
2. Hermes, Graphify, webui, modèles et runtimes sont remplaçables et non souverains.
   Leur popularité ou leur propre sandbox ne satisfait pas les invariants HelixOS.
3. Les services natifs sont distribués par packages signés adaptés à l'OS ; les
   conteneurs par manifests multi-arch et digests résolus.
   Backend VM, guest kernel/init/rootfs, runtime et workers appartiennent aussi à
   la matrice de signature/compatibilité/CVE/rollback.
4. Une update suit : vérifier → quiesce/drain → backup → migration compatible →
   A/B ou remplacement atomique → smoke → commit/rollback. Une seule instance
   détient le fencing actif.
5. Aucun auto-update du cœur souverain sans artefact vérifié, matrice de
   compatibilité, preuve de restore et chemin de rollback.
6. Les migrations utilisent expand/contract et déclarent la version minimale de
   rollback. Un downgrade incompatible est refusé.
7. La sauvegarde couvre DB online, policies, catalogue, audit/checkpoints, CAS de
   récupération, clés/inventaires nécessaires et données non reproductibles.
8. Une restauration est testée sur machine vierge. Elle démarre PAUSED, incrémente
   l'epoch, expire leases/plans/approvals et réconcilie les effets avant reprise.
9. Les identités réseau/machine sont ré-enrôlées ; cloner aveuglément un state file
   ou une clé longue durée est interdit par défaut.

## Principe X — Incrémentalité, preuves et gouvernance

1. L'ordre est : contrats/harness → tranche Mac utile → sécurité/ops → second
   driver → troisième driver → connaissance → autonomie → extensions.
2. Aucun moteur de connaissance, vision, UI automation, snapshot privilégié ou
   swarm n'entre dans le chemin critique avant la tranche verticale robuste.
3. Chaque lot a des critères IN/OUT, SLO, menaces, tests négatifs, preuve de
   rollback/restore et mode de retrait.
4. Le catalogue d'acceptance est versionné. Chaque test décrit fixture, hardware,
   workload, répétitions, seuil et artefact. « Documenté » n'équivaut pas à
   « prouvé ».
5. Une release ne peut annoncer Tier 1 que si sécurité, conformance,
   backup/restore, upgrade/rollback et performance ont des preuves sur matériel
   réel.
6. Le Constitution Check bloque unknown intent/schema, cible souveraine,
   host-share, egress direct, secret runtime, artefact non vérifié et test requis
   absent.

---

## Règles de gouvernance

### Amendements

- **MAJOR** : change le modèle de confiance, l'autorité, la sémantique d'effet ou
  une interdiction non négociable ;
- **MINOR** : ajoute un principe/contrôle compatible ;
- **PATCH** : clarification sans changement de garantie.

Un amendement documente : auteur/owner, date, motivation, menace, alternatives,
impact migration, tests requis et plan de rollback documentaire/technique.

### Dérogations

Une dérogation est exceptionnelle, bornée et non silencieuse. Elle contient :

- principe concerné et risque accepté ;
- scope exact, owner, date de début et expiration ;
- contrôle compensatoire ;
- test qui démontre la dérogation ;
- plan daté de résorption.

Une dérogation ne peut autoriser secret brut dans le runtime, host-share de la VM,
auto-émission de bail, unknown intent, mutation de cible souveraine ou approbation
L2 par messagerie.

### Historique

- 1.0.0–1.4.0 : architecture Windows-first, noyau de capacités Rust, HITL distinct,
  rollback par compensation, défense en aval.
- 2.0.0 : refonte Mac-first conçue pour la portabilité ; VM sans share ; leases par
  tâche ; model/egress et secret-use ; projection CAS ; état durable et
  réconciliation ; récupération effect-specific ; superviseur indépendant ;
  supply-chain et preuves Tier 1.

---

## Glossaire normatif

- **helix-core** : binaire souverain de policy, plans, workflow, approvals,
  budgets et audit.
- **helix-edge** : ingress humain minimal authentifiant le principal et émettant
  les `HumanRequestGrant` ; le profil initial est mono-utilisateur.
- **helix-egress** : broker réseau/credentials sandboxé, sans capacité hôte.
- **helix-supervisor** : composant minimal indépendant gérant fencing,
  PAUSE/ABORT/HALT et descendants.
- **WorkloadIdentity** : identité courte d'un service de la VM ; aucune portée
  documentaire implicite ; elle n'isole pas deux conteneurs face à root guest.
- **HumanRequestGrant** : assertion one-shot signée par l'ingress humain de
  confiance, liée au principal, message, session, template de scope et expiry.
- **TaskLease** : capacité signée, bornée à une tâche, des intentions, ressources,
  budgets et une durée.
- **ExecutionGrant** : autorisation one-shot du cœur vers un adaptateur, liée au
  plan/verb/arguments/epoch.
- **PlanEnvelope** : représentation canonique et signée de l'effet prévu.
- **Outcome unknown** : l'effet a peut-être eu lieu mais le système ne peut pas le
  prouver ; aucun retry automatique.
- **Projection** : corpus filtré, immutable et manifesté produit par le cœur pour
  un moteur non fiable.
- **CapabilityReport** : capacités OS réellement observées, utilisées pour
  construire le plan.
- **Tier 1** : profil dont toutes les preuves sécurité, conformance, opérations et
  performance requises passent sur matériel réel.
