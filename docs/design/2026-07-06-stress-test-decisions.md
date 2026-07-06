# HelixOS — Décision-record du stress-test (design hardening)

**Date** : 2026-07-06
**Statut** : validé par l'utilisateur (4 forks tranchés) — sert de source de vérité pour amender
`constitution.md` (→ v1.4.0), `ARCHITECTURE.md` (→ v1.2), `ROADMAP-SPECS.md` (→ v4).
**Méthode** : revue adverse multi-agents (red-team sécurité, architecte sceptique, opérateur
day-2, vérité-terrain Windows/WSL2 + sous-agents VSS/Everything/WebAuthn/firewall, décision
langage) + 2 cartographies vérité-terrain (Hermes Agent, Graphify). ~40 sources primaires.
Rapport visuel : `stress-test-verdict.html`.

---

## 0. Verdict global

Excellent modèle de **sécurité**, modèle d'**exploitation** encore à écrire. La doctrine
« la sécurité est une topologie » tient comme **première ligne**, mais elle borne le **chemin**
(rien d'autre que le noyau ne touche l'hôte) et la **forme** (intentions typées), **jamais le
rayon de souffle** une fois qu'un agent compromis détient le credential légitime du noyau.
Quatre intégrations tierces sont surpromises face à leur réalité 2026 ; deux propriétés sont
affichées comme acquises alors qu'elles ne sont jamais exercées. Rien n'invalide le projet ;
tout se corrige **dans les documents et le périmètre** avant d'écrire du code.

---

## 1. Décisions tranchées (validées utilisateur)

### D1 — Surface d'approbation (SPEC-003) : ntfy + micro-PWA du noyau ; « zéro fork » abandonné
`hermes-webui` exécute l'agent **in-process** (lit le SQLite) et **n'expose aucune API** de
deep-link/push. La promesse « la webui ne transporte qu'un deep link, le noyau rend le plan
canonique » n'a pas de brique de transport, et un passkey prouve « l'humain a cliqué », pas
« l'humain a vu la vérité » (détournement de contexte same-device).
**Décision** :
- Le noyau sert la micro-page d'approbation sur une **origine distincte** (host:port + certif
  dédiés, `frame-ancestors 'none'`, `X-Frame-Options: DENY`), ouverte hors de toute vue
  contrôlable par la webui.
- Deep link livré **hors-bande par ntfy** (self-hosté dans le tailnet) ; le **contenu**
  (résumé + hash du plan) est émis par le **noyau**, jamais par l'agent.
- **Comparaison de hash** (≥ 4 premiers octets) exigée pour les L2.
- Cible = **micro-PWA servie par le noyau** (Web Push) → la webui sort du chemin d'autorité et
  redevient une commodité jetable.
- **« Zéro fork » n'est plus un dogme.** WebAuthn sur tailnet est confirmé faisable (RP ID =
  nom MagicDNS, `ts.net` est sur la Public Suffix List → eTLD+1 propre ; `tailscale cert`
  fournit le secure context ; servir same-origin depuis le noyau).

### D2 — Langage du noyau (SPEC-002) : cœur Rust + sidecar C#/.NET JIT ; amender Principe VIII
Go éliminé (pas de révocation mTLS dans la stdlib ; VSS backup-context impossible via WMI —
deux invariants constitutionnels à recoder). C# seul gagne l'interop brute mais seulement en
JIT (sacrifie le binaire unique + gonfle la surface d'attaque du composant souverain).
**Décision** :
- **Cœur Rust** : `rustls` (révocation CRL native), `webauthn-rs`, `#![forbid(unsafe_code)]`
  sur le cœur, binaire statique, service Windows. Porte : mTLS, plan signé, policy, HITL,
  audit, idempotence, quotas, contrat `DriverHost` (zéro concept OS).
- **Sidecar C#/.NET JIT** (`helixos-winhost`) pour l'interop Windows lourde (VSS backup-context
  via AlphaVSS, COM). **Ni policy, ni HITL, ni auth d'appelant** : n'exécute que des **verbes
  typés déjà validés/approuvés** par le cœur, en **localhost only**, authentifié par le cœur,
  audité avec le `plan_hash`. « Une main, pas une tête ». Remplaçable.
- **Amendement Principe VIII** requis (le noyau n'est plus « un seul binaire »).
- Séquencement : le cœur Rust + driver léger (recherche + PowerShell out-of-proc + fichiers)
  est **livrable sans le sidecar** ; sans lui, `snapshot` se dégrade en `compensation`. Le
  sidecar VSS arrive **tard, isolé, optionnel**.
- Plan B documenté : monolithe C#/.NET JIT si le split coûte trop cher au solo.

### D3 — Réalité matérielle v1 : relais Linux toujours-allumé en P1
Cluster : **WoL est L2, Tailscale est L3** (réveil impossible via le tailnet) ; **expiry de clé
Tailscale à J+180** (lockout silencieux) ; reboots Windows Update ; Docker Desktop ne démarre
pas sans session. La workstation est un **poste, pas un serveur**.
**Décision** : un **petit relais Linux toujours-allumé** (Pi / mini-PC) sur le LAN porte le
magic packet WoL, le point d'entrée Tailscale stable (nœud `tag:server`, expiry désactivé), et
le healthcheck externe. C'est l'extension « machine dédiée » de la roadmap **avancée en P1 de
fait**. Complément : expiry de clé désactivé sur workstation+relais, cold-start durci.

### D4 — Périmètre médias Graphify (SPEC-005) : code + markdown + transcription (100 % local)
Graphify est **codebase-first** ; son watch ne reconstruit pas le markdown ; l'extraction
images/PDF est un **vision-LLM** (cloud sauf Ollama), pas de l'OCR local.
**Décision** : MVP = indexation **code + markdown + transcription** (faster-whisper int8 CPU,
confirmé verbatim) — vraiment local, sans GPU. Images/PDF-vision = **extension explicite**
« Ollama-GPU ou cloud par exception », jamais socle. Fraîcheur **déclenchée par le noyau** à
chaque mutation validée. Deux conteneurs (serving `:ro` + extracteur custom en écriture),
limites cgroup, version pinnée (pas `v8`). **Sortir `obsidian.*` du cœur souverain** (catalogue
applicatif distinct — Obsidian n'est pas un concept OS).

---

## 2. Corrections confirmées à appliquer (A1–A9, non débattables)

1. **Supprimer « OCR/captions légers sur CPU »** des 3 docs. Reclasser : local = code +
   transcription ; LLM requis = images/PDF/docs/entités (Ollama ou cloud). Axe réel = local vs
   cloud, pas CPU vs GPU.
2. **« Fraîcheur < 1 min sur le vault »** → redéfinir : < 1 min pour le code ; vault rafraîchi
   par le noyau à chaque mutation validée.
3. **Secrets `.env` en clair** viole le Principe I. Exiger Hermes **≥ 0.16.0** (contrainte
   versionnée) ; secrets 0600 / externalisés ; **clé du noyau cloisonnée hors `.env`** et
   illisible par toute intention.
4. **`subagent_id`** = hint déclaratif debug/coûts, **sans valeur de sécurité** (retirer
   « préserve la granularité de l'audit »). Traçabilité fiable = credential mTLS + plan signé.
5. **Portabilité** : « portable dès le 1er jour » → « architecture prête pour la portabilité » ;
   retirer de la colonne « Robuste » tant qu'un 2e driver ne l'a pas prouvée.
6. **Constitution non ratifiée** : mettre la vraie date (2026-07-06).
7. **Matrice test↔SPEC** : test 5 (Obsidian) → SPEC-004 (pas 003) ; dédupliquer test 12
   (TOCTOU) entre 002/003 ; §9 = source unique.
8. **Graphify « en conteneur »** = serving MCP seulement → 2 conteneurs + cgroup + version
   pinnée.
9. **« WhatsApp/Twilio »** factuellement faux (Baileys ; Twilio = SMS) → ntfy canonique,
   WhatsApp = commodité optionnelle non fiable.

---

## 3. Doctrine — combler le trou topologie → rayon de souffle (D5, à intégrer constitution)

**L'agent est présumé compromissible** (prompt injection non résolu en 2026 ; test #6
« donnée ≠ instruction » = pass/fail non falsifiable). Défense **en aval** :
- `host.read_file` **deny-list** de secrets (`*.env, *.key, *.pem, id_*, *.kdbx, .ssh/,
  .hermes/`, stores de credentials Windows) → force **L2 + passkey même en lecture**.
- **Budgets d'exfiltration** : volume cumulé lu + nb de fichiers distincts / fenêtre glissante,
  orthogonaux aux quotas par-action.
- **Credential du noyau non lisible** par aucune intention (hors volumes montés lisibles).
- **Taint tracking** : une action influencée par du contenu non fiable lu dans le tour ne peut
  pas être auto-approuvée (L0) → +1 cran HITL. Étendre le principe SPEC-006 (« le déclencheur
  n'élargit pas la politique ») à **tout contenu lu**.
- Test #6 → **éval adversariale continue** (taux de compromission < seuil), pas pass/fail.

---

## 4. Vérité-terrain Windows (D6, à intégrer architecture §2/§3)

- **WebAuthn/passkey sur tailnet = CONFIRMÉ.** RP ID = nom MagicDNS `helix.<tailnet>.ts.net`
  (marche car `ts.net` ∈ Public Suffix List → eTLD+1) ; `tailscale cert` = Let's Encrypt secure
  context ; servir same-origin depuis le noyau ; attestation `none` ; jamais l'IP `100.x`.
- **VSS = taxonomie à l'envers.** VSS est par-volume (jamais par-fichier), gel writer de
  plusieurs secondes, se perd sous I/O, échoue disque plein, chemin de création facile
  server-only/en suppression ; seul COM `IVssBackupComponents` est supporté client (absent de
  win32metadata → FFI Rust douloureux ; AlphaVSS C#/C++CLI incompatible AOT → sidecar JIT).
  **Décision** : `compensation` (copie-aside + `ReplaceFile` atomique, déterministe, tout
  filesystem, sans élévation) = classe **garantie par défaut** ; `auto` (VSS) = **exception
  opportuniste** derrière un probe (NTFS fixe + writers sains + espace + élévation), **un
  snapshot par lot jamais par fichier**. La classe est **observée** par le driver au runtime,
  jamais **promise** par le contrat.
- **Recherche de fichiers** = capacité de driver **remplaçable** : Everything (dépend app+service
  tiers) ou Windows Search (OLE DB `Search.CollatorDSO`, zéro install mais pas whole-disk par
  défaut, asynchrone, visibilité LocalSystem à prouver par spike) ou USN/MFT self-built
  (substantiel). Ne pas en faire une dépendance dure ; valider par un spike.
- **Frontière WSL2 = réduction de surface, PAS frontière de VM.** `automount/interop/
  appendWindowsPath=off` fuient (bugs MS) et durcissent surtout Linux→Windows ; l'exposition
  host→distro (`\\wsl$`, vhdx offline, NAT) reste. **Docker Desktop réintroduit des ponts hôte
  massifs** (`\\.\pipe\docker_engine`, bind-mounts Windows auto, moteur cross-distro partagé) →
  **utiliser dockerd natif WSL2 + systemd (ou Podman rootless)**. Interdire et tester : montage
  `docker.sock`, `network_mode: host`, `privileged`, `pid/ipc: host`, `/dev/shm` hôte.
- **Firewall Hyper-V « un seul port »** : vrai pour le routé (NAT + `DefaultOutboundAction=Block`
  + 1 règle), **pas pour le loopback** (`LoopbackEnabled` = toggle global, pas par-port) → binder
  l'endpoint sur la gateway WSL, pas `127.0.0.1`. **mTLS par cert client par conteneur**
  (identité = cert, pas réseau).
- **Reformuler la promesse du harness** : « prouve que les réglages tiennent et régresse s'ils
  sont relâchés », **jamais** « prouve l'inévasibilité ».

---

## 5. Specs / runbooks manquants à ajouter à la roadmap (C1–C5)

Ordre = priorité réelle de mise en prod perso. Ne changent pas l'architecture ; la rendent
vivable un an, seul, depuis un téléphone.

1. **RUNBOOK-BACKUP-RESTORE + 3-2-1** (CRITIQUE) — `~/.hermes` chiffré (secrets + skills +
   mémoire non reproductibles), SQLite via `.backup` + `integrity_check` (jamais `cp` sur WAL),
   vault restic en plus de Git, **restauration testée pour de vrai**.
2. **SPEC-UPGRADE** (CRITIQUE) — blue/green, pin par **digest sha256**, snapshot-avant-upgrade,
   smoke test, rollback, couplage **agent↔webui ET agent↔Graphify** ; CVE exposée-tailnet vs
   non-exposée.
3. **RUNBOOK-COLDSTART & disponibilité** (CRITIQUE) — dockerd/WSL2 natif, auto-start WSL au boot,
   graphe de dépendances noyau↔conteneurs + healthchecks, reprise post-reboot WU, **expiry de
   clé Tailscale désactivé (`tag:server`)**, relais Linux.
4. **SPEC-BUDGET-COÛT** (CRITIQUE) — plafonds **en devise** (jour/mois, par déclencheur +
   global) appliqués par le noyau, coupure = PAUSE auto, extraction/backfill sur Haiku/Ollama
   par défaut, **anti-boucle** orchestrateur Graphify (ré-extraction vision-LLM en boucle =
   centaines de $/nuit).
5. **RUNBOOK-DÉGRADATION + sémantique KILL SWITCH** (MAJEUR) — 3 niveaux **PAUSE(<5 s) /
   ABORT(best-effort) / HALT(brutal)** chronométrés+testés ; le kill doit **tuer les process
   hôte enfants** (`run_approved_script`), pas juste suspendre les crons ; fallback provider
   LLM ; disque-plein→VSS honnête ; Tailscale/Baileys down ; « p95 sous charge » **falsifiable**
   (load-generator synthétique, sinon théâtre).

---

## 6. Ce qui survit comme sain (ne pas toucher, au-delà des correctifs)

Doctrine « sécurité = topologie » comme première ligne · plan signé (hash/TTL/usage unique) +
HITL L0/L1/L2 + taxonomie de rollback honnête + audit append-only + idempotence · noyau portier
unique à intentions typées · CPU-first transcription (faster-whisper int8) · Tailscale
deny-by-default (garde 8642/9119 non exposés ; chiffrer le state file, Tailnet Lock) ·
séparation « Tailscale protège l'accès, le noyau protège les actions ».

---

## 7. Prochaines étapes

1. Amender les 3 docs depuis ce record (constitution v1.4.0, architecture v1.2, roadmap v4 + 5
   runbooks). 2. Revue de cohérence. 3. git init + commit. 4. Revue utilisateur. 5. `/plan`
   SPEC-001 (frontière durcie + harness, runtime natif, relais).
