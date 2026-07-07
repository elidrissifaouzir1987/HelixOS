# Phase A — Frontière runtime→hôte (SPEC-001 MVP-0)

Rendre la frontière **prouvée**, de façon portable, sur un **runtime natif** (dockerd dans une
distro WSL2 dédiée durcie — **jamais Docker Desktop**). Rien d'autre ne se construit tant que le
harness ne passe pas au vert (les tentatives de contournement échouent) et ne vire pas au rouge
quand on relâche un réglage.

> **WSL2 = réduction de surface, PAS frontière de VM.** Le vrai rempart contre un conteneur
> hostile est le **noyau + HITL**, pas l'isolation WSL2. Le harness prouve que *les réglages
> configurés tiennent*, jamais l'inévasibilité absolue.

## Contexte de cette machine
- Distro existante : `Ubuntu` (**intouchée** — HelixOS utilise une distro DÉDIÉE `helixos`).
- Pas de Docker installé → **dockerd natif** dans `helixos` (pas de Docker Desktop).
- Cmdlets Hyper-V firewall : disponibles.

## Runbook (ordre)

**1. Provisionner la distro durcie `helixos`** (PowerShell, pas admin) — isolée d'Ubuntu :
```powershell
# Recommandé : rootfs Ubuntu WSL propre (à télécharger une fois) :
#   https://cloud-images.ubuntu.com/wsl/noble/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz
.\wsl\setup-distro.ps1 -RootfsTar C:\chemin\ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz
# OU, sans téléchargement, cloner l'Ubuntu existant (export lecture seule) :
.\wsl\setup-distro.ps1 -CloneUbuntu
```
Vérif : `wsl -d helixos -u helix -- sh -c 'ls /mnt 2>&1; id; docker info --format {{.OperatingSystem}}'`
→ `/mnt` vide (automount off), user `helix` non-root, docker répond (dockerd natif).

**2. Exposer le vault en LECTURE SEULE** dans `helixos` (le compose monte `/mnt/vault`→`/vault:ro`).
Choisir le vault hôte (ex. `C:\Users\elidr\HelixVault`) et le rendre visible en RO à la distro
(montage contrôlé documenté dans SPEC-004 ; pour le test, un dossier de démonstration suffit).
Toute **mutation** du vault passera par le **noyau** (hôte), jamais par ce montage.

**3. Déployer le compose Hermes** (dans `helixos`) :
```powershell
# copier le compose là où la distro le voit (ex. /mnt/compose) puis :
wsl -d helixos -u helix -- sh -lc 'cd /mnt/compose && docker compose up -d'
```
Épingler d'abord l'image Hermes par **digest** (≥ 0.16.0) — remplacer `<PIN_ME>` dans
`compose/docker-compose.yml`.

**4. ⚠ Verrou réseau (OPTIONNEL, MACHINE-WIDE)** — PowerShell **ADMIN** :
```powershell
.\firewall\lockdown.ps1 -WhatIf      # voir sans appliquer
.\firewall\lockdown.ps1              # APPLIQUE (affecte AUSSI la distro Ubuntu !)
.\firewall\lockdown.ps1 -Revert      # restaure le réseau WSL
```
> Le réglage Hyper-V est **partagé par toutes les distros WSL2**, donc il coupera la sortie
> réseau de ta distro `Ubuntu` aussi. À n'appliquer qu'en connaissance de cause. Sans lui, les
> tests 1 (filesystem/interop/vault/socket) passent quand même ; seul le test 2 (port hôte)
> dépend du verrou réseau.

**5. Prouver la frontière** (PowerShell) :
```powershell
.\harness\run-harness.ps1
```
→ `HARNESS VERT` = frontière étanche. Test de régression : relâche un réglage (interop=true, ou
un bind `/mnt/c`) et relance → doit afficher `HARNESS ROUGE`.

## Ce que le harness vérifie
- **Statique** : le compose ne contient aucun pont hôte interdit (`docker.sock`,
  `network_mode: host`, `privileged`, `pid|ipc: host`, `/dev/shm`).
- **Dynamique (depuis le conteneur)** : `/mnt/c` inaccessible, vault RO, interop off, pas de
  `docker.sock`, port hôte non prévu injoignable.

## Sortie de phase
Hermes tourne, structurellement incapable de toucher l'hôte ; harness vert (et rouge si on
relâche). Tests d'acceptance 1 et 2 = **échec attendu** (contournement impossible).
