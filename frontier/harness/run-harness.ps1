<#
  run-harness.ps1 — Prouve la frontière : lance un conteneur PROBE (busybox) avec l'isolation
  du service Hermes, exécute les tentatives de contournement DEDANS, et VERROUILLE le résultat.

  VERT  = tous les contournements ont échoué (frontière étanche pour les réglages testés).
  ROUGE = au moins une fuite (frontière percée) -> exit 1, bloque toute suite.

  DÉCISION PAR MARQUEUR, pas par code de sortie : le code de retour de `docker exec sh < stdin`
  ne se propage pas de façon fiable à travers docker/wsl/powershell (observé : RESULT=1 mais
  exit 0). On décide donc sur les marqueurs `FRONTIERE-ETANCHE` / `FRONTIERE-PERCEE` / `LEAK`
  imprimés par le conteneur — jamais sur $LASTEXITCODE seul (sinon FAUX VERT possible).

  Le harness ne PROUVE PAS l'inévasibilité absolue (WSL2 = réduction de surface). Il prouve que
  LES RÉGLAGES CONFIGURÉS TIENNENT, et régresse (ROUGE) si on en relâche un.
#>
param(
  [string]$Distro = 'helixos',
  [string]$AppUser = 'helix'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$forbidden = 'docker\.sock|network_mode:\s*host|privileged:\s*true|pid:\s*host|ipc:\s*host|/dev/shm'

# 1) Garde STATIQUE : ni le compose réel (Hermes) ni le probe ne doivent contenir un pont hôte interdit.
foreach ($f in @((Join-Path (Split-Path $here -Parent) 'compose\docker-compose.yml'),
                 (Join-Path $here 'probe-compose.yml'))) {
  # Ne matcher que les DIRECTIVES ACTIVES : on retire les commentaires (# ...), qui documentent
  # justement les patterns interdits (sinon faux positif sur "# PAS de docker.sock").
  $active = (Get-Content $f) | ForEach-Object { $_ -replace '#.*$','' } | Where-Object { $_ -match '\S' }
  $bad = $active | Select-String -Pattern $forbidden
  if ($bad) { Write-Error "HARNESS ROUGE (statique) : pont hote interdit (directive active) dans $f :`n$($bad.Line -join "`n")"; exit 1 }
}
Write-Host "OK statique : aucun pont hote interdit (directives actives du compose Hermes + probe)."

# 2) Injecter probe-compose.yml + le script de contournement dans la distro (base64, car automount off).
function To-B64($path) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(((Get-Content -Raw $path) -replace "`r`n","`n"))) }
$checkB64 = To-B64 (Join-Path $here 'checks\from-container.sh')

# Commande bash SUR UNE LIGNE, base64 INLINÉ (évite here-string multi-ligne + env + login shell,
# tous sources de fragilité PS->wsl). `bash -c` (pas -l) pour éviter l'avertissement systemd-user.
# Pas de `set -e` : un non-zéro bénin ne doit pas avorter avant la décision par marqueur.
# `docker.io` (Ubuntu) n'inclut PAS le plugin `docker compose` v2 -> on utilise `docker run`,
# qui reproduit à l'identique l'isolation de probe-compose.yml (réseau `internal`, vault RO,
# cap_drop ALL, no-new-privileges). probe-compose.yml reste la doc + la cible de la garde statique.
$cmd = "echo $checkB64 | base64 -d > /tmp/from-container.sh; " +
       "mkdir -p `$HOME/vault-demo; echo 'note originale' > `$HOME/vault-demo/demo.md; " +
       "(docker network inspect helix-kernelnet >/dev/null 2>&1 || docker network create --internal helix-kernelnet >/dev/null 2>&1); " +
       "docker pull -q busybox >/dev/null 2>&1; " +
       "echo '--- CONTOURNEMENTS (dans le conteneur probe) ---'; " +
       "docker run --rm -i --network helix-kernelnet --cap-drop ALL --security-opt no-new-privileges -v `$HOME/vault-demo:/vault:ro busybox sh < /tmp/from-container.sh 2>&1"
# NE PAS 2>&1 sur wsl.exe (PS 5.1 emballe stderr en ErrorRecord -> casse sur l'avertissement wsl).
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$out = (wsl.exe -d $Distro -u $AppUser -- bash -c $cmd | Out-String)
$ErrorActionPreference = $prev
Write-Host $out

# 3) DÉCISION par marqueur (robuste au code de sortie).
if ($out -match 'FRONTIERE-PERCEE' -or $out -match 'LEAK ') {
  Write-Error "HARNESS ROUGE : un contournement a REUSSI (frontiere percee)."; exit 1
}
if ($out -notmatch 'FRONTIERE-ETANCHE') {
  Write-Error "HARNESS INDECIS : marqueur 'FRONTIERE-ETANCHE' absent (le probe n'a pas tourne correctement)."; exit 2
}
Write-Host "HARNESS VERT : tous les contournements ont echoue (frontiere etanche). Tests 1, 2 = echec (attendu)."
Write-Host "Regression : relache un reglage (interop=true, bind /mnt/c, ou vault :rw + reseau non-internal) -> doit virer au ROUGE."
