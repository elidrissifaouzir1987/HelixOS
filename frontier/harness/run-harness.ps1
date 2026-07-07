<#
  run-harness.ps1 — Prouve la frontière : lance les tentatives de contournement DEPUIS le
  conteneur Hermes et VERROUILLE le résultat.

  VERT  = tous les contournements ont échoué (frontière étanche pour les réglages testés).
  ROUGE = au moins une fuite (frontière percée) -> exit 1, bloque toute suite.

  Le harness ne PROUVE PAS l'inévasibilité absolue (WSL2 = réduction de surface, pas frontière
  de VM). Il prouve que LES RÉGLAGES CONFIGURÉS TIENNENT, et régresse (vire au ROUGE) si on en
  relâche un — cf. décision-record. Complément obligatoire : revue manuelle du compose
  (aucun docker.sock / network_mode host / privileged / pid|ipc host / dev/shm hôte).
#>
param(
  [string]$Distro = 'helixos',
  [string]$ComposeDir = '/mnt/compose',   # emplacement du docker-compose.yml VU DEPUIS la distro
  [string]$Service = 'hermes'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1) Garde-fou statique : le compose ne doit contenir AUCUN pont hôte interdit.
$composeHostPath = Join-Path (Split-Path -Parent $here) 'compose\docker-compose.yml'
$bad = Select-String -Path $composeHostPath -Pattern 'docker\.sock|network_mode:\s*host|privileged:\s*true|pid:\s*host|ipc:\s*host|/dev/shm' -ErrorAction SilentlyContinue
if ($bad) { Write-Error "HARNESS ROUGE (statique) : pont hôte interdit dans le compose :`n$($bad.Line -join "`n")"; exit 1 }
Write-Host "OK statique : aucun pont hôte interdit dans le compose."

# 2) Copier le script de contournement dans la distro et l'exécuter DANS le conteneur.
$check = (Get-Content -Raw (Join-Path $here 'checks\from-container.sh')) -replace "`r`n","`n"
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($check))
# Écrit le script dans la distro (/tmp) puis l'injecte dans le conteneur via `docker compose exec`.
wsl.exe -d $Distro -u helix -- bash -lc "echo $b64 | base64 -d > /tmp/from-container.sh && cd $ComposeDir && docker compose exec -T $Service sh < /tmp/from-container.sh"
$rc = $LASTEXITCODE

Write-Host ""
if ($rc -ne 0) { Write-Error "HARNESS ROUGE : un contournement a RÉUSSI (frontière percée). exit=$rc"; exit 1 }
Write-Host "HARNESS VERT : tous les contournements ont échoué (frontière étanche). Tests 1, 2 = échec (attendu)."
Write-Host "Régression : relâche un réglage (ex. interop=true, ou un bind /mnt/c) et relance -> doit virer au ROUGE."
