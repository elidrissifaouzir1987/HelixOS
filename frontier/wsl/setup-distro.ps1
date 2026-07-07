<#
  setup-distro.ps1 — Provisionne la distro WSL2 DÉDIÉE `helixos` (isolée de la distro
  `Ubuntu` existante de l'utilisateur), la durcit, et installe dockerd natif + systemd.

  NE TOUCHE JAMAIS la distro `Ubuntu` existante (sauf, en mode -CloneUbuntu, un export
  lecture-seule pour fabriquer le rootfs de départ).

  Exécution : PowerShell normal (pas besoin d'admin pour wsl import/config).
  Idempotent : refuse de réimporter si `helixos` existe déjà (utiliser -Force pour recréer).

  Rootfs de départ — deux voies :
    (défaut) -RootfsTar <chemin.tar[.gz]>  : un rootfs Ubuntu WSL téléchargé
             (https://cloud-images.ubuntu.com/wsl/noble/current/ ubuntu-noble-wsl-amd64-*.rootfs.tar.gz)
    (fallback) -CloneUbuntu                : clone la distro Ubuntu existante via `wsl --export`
             (self-contained, aucun téléchargement ; part de l'état actuel d'Ubuntu).
#>
param(
  [string]$RootfsTar,
  [switch]$CloneUbuntu,
  [string]$DistroName = 'helixos',
  [string]$InstallDir = "$env:LOCALAPPDATA\helixos-wsl",
  [string]$AppUser = 'helix',
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-Distro($name) { (wsl.exe --list --quiet) -contains $name }

if (Test-Distro $DistroName) {
  if (-not $Force) { throw "La distro '$DistroName' existe déjà. Utiliser -Force pour la recréer (destructif)." }
  Write-Host "Suppression de '$DistroName' (--Force)..." ; wsl.exe --unregister $DistroName | Out-Null
}

# 1) Obtenir un rootfs de départ.
$tar = $null
if ($RootfsTar) {
  if (-not (Test-Path $RootfsTar)) { throw "RootfsTar introuvable : $RootfsTar" }
  $tar = $RootfsTar
} elseif ($CloneUbuntu) {
  if (-not (Test-Distro 'Ubuntu')) { throw "Distro 'Ubuntu' introuvable pour le clone." }
  $tar = Join-Path $env:TEMP 'helixos-seed.tar'
  Write-Host "Export lecture-seule de 'Ubuntu' -> $tar (ne modifie pas Ubuntu)..."
  wsl.exe --export Ubuntu $tar
} else {
  throw "Fournir -RootfsTar <tar> (recommandé, rootfs Ubuntu propre) OU -CloneUbuntu (clone l'Ubuntu existant)."
}

# 2) Importer la distro dédiée.
New-Item -ItemType Directory -Force $InstallDir | Out-Null
Write-Host "Import de '$DistroName' dans $InstallDir ..."
wsl.exe --import $DistroName $InstallDir $tar --version 2

# 3) Créer l'utilisateur applicatif non-root (sudo pour le provisioning, à verrouiller ensuite).
Write-Host "Création de l'utilisateur '$AppUser'..."
wsl.exe -d $DistroName -u root -- bash -lc "id -u $AppUser >/dev/null 2>&1 || (useradd -m -s /bin/bash $AppUser && usermod -aG sudo $AppUser && passwd -d $AppUser)"

# 4) Installer dockerd natif + systemd (PAS Docker Desktop).
Write-Host "Installation de dockerd natif..."
wsl.exe -d $DistroName -u root -- bash -lc "apt-get update -y && apt-get install -y docker.io && usermod -aG docker $AppUser && systemctl enable docker || true"

# 5) Déployer le wsl.conf durci (ferme automount/interop/appendWindowsPath, user non-root, systemd).
$conf = (Get-Content -Raw (Join-Path $here 'helixos.wsl.conf')) -replace "`r`n","`n"
$confB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($conf))
wsl.exe -d $DistroName -u root -- bash -lc "echo $confB64 | base64 -d > /etc/wsl.conf && chmod 644 /etc/wsl.conf && echo '--- /etc/wsl.conf ---' && cat /etc/wsl.conf"

# 6) Redémarrer la distro pour appliquer wsl.conf + systemd.
Write-Host "Redémarrage de '$DistroName' pour appliquer le durcissement..."
wsl.exe --terminate $DistroName

Write-Host ""
Write-Host "OK. Distro '$DistroName' provisionnée (durcie, dockerd natif). Vérifs rapides :"
Write-Host "  wsl -d $DistroName -u $AppUser -- sh -c 'ls /mnt 2>&1; id; docker info --format {{.OperatingSystem}}'"
Write-Host "Attendu : /mnt vide (automount off), user '$AppUser' non-root, docker répond (dockerd natif)."
Write-Host "NB durcissement post-provisioning : retirer '$AppUser' de sudo une fois l'install terminée si tu veux un moindre privilège strict."
