<#
.SYNOPSIS
    HelixOS ops (Task E1) — restaure un backup produit par backup.ps1 (vault +
    state dir JSONL du noyau), puis RE-VERIFIE chaque fichier restaure contre le
    manifest SHA256. Echoue (exit 1) si un hash diverge.

.PARAMETER BackupDir
    Dossier d'un backup horodate produit par backup.ps1 (contient vault\, state\,
    manifest.txt).

.PARAMETER VaultDir
    Dossier du vault a restaurer (ecrase le contenu existant).

.PARAMETER StateDir
    Dossier d'etat du noyau a restaurer (ecrase le contenu existant).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDir,

    [Parameter(Mandatory = $true)]
    [string]$VaultDir,

    [Parameter(Mandatory = $true)]
    [string]$StateDir
)

$ErrorActionPreference = 'Stop'

$srcVault = Join-Path $BackupDir 'vault'
$srcState = Join-Path $BackupDir 'state'
$manifestPath = Join-Path $BackupDir 'manifest.txt'

if (-not (Test-Path -LiteralPath $BackupDir)) {
    throw "BackupDir introuvable: $BackupDir"
}
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "manifest.txt introuvable dans le backup: $manifestPath"
}

# --- 1. Restauration (ecrase la destination) ---
New-Item -ItemType Directory -Force -Path $VaultDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

# NOTE: -Path (pas -LiteralPath) pour ces operations sur `...\*` : on a besoin de
# l'expansion du wildcard pour agir sur le CONTENU du dossier. -LiteralPath traite
# `*` comme un caractere litteral (chemin inexistant -> no-op silencieux), ce qui
# ferait "reussir" une restauration qui n'a en fait rien copie.
if (Test-Path -LiteralPath $srcVault) {
    Remove-Item -Path "$VaultDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$srcVault\*" -Destination $VaultDir -Recurse -Force
}
else {
    Write-Warning "Pas de dossier vault\ dans le backup ($BackupDir) -> rien restaure pour le vault"
}

if (Test-Path -LiteralPath $srcState) {
    Remove-Item -Path "$StateDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$srcState\*" -Destination $StateDir -Recurse -Force
}
else {
    Write-Warning "Pas de dossier state\ dans le backup ($BackupDir) -> rien restaure pour le state"
}

# --- 2. Re-verification SHA256 de chaque fichier restaure contre le manifest ---
$manifestLines = Get-Content -LiteralPath $manifestPath | Where-Object { $_.Trim().Length -gt 0 }

$mismatches = New-Object System.Collections.Generic.List[string]
$verifiedCount = 0

foreach ($line in $manifestLines) {
    # Format: "<sha256hex>  <chemin-relatif>" (chemin peut contenir des espaces,
    # donc on ne split que sur le premier bloc de separateurs).
    if ($line -notmatch '^([0-9A-Fa-f]{64})\s+(.+)$') {
        throw "Ligne de manifest illisible: $line"
    }
    $expectedHash = $Matches[1]
    $relPath = $Matches[2]

    if ($relPath.StartsWith('vault')) {
        $restoredRoot = $VaultDir
        $relUnderRoot = $relPath.Substring('vault'.Length).TrimStart('\', '/')
    }
    elseif ($relPath.StartsWith('state')) {
        $restoredRoot = $StateDir
        $relUnderRoot = $relPath.Substring('state'.Length).TrimStart('\', '/')
    }
    else {
        throw "Entree de manifest hors vault/state: $relPath"
    }

    $restoredFile = Join-Path $restoredRoot $relUnderRoot

    if (-not (Test-Path -LiteralPath $restoredFile)) {
        $mismatches.Add("MANQUANT apres restauration: $relPath")
        continue
    }

    $actualHash = (Get-FileHash -LiteralPath $restoredFile -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        $mismatches.Add("HASH DIVERGENT: $relPath (attendu $expectedHash, obtenu $actualHash)")
        continue
    }

    $verifiedCount++
}

if ($mismatches.Count -gt 0) {
    Write-Error "Restauration ECHOUEE : $($mismatches.Count) fichier(s) divergent(s) du manifest :"
    $mismatches | ForEach-Object { Write-Error "  $_" }
    exit 1
}

Write-Host "Restauration verifiee ($verifiedCount fichier(s) conformes au manifest)."
Write-Host "Restauration verifiee"
exit 0
