<#
.SYNOPSIS
    HelixOS ops (Task E1) — sauvegarde le vault (notes markdown, repo Git) et le
    state dir JSONL du noyau (audit.jsonl, consumed.jsonl) sous un dossier horodate,
    avec un manifest SHA256 permettant de verifier la restauration bit-a-bit.

.DESCRIPTION
    MVP-0 scope : pas de SQLite / pas de ~/.hermes (Hermes est gele). Le seul etat
    durable a proteger est le vault (Git) + le state dir JSONL ecrit par le noyau
    Rust. Voir docs\superpowers\plans\2026-07-06-helixos-mvp0.md Phase E / Task E1.

.PARAMETER VaultDir
    Dossier du vault (notes markdown). Si c'est un repo Git, un commit est tente
    avant la copie (tolere "rien a committer").

.PARAMETER StateDir
    Dossier d'etat du noyau (contient audit.jsonl, consumed.jsonl, etc.).

.PARAMETER DestRoot
    Racine des backups. Le backup est ecrit sous "$DestRoot\$Stamp\".

.PARAMETER Stamp
    Horodatage du backup, PASSE EN ARGUMENT (jamais Get-Date en dur dans le script)
    pour rester deterministe et testable depuis test-backup-restore.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VaultDir,

    [Parameter(Mandatory = $true)]
    [string]$StateDir,

    [Parameter(Mandatory = $true)]
    [string]$DestRoot,

    [Parameter(Mandatory = $true)]
    [string]$Stamp
)

$ErrorActionPreference = 'Stop'

function Get-RelativeFiles {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
        [PSCustomObject]@{
            FullPath = $_.FullName
            Relative = $_.FullName.Substring($Root.Length).TrimStart('\', '/')
        }
    }
}

if (-not (Test-Path -LiteralPath $VaultDir)) {
    throw "VaultDir introuvable: $VaultDir"
}
if (-not (Test-Path -LiteralPath $StateDir)) {
    throw "StateDir introuvable: $StateDir"
}

# --- 1. Vault : commit Git si c'est un repo (tolere "rien a committer") ---
$vaultGitDir = Join-Path $VaultDir '.git'
if (Test-Path -LiteralPath $vaultGitDir) {
    Write-Host "Vault est un repo git -> commit avant sauvegarde ($VaultDir)"
    & git -C $VaultDir add -A 2>&1 | Out-Null
    & git -C $VaultDir commit -m "backup $Stamp" 2>&1 | Out-Null
    # git commit renvoie un code non-zero quand il n'y a rien a committer : on tolere,
    # on ne veut PAS que $ErrorActionPreference='Stop' fasse planter le backup pour ca.
    $global:LASTEXITCODE = 0
}
else {
    Write-Host "Vault n'est pas un repo git ($VaultDir) -> copie simple, pas de commit"
}

# --- 2. Destination horodatee ---
$destDir = Join-Path $DestRoot $Stamp
$destVault = Join-Path $destDir 'vault'
$destState = Join-Path $destDir 'state'

New-Item -ItemType Directory -Force -Path $destVault | Out-Null
New-Item -ItemType Directory -Force -Path $destState | Out-Null

# NOTE: -Path (pas -LiteralPath) ici, car on a besoin de l'expansion du wildcard `*`
# pour copier le CONTENU du dossier plutot que le dossier lui-meme. -LiteralPath
# traiterait `*` comme un caractere litteral (chemin inexistant -> no-op silencieux).
Copy-Item -Path "$VaultDir\*" -Destination $destVault -Recurse -Force
Copy-Item -Path "$StateDir\*" -Destination $destState -Recurse -Force

# --- 3. Manifest SHA256 : "SHA256  chemin-relatif" pour chaque fichier sauvegarde ---
$manifestPath = Join-Path $destDir 'manifest.txt'
$lines = New-Object System.Collections.Generic.List[string]

foreach ($section in @(
        @{ Dir = $destVault; Prefix = 'vault' },
        @{ Dir = $destState; Prefix = 'state' }
    )) {
    foreach ($f in (Get-RelativeFiles -Root $section.Dir)) {
        $hash = (Get-FileHash -LiteralPath $f.FullPath -Algorithm SHA256).Hash
        $relWithPrefix = Join-Path $section.Prefix $f.Relative
        $lines.Add("$hash  $relWithPrefix")
    }
}

Set-Content -LiteralPath $manifestPath -Value $lines -Encoding utf8

Write-Host "Backup: $destDir"
