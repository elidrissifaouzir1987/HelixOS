<#
  helix-up.ps1 — Démarre HelixOS : génère les certificats (si absents) puis lance le service noyau
  (serveur mTLS + page d'approbation) pointé sur ton dossier de notes (le "vault").

  Exemple :
    .\ops\helix-up.ps1                                   # vault = %USERPROFILE%\HelixVault
    .\ops\helix-up.ps1 -Vault "D:\MesNotes"              # un autre dossier

  Laisse cette fenêtre ouverte (le service tourne dedans). Ctrl-C pour arrêter.
#>
param(
  [string]$Vault          = "$env:USERPROFILE\HelixVault",
  [string]$Runtime        = "$env:USERPROFILE\.helixos",
  [string]$MtlsAddr       = "127.0.0.1:8443",
  [string]$ApprovalAddr   = "127.0.0.1:8600",
  [string]$ApprovalOrigin = "https://localhost:8600"
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot                 # ...\HelixOS
$bin  = Join-Path $repo 'kernel\target\debug'
$prov = Join-Path $bin 'helixos-provision.exe'
$kern = Join-Path $bin 'helixos-kernel.exe'
if (-not (Test-Path $kern)) { throw "Binaire noyau introuvable. Compile d'abord : cd '$repo\kernel'; cargo build" }

New-Item -ItemType Directory -Force $Vault, "$Runtime\certs", "$Runtime\state" | Out-Null
if (-not (Test-Path "$Runtime\certs\ca.pem")) {
  Write-Host "Génération de la PKI locale dans $Runtime\certs ..."
  & $prov --out "$Runtime\certs"
}
Write-Host ""
Write-Host "HelixOS demarre :"
Write-Host "  vault (notes)   : $Vault"
Write-Host "  mTLS (appelants): $MtlsAddr"
Write-Host "  approbation     : $ApprovalOrigin"
Write-Host "  certs / etat    : $Runtime"
Write-Host "  (Ctrl-C pour arreter)"
Write-Host ""
& $kern --state-dir "$Runtime\state" --vault-root $Vault --cert-dir "$Runtime\certs" `
        --mtls-addr $MtlsAddr --approval-addr $ApprovalAddr --approval-origin $ApprovalOrigin --task-id local
