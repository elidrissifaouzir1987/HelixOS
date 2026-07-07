<#
  lockdown.ps1 — Verrou réseau Hyper-V : n'autoriser depuis WSL2 vers l'hôte QUE le port du noyau.

  ================================  ⚠  PORTÉE MACHINE-WIDE  ⚠  ================================
  Le réglage Hyper-V s'applique au *VMCreator WSL* ({40E0AC32-46A5-438A-A0B2-2B479E8F2E90}),
  PARTAGÉ PAR TOUTES LES DISTROS WSL2 — donc AUSSI ta distro `Ubuntu` existante.
  `DefaultOutboundAction Block` coupera la sortie réseau de TOUTES tes distros WSL sauf le port
  autorisé ci-dessous. Si tu utilises Ubuntu pour autre chose (apt, git, réseau), ça le CASSERA.

  → C'est un choix explicite. Ne lance ce script QUE si tu acceptes cet effet machine-wide,
    ou après avoir migré tes usages WSL réseau-dépendants hors de la fenêtre de test.
  → -WhatIf montre ce qui serait fait sans l'appliquer. -Revert restaure DefaultOutboundAction=Allow.
  ============================================================================================

  Requiert : PowerShell ADMIN. Windows 11 22H2+ / WSL 2.0.9+ (Hyper-V firewall).
#>
param(
  [int]$KernelPort = 8443,     # port mTLS du noyau (routé, gateway WSL — cf. décision-record : pas 127.0.0.1)
  [switch]$Revert,
  [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'
$wsl = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'   # VMCreatorId WSL (toutes distros)

if (-not (Get-Command Get-NetFirewallHyperVVMSetting -ErrorAction SilentlyContinue)) {
  throw "Cmdlets Hyper-V firewall indisponibles (Windows 11 22H2+ requis)."
}

if ($Revert) {
  Write-Host "REVERT : DefaultOutboundAction -> Allow, LoopbackEnabled -> True (restaure le réseau WSL machine-wide)."
  if (-not $WhatIf) {
    Set-NetFirewallHyperVVMSetting -Name $wsl -DefaultOutboundAction Allow -LoopbackEnabled True
    Get-NetFirewallHyperVRule -Name 'HelixKernelMTLS' -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule
  }
  Write-Host "Fait." ; return
}

Write-Host "APPLIQUER le verrou (machine-wide sur toutes les distros WSL) :"
Write-Host "  - DefaultInboundAction = Block, DefaultOutboundAction = Block, LoopbackEnabled = False"
Write-Host "  - Règle autorisée : Outbound TCP/$KernelPort (le noyau, sur la gateway WSL)"
if ($WhatIf) { Write-Host "(-WhatIf : rien appliqué.)" ; return }

Set-NetFirewallHyperVVMSetting -Name $wsl -Enabled True `
  -DefaultInboundAction Block -DefaultOutboundAction Block -LoopbackEnabled False
New-NetFirewallHyperVRule -Name 'HelixKernelMTLS' -DisplayName 'HelixOS kernel mTLS' `
  -Direction Outbound -VMCreatorId $wsl -Protocol TCP -RemotePorts $KernelPort | Out-Null

Write-Host "Verrou appliqué. WSL -> hôte autorisé UNIQUEMENT sur TCP/$KernelPort."
Write-Host "Pour restaurer le réseau de tes distros : .\lockdown.ps1 -Revert"
