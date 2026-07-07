<#
.SYNOPSIS
    HelixOS ops (Task E1) — test d'acceptance : prouve que backup.ps1 + restore.ps1
    realisent une restauration BIT-IDENTIQUE du vault et du state dir JSONL du noyau,
    apres perte/corruption reelle des fichiers d'origine.

.DESCRIPTION
    Ne touche a AUCUN vrai vault/state : tout se passe dans des dossiers temporaires
    crees et detruits par ce script. Sequence :
      1. Cree un vault temporaire (demo.md) + un state temporaire (audit.jsonl,
         consumed.jsonl).
      2. Calcule les SHA256 d'origine.
      3. Lance backup.ps1 avec un -Stamp fixe (deterministe).
      4. Detruit/corrompt l'audit + la note d'origine (simulate une perte materielle).
      5. Lance restore.ps1.
      6. Compare les SHA256 restaures aux originaux.
    "E1 OK: restauration bit-identique" + exit 0 si tout correspond, sinon message
    d'erreur + exit 1. Nettoie les dossiers temporaires dans un `finally`.
#>

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backupScript = Join-Path $scriptDir 'backup.ps1'
$restoreScript = Join-Path $scriptDir 'restore.ps1'

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
$sandbox = Join-Path $env:TEMP "helix-e1-test-$runId"

$vaultDir = Join-Path $sandbox 'vault'
$stateDir = Join-Path $sandbox 'state'
$destRoot = Join-Path $sandbox 'backups'
$stamp = '20260101-000000'   # fixe et deterministe, pas Get-Date

$exitCode = 1

try {
    Write-Host "=== E1 test sandbox: $sandbox ==="

    # --- 1. Vault + state temporaires ---
    New-Item -ItemType Directory -Force -Path $vaultDir | Out-Null
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

    $demoPath = Join-Path $vaultDir 'demo.md'
    $demoContent = "# Demo note`n`nContenu original du vault, cree pour le test E1.`nLigne 2 : ne doit pas etre perdue.`n"
    Set-Content -LiteralPath $demoPath -Value $demoContent -Encoding utf8 -NoNewline

    $auditPath = Join-Path $stateDir 'audit.jsonl'
    $auditContent = @(
        '{"operation_id":"op1","tool":"apply_file_patch","result":"success"}'
        '{"operation_id":"op2","tool":"apply_file_patch","result":"success"}'
    ) -join "`n"
    Set-Content -LiteralPath $auditPath -Value $auditContent -Encoding utf8

    $consumedPath = Join-Path $stateDir 'consumed.jsonl'
    $consumedContent = @(
        '{"plan_hash":"aaaa1111"}'
        '{"plan_hash":"bbbb2222"}'
    ) -join "`n"
    Set-Content -LiteralPath $consumedPath -Value $consumedContent -Encoding utf8

    # --- 2. SHA256 d'origine ---
    $originalHashes = @{
        'demo.md'        = (Get-FileHash -LiteralPath $demoPath -Algorithm SHA256).Hash
        'audit.jsonl'    = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash
        'consumed.jsonl' = (Get-FileHash -LiteralPath $consumedPath -Algorithm SHA256).Hash
    }
    Write-Host "SHA256 d'origine calcules pour $($originalHashes.Count) fichiers."

    # --- 3. Backup (stamp fixe) ---
    & $backupScript -VaultDir $vaultDir -StateDir $stateDir -DestRoot $destRoot -Stamp $stamp
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
        throw "backup.ps1 a echoue (exit $LASTEXITCODE)"
    }

    $backupDir = Join-Path $destRoot $stamp
    if (-not (Test-Path -LiteralPath (Join-Path $backupDir 'manifest.txt'))) {
        throw "manifest.txt absent apres backup.ps1 -> backup invalide"
    }

    # --- 4. Detruire/corrompre l'audit + la note d'origine (perte materielle simulee) ---
    Write-Host "Simulation de perte : suppression de l'audit, corruption de la note..."
    Remove-Item -LiteralPath $auditPath -Force
    Set-Content -LiteralPath $demoPath -Value "CORROMPU" -Encoding utf8 -NoNewline
    # consumed.jsonl : on le laisse intact pour verifier que restore.ps1 l'ecrase quand meme
    # correctement (pas seulement les fichiers manquants/corrompus).

    if (Test-Path -LiteralPath $auditPath) { throw "sanity: audit.jsonl aurait du etre supprime" }

    # --- 5. Restore ---
    & $restoreScript -BackupDir $backupDir -VaultDir $vaultDir -StateDir $stateDir
    $restoreExit = $LASTEXITCODE

    if ($restoreExit -ne 0) {
        Write-Host "E1 FAIL: restore.ps1 a signale un echec (exit $restoreExit)" -ForegroundColor Red
        $exitCode = 1
    }
    else {
        # --- 6. Comparaison des SHA256 restaures aux originaux ---
        $restoredHashes = @{
            'demo.md'        = (Get-FileHash -LiteralPath $demoPath -Algorithm SHA256).Hash
            'audit.jsonl'    = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash
            'consumed.jsonl' = (Get-FileHash -LiteralPath $consumedPath -Algorithm SHA256).Hash
        }

        $allMatch = $true
        foreach ($key in $originalHashes.Keys) {
            $orig = $originalHashes[$key]
            $restored = $restoredHashes[$key]
            if ($orig -ne $restored) {
                Write-Host "MISMATCH sur $key : original=$orig restaure=$restored" -ForegroundColor Red
                $allMatch = $false
            }
            else {
                Write-Host "OK $key : $restored"
            }
        }

        if ($allMatch) {
            Write-Host "E1 OK: restauration bit-identique"
            $exitCode = 0
        }
        else {
            Write-Host "E1 FAIL: au moins un fichier restaure ne correspond pas a l'original" -ForegroundColor Red
            $exitCode = 1
        }
    }
}
catch {
    Write-Host "E1 FAIL: exception -> $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    if (Test-Path -LiteralPath $sandbox) {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
