<#
.SYNOPSIS
  Saves a recoverable checkpoint: every project file that differs from (or is missing in) the verified backup is copied to a new
  folder outside the project, with a change list and a SHA-256 manifest. Restoring a file = copying it back from the backup or a checkpoint.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\checkpoint.ps1 -Name D2-server-core -Backup C:\Ap_project_backup_20261012-123054
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Backup,
    [string]$EvidenceFrom
)
$ErrorActionPreference = 'Stop'
$proj = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dest = "C:\Ap_project_checkpoints\$stamp-$Name"
$null = New-Item -ItemType Directory -Path "$dest\files"
function Sha([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
$skip = '\\(build|\.git)\\'
$changes = New-Object System.Collections.Generic.List[string]; $manifest = New-Object System.Collections.Generic.List[string]
foreach ($f in Get-ChildItem -LiteralPath $proj -Recurse -File -Force) {
    if ($f.FullName -match $skip) { continue }
    $rel = $f.FullName.Substring($proj.Length + 1)
    if ($rel -like 'db\zero_trust.db*') { continue }
    $b = Join-Path "$Backup\project" $rel
    $state = $null
    if (-not (Test-Path -LiteralPath $b)) { $state = 'ADDED' } elseif ((Sha $b) -ne (Sha $f.FullName)) { $state = 'CHANGED' }
    if ($state) {
        $t = Join-Path "$dest\files" $rel
        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $t)
        Copy-Item -LiteralPath $f.FullName -Destination $t
        $changes.Add(("{0,-8} {1}" -f $state, $rel.Replace('\', '/')))
        $manifest.Add(("{0}  {1}" -f (Sha $f.FullName), $rel.Replace('\', '/')))
    }
}
# files of the backup that no longer exist in the project (moved to legacy_src, etc.)
foreach ($f in Get-ChildItem -LiteralPath "$Backup\project" -Recurse -File -Force) {
    $rel = $f.FullName.Substring("$Backup\project".Length + 1)
    if ($rel -match $skip) { continue }
    if (-not (Test-Path -LiteralPath (Join-Path $proj $rel))) { $changes.Add(("{0,-8} {1}" -f 'REMOVED', $rel.Replace('\', '/'))) }
}
[System.IO.File]::WriteAllLines("$dest\CHANGES.txt", [string[]]($changes | Sort-Object))
[System.IO.File]::WriteAllLines("$dest\MANIFEST_SHA256.txt", [string[]]$manifest)
if ($EvidenceFrom -and (Test-Path -LiteralPath $EvidenceFrom)) {
    $ev = "C:\Ap_project_evidence\DEMO\$stamp-$Name"
    $null = New-Item -ItemType Directory -Force -Path $ev
    Copy-Item -Path (Join-Path $EvidenceFrom '*') -Destination $ev -Recurse
    Write-Output "evidence copied to $ev"
}
Write-Output ("checkpoint {0}: {1} changed/added/removed entries -> {2}" -f $Name, $changes.Count, $dest)
