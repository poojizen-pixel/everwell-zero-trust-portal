<#
.SYNOPSIS
  Makes a consistent SQLite online backup (VACUUM INTO) of a database and verifies it table by table.
.DESCRIPTION
  An online backup includes data that is still only in the -wal file, which a copy of the .db file alone would miss.
  The backup is verified by comparing a SHA-256 per table between source and backup (no row values are printed).
  Guards: the project's live db folder is refused unless -AllowProjectDb is given explicitly; the destination must not
  exist and must be outside the repository (or inside <repo>\build).
  Exit code: 0 = backup written and verified, non-zero = refused or failed.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\backup-db.ps1 -DbPath <db> -Dest <new backup file>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DbPath,
    [Parameter(Mandatory = $true)][string]$Dest,
    [switch]$AllowProjectDb
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
$root = Get-RepoRoot

# Guards run before anything touches the database.
$destFull = [System.IO.Path]::GetFullPath($Dest)
if (-not $AllowProjectDb) { Assert-NotProjectDb ([System.IO.Path]::GetFullPath($DbPath)) }
if (Test-Path -LiteralPath $destFull) { throw "Refusing: destination already exists: $destFull" }
if ((Test-PathInside $destFull $root) -and -not (Test-PathInside $destFull (Join-Path $root 'build'))) {
    throw "Refusing: backups must not be written inside the repository (use a folder outside it, or <repo>\build)."
}
if (-not (Test-Path -LiteralPath $DbPath)) { throw "Database not found: $DbPath" }
$dbFull = (Resolve-Path -LiteralPath $DbPath).Path

$java = Find-Tool 'java'
if (-not $java) { throw 'java was not found on PATH' }
$toolsDir = Join-Path $root 'build\tools'
if (-not (Test-Path -LiteralPath (Join-Path $toolsDir 'DbTool.class'))) {
    & "$PSScriptRoot\build.ps1" -Component tools *> $null
    if ($LASTEXITCODE -ne 0) { throw 'could not build DbTool (scripts\build.ps1 -Component tools)' }
}
$cp = $toolsDir + ';' + (Get-JavaClasspath)
$r = Invoke-Native -File $java -Arguments @('--enable-native-access=ALL-UNNAMED', '-cp', $cp, 'DbTool', 'backup', $dbFull, $destFull) -WorkingDirectory $root -TimeoutSec 300
Write-Host ($r.StdOut.TrimEnd())
if ($r.StdErr.Trim()) { Write-Host ($r.StdErr.TrimEnd()) }
exit $r.ExitCode
