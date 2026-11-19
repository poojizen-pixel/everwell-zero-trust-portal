<#
.SYNOPSIS
  Makes a disposable, hash-verified copy of a database (zero_trust.db plus its -wal and -shm files) for tests.
.DESCRIPTION
  This is a plain FILE copy: the source database is never opened by SQLite, so a verified backup stays byte-identical.
  All three files are copied because the -wal file can hold committed data that is not yet in the .db file.
  The source may not be inside the project's live db folder, and the copy goes to a work folder outside the repository.
  Output object: DbPath, Dir, Files, RunId.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\new-disposable-db.ps1 -Source <folder-with-the-verified-db-files>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [string]$WorkRoot,
    [string]$RunId,
    [string]$BaseName = 'zero_trust'
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"

$src = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\')
Assert-NotProjectDb $src
$work = Get-WorkRoot $WorkRoot
Assert-WorkRootSafe $work
if (-not $RunId) { $RunId = New-RunId }
$dest = Join-Path (Join-Path $work $RunId) 'disposable-db'
if (Test-Path -LiteralPath $dest) { throw "Refusing to overwrite existing path: $dest" }
$main = Join-Path $src ($BaseName + '.db')
if (-not (Test-Path -LiteralPath $main)) { throw "No $BaseName.db found in $src" }

New-Item -ItemType Directory -Force -Path $dest | Out-Null
$copied = New-Object System.Collections.Generic.List[string]
foreach ($suffix in @('.db', '.db-wal', '.db-shm')) {
    $from = Join-Path $src ($BaseName + $suffix)
    if (Test-Path -LiteralPath $from) {
        $to = Join-Path $dest ($BaseName + $suffix)
        Copy-Item -LiteralPath $from -Destination $to
        if ((Get-Sha256Hex $from) -ne (Get-Sha256Hex $to)) { throw "Copy verification failed for $from" }
        $copied.Add($BaseName + $suffix)
    }
}
Write-Host ("disposable copy: " + $dest + "  [" + ($copied -join ', ') + "]  (copies verified by SHA-256)")
[pscustomobject]@{ DbPath = (Join-Path $dest ($BaseName + '.db')); Dir = $dest; Files = $copied.ToArray(); RunId = $RunId }
