<#
.SYNOPSIS
  Runs the secret scanner (scripts\tools\secret_scan.js, needs Node.js) over the project or another folder.
.DESCRIPTION
  Findings are redacted: only names, locations, lengths and a per-run fingerprint are shown, never a secret value.
  A report is written to <repo>\build\reports\secret-scan by default.
  Exit code: 0 = no confirmed findings, 1 = confirmed findings (or possible ones with -FailOnPossible),
             2 = usage or tool error, 3 = NOT RUN because Node.js is missing.
  -SelfTest checks the scanner itself against planted fake secrets and a clean file (nothing in the project is read).
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check-secrets.ps1 -Detail
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string]$OutDir,
    [string]$WorkRoot,
    [switch]$SelfTest,
    [switch]$Detail,
    [switch]$FailOnPossible
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
$root = Get-RepoRoot
$node = Find-Tool 'node'
if (-not $node) {
    Write-Host 'NOT RUN: node was not found on PATH (Node.js is needed only for the secret scan).'
    exit 3
}
$scanner = Join-Path $PSScriptRoot 'tools\secret_scan.js'
$work = Get-WorkRoot $WorkRoot
Assert-WorkRootSafe $work
$runDir = Join-Path $work ('secrets-' + (New-RunId))
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

if ($SelfTest) {
    $r = Invoke-Native -File $node -Arguments @($scanner, 'selftest', '--root', (Join-Path $runDir 'controls'), '--out', (Join-Path $runDir 'out')) -WorkingDirectory $root -TimeoutSec 120
    Write-Host ($r.StdOut.TrimEnd())
    if ($r.StdErr.Trim()) { Write-Host ($r.StdErr.TrimEnd()) }
    exit $r.ExitCode
}

if (-not $Path) { $Path = $root }
$Path = (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\')
if (-not $OutDir) { $OutDir = Join-Path $root 'build\reports\secret-scan' }
$OutDir = [System.IO.Path]::GetFullPath($OutDir)

$scanArgs = @($scanner, 'scan', '--root', $Path, '--out', $OutDir)
$decks = @(Get-ChildItem -LiteralPath (Join-Path $Path 'slides') -Filter '*.pptx' -File -ErrorAction SilentlyContinue)
if ($decks.Count -ge 1) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $deckDir = Join-Path $runDir 'deck'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($decks[0].FullName, $deckDir)
    $scanArgs += @('--pptx', $deckDir, '--pptxrel', ('slides/' + $decks[0].Name))
    if ($decks.Count -gt 1) { Write-Warning "Only the first of $($decks.Count) decks is scanned." }
}
$ignoreFile = Join-Path $Path '.gitignore'
if (Test-Path -LiteralPath $ignoreFile) { $scanArgs += @('--gitignore', $ignoreFile) }
if ($FailOnPossible) { $scanArgs += @('--fail-on', 'possible') }

$r = Invoke-Native -File $node -Arguments $scanArgs -WorkingDirectory $root -TimeoutSec 300
$lines = @($r.StdOut -split "`r?`n")
if ($Detail) {
    $lines | ForEach-Object { Write-Host $_ }
} else {
    $lines | Where-Object { $_ -like 'files scanned:*' -or $_ -like 'findings:*' -or $_ -like 'by category:*' -or $_ -like '--- gitignore*' } | ForEach-Object { Write-Host $_ }
}
if ($r.StdErr.Trim()) { Write-Host ($r.StdErr.TrimEnd()) }
Write-Host "report folder: $OutDir"
if ($r.ExitCode -eq 0) { Write-Host 'SECRET SCAN: PASS (no confirmed findings)' } elseif ($r.ExitCode -eq 1) { Write-Host 'SECRET SCAN: FAIL (confirmed findings; see the redacted report)' }
exit $r.ExitCode
