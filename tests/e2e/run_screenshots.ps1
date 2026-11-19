<#
.SYNOPSIS
  Takes screenshots of the real portal (sign-in screen and every role) at a desktop size and at an emulated 360 px phone viewport.
.DESCRIPTION
  Uses the installed desktop Chrome headless with a throw-away profile (tests\e2e\screenshots.mjs). The demo credentials are read from the run folder
  and handed to the script through environment variables only; nothing secret is printed. The phone images are an EMULATED viewport in desktop
  Chrome, not a test on a real phone. Nothing here touches a Windows setting.
#>
[CmdletBinding()]
param(
    [string]$RunDir,
    [string]$OutDir,
    [ValidateSet('core', 'all')][string]$Set = 'core'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $RunDir) { $RunDir = (Get-Content (Join-Path $env:LOCALAPPDATA 'zt-demo\current.txt') -TotalCount 1).Trim() }
if (-not $OutDir) { $OutDir = Join-Path $repo 'docs\screenshots' }
$creds = @{}
$pins = @{}
foreach ($l in Get-Content (Join-Path $RunDir 'demo_credentials.txt')) {
    if ($l -match '^(\S+)\s+(\S+)\s+password:\s+(\S+)\s+step-up PIN:\s+(\d+)\s*$') { $creds[$Matches[1]] = $Matches[3]; $pins[$Matches[1]] = $Matches[4] }
}
$run = Get-Content (Join-Path $RunDir 'run.json') -Raw | ConvertFrom-Json
$chrome = @((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$node = 'C:\Program Files\nodejs\node.exe'
if (-not $chrome -or -not (Test-Path $node)) { throw 'Chrome and Node.js are needed' }
$envSet = @{
    ZT_TEST_CHROME = $chrome; ZT_TEST_BASE = ('http://127.0.0.1:' + $run.ports.edgeHttp); ZT_TEST_PROFILE = (Join-Path $RunDir 'chrome-profile-shots')
    ZT_ROLE_CREDS = (ConvertTo-Json -Compress -InputObject $creds); ZT_ROLE_PINS = (ConvertTo-Json -Compress -InputObject $pins); ZT_SHOT_DIR = $OutDir; ZT_SHOT_SET = $Set
}
$saved = @{}
foreach ($k in $envSet.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $envSet[$k], 'Process') }
try {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = & $node (Join-Path $PSScriptRoot 'screenshots.mjs') 2>&1 | ForEach-Object { $_.ToString() }
    $ErrorActionPreference = $prev
} finally { foreach ($k in $envSet.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') } }
$line = @($out | Where-Object { $_ -like 'RESULT_JSON:*' })
if ($line.Count -eq 0) { throw ('no result: ' + (($out | Select-Object -Last 5) -join ' | ')) }
$res = ConvertFrom-Json -InputObject ($line[0] -replace '^RESULT_JSON:', '')
if ($res.error) { Write-Host ('ERROR: ' + $res.error) }
foreach ($f in $res.files) { Write-Host ('wrote ' + $f) }
Remove-Item -LiteralPath (Join-Path $RunDir 'chrome-profile-shots') -Recurse -Force -ErrorAction SilentlyContinue
