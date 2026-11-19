<#
.SYNOPSIS
  Emergency stop for a CP3 Phase B run: stops only the processes recorded in <RunDir>\pids.tsv, and only when the pid,
  the start time and the image path all still match the record. It never stops anything else.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cp3\Stop-Cp3.ps1 -RunDir <work>\cp3-...
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$RunDir)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\cp3_lib.ps1"
. "$PSScriptRoot\cp3_proc.ps1"
$pidFile = Join-Path ([System.IO.Path]::GetFullPath($RunDir)) 'pids.tsv'
if (-not (Test-Path -LiteralPath $pidFile)) { Write-Host "No pids.tsv in $RunDir - nothing was recorded, nothing is stopped."; exit 0 }
$bad = 0
foreach ($rec in @(Read-Cp3PidFile $pidFile | Sort-Object -Property StartUtcTicks -Descending)) {
    $r = Stop-Cp3Recorded $rec
    Write-Host ('{0,-6} pid {1,6}: {2}' -f $rec.Role, $rec.Pid, $r)
    if ($r.StartsWith('REFUSED')) { $bad++ }
}
$busy = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $script:Cp3TestPorts -contains [int]$_.LocalPort })
Write-Host ('listeners still on the test ports 15000 / 18443 / 19000: ' + $busy.Count)
foreach ($b in $busy) { Write-Host ('  pid {0} {1}:{2} - check by hand; this script only stops recorded processes' -f $b.OwningProcess, $b.LocalAddress, $b.LocalPort) }
if ($bad -gt 0 -or $busy.Count -gt 0) { exit 1 }
exit 0
