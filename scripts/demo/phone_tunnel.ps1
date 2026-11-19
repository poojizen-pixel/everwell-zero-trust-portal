<#
.SYNOPSIS
  Keeps the USB tunnel to the phone open: whenever the phone (re)connects, it runs  adb reverse tcp:8080 tcp:8080  again.
.DESCRIPTION
  adb forgets its reverse tunnels every time the phone's USB connection drops (a loose cable, a change of the USB mode on the phone, another
  program taking the debugging interface). The portal then shows "You are offline" / "The hospital network cannot be reached" on the phone.
  This script only ever issues that one idempotent adb command. It changes no firewall, network or certificate setting, opens nothing on the
  laptop's network (the tunnel exists on the USB cable only: phone localhost:8080 -> laptop 127.0.0.1:8080) and downloads nothing.
  It ends by itself after -Hours (default 4), when you press Ctrl+C, or when you stop its process. -Remove ends the tunnel instead.
  adb is looked for on the PATH and in Downloads\platform-tools*; pass -Adb to name it.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\phone_tunnel.ps1
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\phone_tunnel.ps1 -Remove
#>
param(
    [string]$Adb,
    [int[]]$Port = @(8080),
    [double]$Hours = 4,
    [string]$Log,
    [switch]$Remove
)
$ErrorActionPreference = 'Continue'      # adb writes progress text to stderr
if (-not $Adb) {
    $c = Get-Command adb.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $Adb = $c.Source }
    else {
        $hit = @(Get-ChildItem (Join-Path $env:USERPROFILE 'Downloads') -Directory -Filter 'platform-tools*' -ErrorAction SilentlyContinue |
            ForEach-Object { @((Join-Path $_.FullName 'adb.exe'), (Join-Path $_.FullName 'platform-tools\adb.exe')) } | Where-Object { Test-Path -LiteralPath $_ })
        if ($hit.Count -gt 0) { $Adb = $hit[0] }
    }
}
if (-not $Adb -or -not (Test-Path -LiteralPath $Adb)) { Write-Host 'adb.exe not found: pass -Adb <path to adb.exe> (nothing is downloaded by this script).'; exit 2 }
if ($Remove) {
    & $Adb reverse --remove-all 2>&1 | ForEach-Object { Write-Host $_ }
    Write-Host 'the reverse tunnels were removed (the phone can no longer reach the portal until a tunnel is opened again)'
    exit 0
}
if (-not $Log) {
    $cur = Join-Path $env:LOCALAPPDATA 'zt-demo\current.txt'
    $dir = if (Test-Path -LiteralPath $cur) { Join-Path ((Get-Content -LiteralPath $cur -TotalCount 1).Trim()) 'logs' } else { $env:TEMP }
    if (-not (Test-Path -LiteralPath $dir)) { $dir = $env:TEMP }
    $Log = Join-Path $dir 'phone_tunnel.log'
}
function Note([string]$t) { $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $t; Add-Content -LiteralPath $Log -Value $line; Write-Host $line }
$end = (Get-Date).AddHours($Hours)
$present = $false
Note ("watching: adb={0}; tunnel ports {1}; until {2:HH:mm}; log {3}; pid {4}" -f $Adb, ($Port -join ','), $end, $Log, $PID)
while ((Get-Date) -lt $end) {
    $list = (& $Adb reverse --list 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
    if ($LASTEXITCODE -eq 0) {
        if (-not $present) { Note 'phone connected'; $present = $true }
        foreach ($p in $Port) {
            if ($list -notmatch ("tcp:{0}(\s|$)" -f $p)) {
                $out = (& $Adb reverse ("tcp:{0}" -f $p) ("tcp:{0}" -f $p) 2>&1 | ForEach-Object { $_.ToString() }) -join ' '
                Note ("tunnel {0} was missing: reopened (adb exit {1}) {2}" -f $p, $LASTEXITCODE, $out)
            }
        }
    } elseif ($present) { Note 'phone NOT connected (the cable or the USB mode changed): waiting'; $present = $false }
    Start-Sleep -Seconds 3
}
Note 'time is up: stopped'
