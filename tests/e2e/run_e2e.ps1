<#
.SYNOPSIS
  End-to-end scenario tests for the Zero Trust Hospital Portal, run against the disposable run folder created by scripts\demo\demo.ps1.
.DESCRIPTION
  Every check talks to the real stack over HTTP (PEP on loopback; the TLS edge is tested separately). Each row of the scenario matrix
  has an expected result, the actual result and PASS / FAIL / NOT RUN. Nothing here touches the legacy database or any Windows setting.
  The runner changes server policy only through the administrator API and restores it; it starts/stops only the posture agent of this run.
#>
[CmdletBinding()]
param(
    [string]$RunDir,
    [string]$Pep = 'http://127.0.0.1:5000',
    [string]$OutDir,
    [string[]]$Groups = @('A', 'W', 'L', 'B', 'C', 'D', 'E', 'F', 'T', 'M', 'BR', 'X', 'RU'),
    [string]$ManualResults
)
$ErrorActionPreference = 'Stop'
$Groups = @($Groups | ForEach-Object { $_ -split ',' } | Where-Object { $_ })   # -File mode passes "B,E" as one string
Add-Type -AssemblyName System.Net.Http
$repo =(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $RunDir) { $RunDir = (Get-Content (Join-Path $env:LOCALAPPDATA 'zt-demo\current.txt') -TotalCount 1).Trim() }
if (-not $OutDir) { $OutDir = Join-Path $RunDir 'reports' }
$null = New-Item -ItemType Directory -Force -Path $OutDir
$sec = Get-Content (Join-Path $RunDir 'secrets\secrets.json') -Raw | ConvertFrom-Json
$creds = @{}
foreach ($l in Get-Content (Join-Path $RunDir 'demo_credentials.txt')) {
    if ($l -match '^(\S+)\s+(\S+)\s+password:\s+(\S+)\s+step-up PIN:\s+(\d+)\s*$') { $creds[$Matches[1]] = @{ Role = $Matches[2]; Password = $Matches[3]; Pin = $Matches[4] } }
}
$http = New-Object System.Net.Http.HttpClient
$http.Timeout = [TimeSpan]::FromSeconds(30)
$hostDevice = 'DEV-' + $env:COMPUTERNAME
$rows = New-Object System.Collections.Generic.List[object]

function Add-Row([string]$Id, [string]$Group, [string]$Title, [string]$Expected, [string]$Actual, [string]$Result) {
    $rows.Add([pscustomobject]@{ Id = $Id; Group = $Group; Title = $Title; Expected = $Expected; Actual = $Actual; Result = $Result; Method = 'automated' })
    $mark = switch ($Result) { 'PASS' { 'PASS' } 'FAIL' { '*** FAIL' } default { $Result } }
    Write-Host ('{0,-6} {1,-9} {2}' -f $Id, $mark, $Title)
    if ($Result -eq 'FAIL') { Write-Host ('         expected: {0}' -f $Expected); Write-Host ('         actual  : {0}' -f $Actual) }
}
function Check([string]$Id, [string]$Group, [string]$Title, [string]$Expected, [string]$Actual, [bool]$Ok) { Add-Row $Id $Group $Title $Expected $Actual $(if ($Ok) { 'PASS' } else { 'FAIL' }) }
function NotRun([string]$Id, [string]$Group, [string]$Title, [string]$Expected, [string]$Why) { Add-Row $Id $Group $Title $Expected $Why 'NOT RUN' }

function Call([string]$Method, [string]$Path, $Body = $null, [hashtable]$Headers = @{}, [string]$Base = '') {
    if (-not $Base) { $Base = $Pep }
    $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::new($Method), ($Base + $Path))
    foreach ($k in $Headers.Keys) { $null = $req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k]) }
    if ($null -ne $Body) {
        $text = if ($Body -is [string]) { $Body } else { ConvertTo-Json -Compress -Depth 6 -InputObject $Body }
        $req.Content = New-Object System.Net.Http.StringContent ($text, [System.Text.Encoding]::UTF8, 'application/json')
    }
    $resp = $http.SendAsync($req).GetAwaiter().GetResult()
    $txt = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $obj = $null; try { $obj = $txt | ConvertFrom-Json } catch { }
    $hdrs = @{}; foreach ($h in $resp.Headers) { $hdrs[$h.Key.ToLower()] = ($h.Value -join ',') }
    foreach ($h in $resp.Content.Headers) { $hdrs[$h.Key.ToLower()] = ($h.Value -join ',') }
    [pscustomobject]@{ Status = [int]$resp.StatusCode; Json = $obj; Text = $txt; Headers = $hdrs }
}
function Hd($s, [hashtable]$extra = @{}) {
    $h = @{ Authorization = 'Bearer ' + $s.Token; 'X-Device-Id' = $s.Device }
    if ($s.Ip) { $h['X-Edge-Key'] = $sec.edgeKey; $h['X-Forwarded-For'] = $s.Ip }
    foreach ($k in $extra.Keys) { $h[$k] = $extra[$k] }
    $h
}
function Login([string]$User, [string]$Device = $hostDevice, [string]$Kind = 'agent', [string]$Ip = $null, [string]$Password = $null) {
    $pw = if ($Password) { $Password } else { $creds[$User].Password }
    $h = @{ 'X-Device-Id' = $Device }
    if ($Ip) { $h['X-Edge-Key'] = $sec.edgeKey; $h['X-Forwarded-For'] = $Ip }
    $body = @{ username = $User; password = $pw; device_kind = $Kind; device_label = 'e2e test device'; platform = 'Android'; signals = @{ secure_context = $true; standalone = $true; online = $true; visible = $true; connection = '4g' } }
    $r = Call 'POST' '/ctl/login' $body $h
    $s = $null
    if ($r.Status -eq 200 -and $r.Json.token) { $s = [pscustomobject]@{ User = $User; Token = $r.Json.token; Device = $Device; Ip = $Ip; SessionId = $r.Json.session_id; Role = $r.Json.user.role } }
    [pscustomobject]@{ Status = $r.Status; Json = $r.Json; Session = $s }
}
function Pin([string]$User) { $creds[$User].Pin }
function Keys($o) { if ($null -eq $o) { @() } else { @($o.PSObject.Properties.Name) } }
function Desc($r) { $c = ''; if ($r.Json -and $r.Json.error) { $c = ' ' + $r.Json.error } elseif ($r.Json -and $r.Json.code) { $c = ' ' + $r.Json.code }; "HTTP $($r.Status)$c" }
function Hb($s, $signals = @{ secure_context = $true; standalone = $true; online = $true; visible = $true; connection = '4g' }) { Call 'POST' '/ctl/heartbeat' @{ signals = $signals } (Hd $s) }

function Set-Policy($admin, [string]$Path, $Value) { Call 'POST' '/admin/policy/set' @{ path = $Path; value = $Value } (Hd $admin @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) }
function Get-Events($admin, [string]$Query = 'limit=500') { $r = Call 'GET' ('/admin/events?' + $Query) $null (Hd $admin); if ($r.Json) { @($r.Json.events) } else { @() } }

# A request written byte for byte (the .NET HTTP client would normalise "..", "%2e" and similar before sending).
function Raw([string]$Target, [hashtable]$Headers = @{}, [string]$Method = 'GET', [string]$Body = $null) {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', ([uri]$Pep).Port)
    try {
        $c.ReceiveTimeout = 10000
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append("$Method $Target HTTP/1.1`r`nHost: 127.0.0.1`r`nConnection: close`r`n")
        foreach ($k in $Headers.Keys) { $null = $sb.Append("${k}: $($Headers[$k])`r`n") }
        if ($null -ne $Body) { $null = $sb.Append("Content-Type: application/json`r`nContent-Length: $([System.Text.Encoding]::UTF8.GetByteCount($Body))`r`n") }
        $null = $sb.Append("`r`n"); if ($null -ne $Body) { $null = $sb.Append($Body) }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
        $ns = $c.GetStream(); $ns.Write($bytes, 0, $bytes.Length)
        $ms = New-Object System.IO.MemoryStream; $buf = New-Object byte[] 4096
        while (($n = $ns.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
        $txt = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
    } finally { $c.Close() }
    $status = 0; if ($txt -match '^HTTP/1\.\d (\d{3})') { $status = [int]$Matches[1] }
    $i = $txt.IndexOf("`r`n`r`n"); $bodyText = if ($i -ge 0) { $txt.Substring($i + 4) } else { '' }
    $obj = $null; try { $obj = $bodyText | ConvertFrom-Json } catch { }
    [pscustomobject]@{ Status = $status; Json = $obj; Text = $bodyText }
}

# ---- control of the posture agent of THIS run (only the agent process recorded in pids.tsv / started here) -------------------------
$pidFile = Join-Path $RunDir 'pids.tsv'
$agentExe = Join-Path $RunDir 'build\cpp\agent.exe'
function Stop-RunAgent {
    if (-not (Test-Path $pidFile)) { return }
    foreach ($l in Get-Content $pidFile) {
        $f = $l -split "`t"
        if ($f[0] -like 'agent*') { $p = Get-Process -Id ([int]$f[1]) -ErrorAction SilentlyContinue; if ($p -and $p.Path -ieq $f[2]) { Stop-Process -Id $p.Id -Force } }
    }
}
function Start-RunAgent([string[]]$AgentArgs = @()) {
    $saved = [Environment]::GetEnvironmentVariable('ZT_AGENT_SECRET', 'Process')
    [Environment]::SetEnvironmentVariable('ZT_AGENT_SECRET', $sec.agentSecret, 'Process')
    try {
        $n = Get-Random -Maximum 100000
        $sp = @{ FilePath = $agentExe; WorkingDirectory = $RunDir; RedirectStandardOutput = (Join-Path $RunDir "logs\agent_e2e_$n.out.log"); RedirectStandardError = (Join-Path $RunDir "logs\agent_e2e_$n.err.log"); WindowStyle = 'Hidden'; PassThru = $true }
        if ($AgentArgs.Count -gt 0) { $sp.ArgumentList = ($AgentArgs -join ' ') }
        $p = Start-Process @sp
        $null = $p.Handle
    } finally { [Environment]::SetEnvironmentVariable('ZT_AGENT_SECRET', $saved, 'Process') }
    Add-Content -LiteralPath $pidFile -Value ("agent_e2e`t{0}`t{1}`t{2}" -f $p.Id, $agentExe, (Get-Date -Format 'o'))
}
function Wait-Device($admin, [scriptblock]$Pred, [int]$Seconds = 20) {
    $until = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $until) {
        $r = Call 'GET' '/admin/devices' $null (Hd $admin)
        if ($r.Status -eq 200) { $d = @($r.Json.devices | Where-Object { $_.device_id -eq $hostDevice }); if ($d.Count -gt 0 -and (& $Pred $d[0])) { return $d[0] } }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

# ---- the TLS edge (group A) -----------------------------------------------------------------------------------------------------------
$runInfo = Get-Content (Join-Path $RunDir 'run.json') -Raw | ConvertFrom-Json
$edgeHttp = 'http://127.0.0.1:' + $runInfo.ports.edgeHttp
$edgeHttpsPort = [int]$runInfo.ports.edgeHttps
$caCrt = Join-Path $env:LOCALAPPDATA 'zt-demo\ca\ca.crt'
function ECall([string]$Method, [string]$Path, $Body = $null, [hashtable]$Headers = @{}) { Call $Method $Path $Body $Headers $edgeHttp }
# native tools: stderr text must not abort the runner
function RunTool([string]$Exe, [string[]]$ToolArgs) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $Exe @ToolArgs 2>&1 | ForEach-Object { $_.ToString() }; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $code; Output = (@($out) -join "`n") }
}
function Find-Exe([string[]]$Candidates) { foreach ($c in $Candidates) { if (Test-Path -LiteralPath $c) { return $c } }; $null }
# One browser-driven group: runs a Node script (headless desktop Chrome, throw-away profile) with the role credentials and PINs handed over through
# environment variables only (never printed), and turns its RESULT_JSON rows into matrix rows.
function RunBrowserGroup([string]$Group, [string]$Script, [hashtable]$EnvSet, [string]$ProfileName) {
    $nodeX = Find-Exe @('C:\Program Files\nodejs\node.exe')
    $chromeX = Find-Exe @((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'))
    if (-not $chromeX -or -not $nodeX) { NotRun ($Group + '0') $Group 'Browser-level checks' 'run in Chrome' 'Chrome or Node.js is not installed on this machine'; return }
    $credJson = ConvertTo-Json -Compress -InputObject (@{ dr_alice = $creds['dr_alice'].Password; nurse_bob = $creds['nurse_bob'].Password; front_carol = $creds['front_carol'].Password; sec_dan = $creds['sec_dan'].Password })
    $pinJson = ConvertTo-Json -Compress -InputObject (@{ dr_alice = $creds['dr_alice'].Pin; nurse_bob = $creds['nurse_bob'].Pin; front_carol = $creds['front_carol'].Pin; sec_dan = $creds['sec_dan'].Pin })
    $all = @{ ZT_TEST_CHROME = $chromeX; ZT_TEST_BASE = $edgeHttp; ZT_TEST_PROFILE = (Join-Path $RunDir $ProfileName); ZT_ROLE_CREDS = $credJson; ZT_ROLE_PINS = $pinJson }
    foreach ($k in $EnvSet.Keys) { $all[$k] = $EnvSet[$k] }
    $saved = @{}
    foreach ($k in $all.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $all[$k], 'Process') }
    try { $res = RunTool $nodeX @((Join-Path $PSScriptRoot $Script)) } finally { foreach ($k in $all.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') } }
    $lines = @($res.Output -split "`n" | Where-Object { $_ -like 'RESULT_JSON:*' })
    if ($lines.Count -eq 0) { Add-Row ($Group + '0') $Group 'The browser check ran and reported results' 'RESULT_JSON line' ('no result: ' + (($res.Output -split "`n" | Select-Object -Last 4) -join ' | ')) 'FAIL' }
    else { $parsed = ConvertFrom-Json -InputObject ($lines[0] -replace '^RESULT_JSON:', ''); foreach ($x in $parsed) { Check $x.id $Group $x.title $x.expected $x.actual ($x.ok -eq $true) } }
    Remove-Item -LiteralPath (Join-Path $RunDir $ProfileName) -Recurse -Force -ErrorAction SilentlyContinue
}
$opensslExe = Find-Exe @('C:\Program Files\Git\mingw64\bin\openssl.exe', 'C:\Program Files\Git\usr\bin\openssl.exe')
$curlExe = Find-Exe @((Join-Path $env:SystemRoot 'System32\curl.exe'))
function LocalIPv4 {
    $res = @()
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up' -or ([string]$nic.NetworkInterfaceType) -in @('Loopback', 'Tunnel')) { continue }
        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
            $ip = $ua.Address.ToString(); if ($ip -notlike '169.254.*' -and $ip -notlike '127.*') { $res += $ip }
        }
    }
    $res
}
function ParseCertDate([string]$s) { [datetime]::ParseExact((($s -replace '\s+', ' ') -replace ' GMT$', '').Trim(), 'MMM d HH:mm:ss yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
function CertDate([string]$text, [string]$field) { $l = @($text -split "`n" | Where-Object { $_ -like ($field + '=*') })[0]; ParseCertDate ($l -replace ('^' + $field + '='), '') }
function PngSize([string]$file) {
    $b = [System.IO.File]::ReadAllBytes($file)
    if ($b.Length -lt 24 -or $b[1] -ne 0x50 -or $b[2] -ne 0x4E -or $b[3] -ne 0x47) { return $null }
    [pscustomobject]@{ W = ([int]$b[16] * 16777216 + [int]$b[17] * 65536 + [int]$b[18] * 256 + [int]$b[19]); H = ([int]$b[20] * 16777216 + [int]$b[21] * 65536 + [int]$b[22] * 256 + [int]$b[23]) }
}

$run_L = $Groups -contains 'L'; $run_R = $Groups -contains 'R'; $run_W = $Groups -contains 'W'; $run_A = $Groups -contains 'A'; $run_B = $Groups -contains 'B'; $run_C = $Groups -contains 'C'; $run_D = $Groups -contains 'D'; $run_E = $Groups -contains 'E'; $run_F = $Groups -contains 'F'; $run_T = $Groups -contains 'T'; $run_M = $Groups -contains 'M'; $run_U = $Groups -contains 'U'; $run_BR = $Groups -contains 'BR'; $run_X = $Groups -contains 'X'; $run_RU = $Groups -contains 'RU'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "run folder: $RunDir"
$agents = Call 'GET' '/ctl/agents'
$ready = $agents.Status -eq 200 -and @($agents.Json.agents | Where-Object { $_.device_id -eq $hostDevice }).Count -gt 0
if (-not $ready) { throw "the posture agent $hostDevice is not reporting; start the stack first (scripts\demo\demo.ps1 -Action start)" }
# start from a known state: an earlier run may have left accounts locked (risk revocations lock the account for a few minutes)
$a0 = (Login 'sec_dan').Session
if ($null -eq $a0) { throw 'the security administrator could not sign in (is the account locked? wait for the lockout to end)' }
foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $a0) }
# ... and so may emergency (break-glass) access granted during manual use: end every active grant so each test starts from least privilege
$grantList = Call 'GET' '/admin/grants' $null (Hd $a0)
if ($grantList.Json) { foreach ($g in @($grantList.Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $a0 @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) } }
$null = Call 'POST' '/ctl/logout' $null (Hd $a0)

# =============================== A: installable portal, TLS edge, exposure ===========================================================
if ($run_A) {
    Write-Host '--- A: TLS edge, installable web app, exposure'
    $web = Join-Path $repo 'web'
    $httpsUrl = "https://localhost:$edgeHttpsPort"
    if (-not $curlExe -or -not $opensslExe) { throw 'group A needs curl.exe (Windows) and openssl.exe (Git for Windows)' }

    # --- TLS: certificate issued by the demo CA, validated only against the CA file
    $r1 = RunTool $curlExe @('-sS', '--cacert', $caCrt, '--ssl-no-revoke', '--max-time', '15', '-o', '-', '-w', "`n%{http_code}|%{ssl_verify_result}", "$httpsUrl/")
    $last = ($r1.Output -split "`n")[-1]
    Check 'A1' 'A' 'The portal shell is served over HTTPS with a certificate that validates against the demo CA' 'curl exit 0, HTTP 200, certificate verify result 0, shell markup present' ("curl exit {0}, {1} (http|verify), shell markup: {2}" -f $r1.Code, $last, ($r1.Output -match 'id="app"')) ($r1.Code -eq 0 -and $last -eq '200|0' -and $r1.Output -match 'id="app"')
    $r2 = RunTool $curlExe @('-sS', '--ssl-no-revoke', '--max-time', '15', '-o', 'NUL', "$httpsUrl/")
    Check 'A2' 'A' 'Without the demo CA the same HTTPS request is refused (validation is real; the Windows trust store was not changed)' 'curl exit 60 (untrusted root)' ("curl exit {0}: {1}" -f $r2.Code, (($r2.Output -split "`n")[0])) ($r2.Code -eq 60)

    # --- certificate and CA properties
    $srvPem = Join-Path $RunDir 'certs\edge.crt'
    $srvTxt = (RunTool $opensslExe @('x509', '-in', $srvPem, '-noout', '-text')).Output
    $caTxt = (RunTool $opensslExe @('x509', '-in', $caCrt, '-noout', '-text')).Output
    $sd = (RunTool $opensslExe @('x509', '-in', $srvPem, '-noout', '-startdate', '-enddate')).Output
    $cd = (RunTool $opensslExe @('x509', '-in', $caCrt, '-noout', '-startdate', '-enddate')).Output
    $srvDays = ((CertDate $sd 'notAfter') - (CertDate $sd 'notBefore')).TotalDays
    $caDays = ((CertDate $cd 'notAfter') - (CertDate $cd 'notBefore')).TotalDays
    $localIps = @(LocalIPv4)
    $missingSan = @(@('DNS:localhost', 'IP Address:127.0.0.1') + @($localIps | ForEach-Object { 'IP Address:' + $_ }) | Where-Object { $srvTxt -notlike ('*' + $_ + '*') })
    $srvOk = ($srvTxt -match 'CA:FALSE') -and ($srvTxt -match 'TLS Web Server Authentication') -and ($missingSan.Count -eq 0) -and ($srvDays -le 398)
    Check 'A3' 'A' 'Server certificate: SANs for localhost, 127.0.0.1 and every local IPv4, serverAuth, not a CA, validity within the 398-day browser limit' 'all present' ("missing SANs: [{0}]; CA:FALSE={1}; serverAuth={2}; validity {3} days" -f ($missingSan -join ', '), ($srvTxt -match 'CA:FALSE'), ($srvTxt -match 'TLS Web Server Authentication'), [math]::Round($srvDays, 1)) $srvOk
    $caOk = ($caTxt -match 'CA:TRUE, pathlen:0') -and ($caTxt -match 'Name Constraints') -and ($caDays -le 30)
    Check 'A4' 'A' 'The demo CA is short-lived, may not issue sub-CAs and is name-constrained (cannot be used to impersonate public sites)' 'pathlen 0, Name Constraints, <= 30 days' ("pathlen0={0}; nameConstraints={1}; validity {2} days" -f ($caTxt -match 'CA:TRUE, pathlen:0'), ($caTxt -match 'Name Constraints'), [math]::Round($caDays, 1)) $caOk

    # --- installability: manifest, icons, service worker
    $mf = ECall 'GET' '/manifest.webmanifest'
    $m = $mf.Json
    $hasIcon = { param($size, $purpose) @($m.icons | Where-Object { $_.sizes -eq $size -and $_.type -eq 'image/png' -and $_.purpose -eq $purpose }).Count -gt 0 }
    $mOk = $mf.Status -eq 200 -and $mf.Headers['content-type'] -like 'application/manifest+json*' -and $m.name -and $m.short_name -and $m.start_url -and $m.scope -and $m.display -eq 'standalone' -and $m.theme_color -and $m.background_color -and (& $hasIcon '192x192' 'any') -and (& $hasIcon '512x512' 'any') -and (& $hasIcon '512x512' 'maskable')
    Check 'A5' 'A' 'The web app manifest has what Android needs to offer installation (name, start_url, scope, standalone, 192/512/maskable PNG icons)' 'all fields present, served as application/manifest+json' ("HTTP {0}; type {1}; display {2}; start_url {3}; {4} icons" -f $mf.Status, $mf.Headers['content-type'], $m.display, $m.start_url, @($m.icons).Count) ([bool]$mOk)
    $iconProblems = @()
    foreach ($ic in @($m.icons)) {
        $f = Join-Path $web ($ic.src.TrimStart('/') -replace '/', '\')
        $sz = if (Test-Path $f) { PngSize $f } else { $null }
        $want = [int](($ic.sizes -split 'x')[0])
        if ($null -eq $sz -or $sz.W -ne $want -or $sz.H -ne $want) { $iconProblems += $ic.src }
        $served = ECall 'GET' $ic.src
        if ($served.Status -ne 200 -or $served.Headers['content-type'] -ne 'image/png') { $iconProblems += ($ic.src + ' (served ' + $served.Status + ')') }
    }
    $fav = ECall 'GET' '/favicon.png'
    Check 'A6' 'A' 'Every manifest icon exists, is a PNG of the declared size and is served by the edge (plus favicon)' 'no problems' ("problems: [{0}]; favicon HTTP {1}" -f ($iconProblems -join ', '), $fav.Status) ($iconProblems.Count -eq 0 -and $fav.Status -eq 200)
    $swr = ECall 'GET' '/sw.js'
    $swText = Get-Content (Join-Path $web 'sw.js') -Raw
    $swOk = $swr.Status -eq 200 -and $swr.Headers['content-type'] -like 'text/javascript*' -and $swr.Headers['cache-control'] -eq 'no-cache' -and $swr.Headers['service-worker-allowed'] -eq '/'
    Check 'A7' 'A' 'The service worker script is served as JavaScript, revalidated on every load, with scope "/"' 'text/javascript, no-cache, Service-Worker-Allowed: /' ("HTTP {0}; {1}; cache-control {2}; allowed {3}" -f $swr.Status, $swr.Headers['content-type'], $swr.Headers['cache-control'], $swr.Headers['service-worker-allowed']) ([bool]$swOk)
    $swSafe = ($swText -match "'/api/'") -and ($swText -match "'/ctl/'") -and ($swText -match "'/admin/'") -and ($swText -match "headers\.has\('authorization'\)") -and ($swText -match "request\.method !== 'GET'") -and ($swText -match '/offline\.html') -and (([regex]::Matches($swText, 'cache\.put')).Count -eq 1) -and ($swText -match 'SHELL\.includes\(url\.pathname\)')
    Check 'A8' 'A' 'Service worker code (static check): never handles /api, /ctl, /admin or requests with Authorization; stores only listed shell files; has the offline fallback' 'all guards present, one cache.put guarded by the shell list' ("guards present: {0}" -f $swSafe) ([bool]$swSafe)

    # --- security headers and CSP of the shell
    $ix = ECall 'GET' '/'
    $csp = [string]$ix.Headers['content-security-policy']
    $cspOk = $csp -match "default-src 'self'" -and $csp -match "script-src 'self'" -and $csp -match "style-src 'self'" -and $csp -match "frame-ancestors 'none'" -and $csp -match "object-src 'none'" -and $csp -match "base-uri 'none'" -and $csp -notmatch 'unsafe-inline' -and $csp -notmatch 'unsafe-eval' -and $csp -notmatch '\*'
    $hdrOk = $ix.Headers['x-content-type-options'] -eq 'nosniff' -and $ix.Headers['referrer-policy'] -eq 'no-referrer' -and $ix.Headers['x-frame-options'] -eq 'DENY' -and $ix.Headers['cross-origin-opener-policy'] -eq 'same-origin' -and $ix.Headers['cross-origin-resource-policy'] -eq 'same-origin'
    Check 'A9' 'A' 'The shell carries a strict CSP (no inline script/style, no eval, no wildcard, no framing) and the standard hardening headers' 'CSP and nosniff / no-referrer / DENY / COOP / CORP' ("csp strict: {0}; headers: {1}" -f [bool]$cspOk, [bool]$hdrOk) ([bool]($cspOk -and $hdrOk))

    # --- exposure
    $ipp = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $edgeL = @($ipp.GetActiveTcpListeners() | Where-Object { $_.Port -in $edgeHttpsPort, [int]$runInfo.ports.edgeHttp })
    $wild = @($edgeL | Where-Object { $_.Address.ToString() -in '0.0.0.0', '::' })
    $httpNonLoop = @($edgeL | Where-Object { $_.Port -eq [int]$runInfo.ports.edgeHttp -and $_.Address.ToString() -ne '127.0.0.1' })
    Check 'A10' 'A' 'The edge never listens on all interfaces; the plain-HTTP listener is loopback-only; extra HTTPS addresses exist only if requested' 'no 0.0.0.0/::, HTTP only on 127.0.0.1' ("listeners: {0}" -f (($edgeL | ForEach-Object { $_.Address.ToString() + ':' + $_.Port }) -join ', ')) ($edgeL.Count -ge 2 -and $wild.Count -eq 0 -and $httpNonLoop.Count -eq 0)
    $internal = @('/pdp/gateway', '/pdp/evaluate', '/pip/telemetry', '/internal/health', '/pep/status', '/db/zero_trust.db', '/secrets/secrets.json')
    $leaks = @()
    foreach ($p in $internal) { $x = ECall 'GET' $p; if ($x.Status -ne 404) { $leaks += ($p + ' -> ' + $x.Status) } }
    $pt = RunTool $curlExe @('-s', '--path-as-is', '-o', '-', '-w', "`n%{http_code}", "$edgeHttp/ctl/../pdp/evaluate")
    $ptCode = [int](($pt.Output -split "`n")[-1])
    Check 'A11' 'A' 'PDP, protected app and telemetry paths are not reachable through the edge (only the static shell and /api /ctl /admin are exposed)' 'internal paths -> 404; dot-segment trick -> refused' ("not 404: [{0}]; /ctl/../pdp/evaluate -> HTTP {1}" -f ($leaks -join ', '), $ptCode) ($leaks.Count -eq 0 -and $ptCode -ge 400)

    # --- through the edge, end to end
    $dev = 'EDGE-TEST-PHONE-0001'
    $loginBody = @{ username = 'dr_alice'; password = $creds['dr_alice'].Password; device_kind = 'browser'; device_label = 'edge test'; platform = 'Android'; signals = @{ secure_context = $true; standalone = $true; online = $true; visible = $true; connection = '4g' } }
    $lg = ECall 'POST' '/ctl/login' $loginBody @{ 'X-Device-Id' = $dev }
    $tok = $lg.Json.token
    $pl = ECall 'GET' '/api/patients/list' $null @{ Authorization = "Bearer $tok"; 'X-Device-Id' = $dev }
    $ids = @($pl.Json.patients | ForEach-Object { $_.patient_id }) | Sort-Object
    Check 'A12' 'A' 'Through the edge: sign-in, then the doctor sees exactly the two assigned patients; responses are no-store, nosniff and carry no CORS header' 'login 200, 2 patients (101, 102), cache-control no-store, no access-control-allow-origin' ("login {0}; list {1}; ids {2}; cache-control {3}; cors header: {4}" -f $lg.Status, $pl.Status, ($ids -join ','), $pl.Headers['cache-control'], $pl.Headers.ContainsKey('access-control-allow-origin')) ($lg.Status -eq 200 -and $pl.Status -eq 200 -and ($ids -join ',') -eq '101,102' -and $pl.Headers['cache-control'] -eq 'no-store' -and $pl.Headers['x-content-type-options'] -eq 'nosniff' -and -not $pl.Headers.ContainsKey('access-control-allow-origin'))
    $null = ECall 'POST' '/ctl/logout' $null @{ Authorization = "Bearer $tok"; 'X-Device-Id' = $dev }
    $dev2 = 'EDGE-TEST-PHONE-0002'
    $lg2 = ECall 'POST' '/ctl/login' $loginBody @{ 'X-Device-Id' = $dev2; 'X-Forwarded-For' = '203.0.113.9'; 'X-Edge-Key' = 'guess-the-key'; 'Forwarded' = 'for=203.0.113.9' }
    $tok2 = $lg2.Json.token
    $ss = ECall 'GET' '/ctl/session' $null @{ Authorization = "Bearer $tok2"; 'X-Device-Id' = $dev2; 'X-Forwarded-For' = '203.0.113.9'; 'X-Edge-Key' = 'guess-the-key' }
    Check 'A13' 'A' 'A client cannot choose its own network address: forged X-Forwarded-For / X-Edge-Key headers are ignored by the edge' 'session baseline is the real peer 127.0.0.1, not 203.0.113.9' ("login {0}; session {1}; origin_ip {2}" -f $lg2.Status, $ss.Status, $ss.Json.network.origin_ip) ($lg2.Status -eq 200 -and $ss.Status -eq 200 -and $ss.Json.network.origin_ip -eq '127.0.0.1')
    $null = ECall 'POST' '/ctl/logout' $null @{ Authorization = "Bearer $tok2"; 'X-Device-Id' = $dev2 }

    # --- hardening of the edge itself
    $bad = @()
    foreach ($mth in @('PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE')) {
        $x = ECall $mth '/api/patients/list'
        if ($x.Status -ne 405 -or $x.Headers.ContainsKey('access-control-allow-origin')) { $bad += ($mth + ' -> ' + $x.Status) }
    }
    $px = ECall 'POST' '/index.html' '{}' @{}
    if ($px.Status -ne 405) { $bad += ('POST /index.html -> ' + $px.Status) }
    Check 'A14' 'A' 'The edge accepts only GET/POST (HEAD for the shell); PUT, DELETE, PATCH, OPTIONS, TRACE get 405 and no CORS headers' 'all 405' ("unexpected: [{0}]" -f ($bad -join ', ')) ($bad.Count -eq 0)
    $bigStatus = 'no response'
    try { $bigStatus = [string](ECall 'POST' '/ctl/login' ('{"username":"' + ('a' * 70000) + '"}')).Status } catch { $bigStatus = 'connection error: ' + $_.Exception.Message }
    Check 'A15' 'A' 'An oversized request body (70 KB) is rejected by the edge before it reaches the back end' 'HTTP 413' ("HTTP {0}" -f $bigStatus) ($bigStatus -eq '413')
    $paths = @('/../secrets/secrets.json', '/icons/..%2f..%2fsecrets%2fsecrets.json', '/%2e%2e/%2e%2e/secrets/secrets.json', '/..%5csecrets%5csecrets.json', '/icons/icon-192.png/../../app.js', '//app.js', '/APP.JS', '/web/app.js', '/edge/src/edge/Main.java', '/.git/config', '/pdp/sources.txt', '/app.js%00.png', '/icons/', '/sw.js/')
    $trav = @()
    foreach ($p in $paths) {
        $t = RunTool $curlExe @('-s', '--path-as-is', '-o', '-', '-w', "`n%{http_code}", "$edgeHttp$p")
        $code = [int](($t.Output -split "`n")[-1])
        if (($code -ne 404 -and $code -ne 400) -or $t.Output -match 'agentSecret|tokenSecret|package edge|public class Main') { $trav += ($p + ' -> ' + $code) }
    }
    Check 'A16' 'A' 'Path traversal and unlisted files are never served by the static handler' 'every attempt -> 404/400 and no file content' ("{0} attempts; unexpected: [{1}]" -f $paths.Count, ($trav -join ', ')) ($trav.Count -eq 0)

    # --- the page itself must be compatible with that CSP
    $idx = Get-Content (Join-Path $web 'index.html') -Raw
    $off = Get-Content (Join-Path $web 'offline.html') -Raw
    $jsText = Get-Content (Join-Path $web 'app.js') -Raw
    $inlineScripts = ([regex]::Matches($idx + $off, '<script(?![^>]*\bsrc=)[^>]*>')).Count
    $handlerAttrs = ([regex]::Matches($idx + $off, '\son\w+\s*=')).Count
    $styleAttrs = ([regex]::Matches($idx + $off, '\sstyle\s*=')).Count
    $dynamicCode = ([regex]::Matches($jsText, '\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'']|setInterval\s*\(\s*["'']|setAttribute\(\s*["'']style["'']|\.cssText')).Count
    Check 'A17' 'A' 'The pages are CSP-compatible: no inline script, event-handler attribute or style attribute in the HTML; no eval/new Function/cssText/setAttribute("style") in app.js' 'all counts 0' ("inline scripts {0}, handler attributes {1}, style attributes {2}, dynamic code {3}" -f $inlineScripts, $handlerAttrs, $styleAttrs, $dynamicCode) (($inlineScripts + $handlerAttrs + $styleAttrs + $dynamicCode) -eq 0)
    $nodeExe = Find-Exe @('C:\Program Files\nodejs\node.exe')
    if ($nodeExe) {
        $syntaxBad = @()
        foreach ($f in @('app.js', 'sw.js')) { $sr = RunTool $nodeExe @('--check', (Join-Path $web $f)); if ($sr.Code -ne 0) { $syntaxBad += ($f + ': ' + ((@($sr.Output -split "`n") | Select-Object -First 3) -join ' | ')) } }
        Check 'A18' 'A' 'The shipped scripts parse (a syntax error would leave the page blank): node --check on app.js and sw.js' 'both parse' ("problems: [{0}]" -f ($syntaxBad -join '; ')) ($syntaxBad.Count -eq 0)
    } else { NotRun 'A18' 'A' 'The shipped scripts parse (node --check)' 'both parse' 'node.exe not found on this machine' }
}

# =============================== R: role-by-role review (what each role sees and gets back, and what the server refuses) ===============
# Not part of the default group list: it provokes many denials on purpose, so it raises the revoke threshold and burst limit for its own
# duration (restored in a finally block), and it writes role_ui_inventory.json / role_api_inventory.json next to the scenario matrix.
if ($run_R) {
    Write-Host '--- R: role-by-role review'
    $nodeR = Find-Exe @('C:\Program Files\nodejs\node.exe')
    $chromeR = Find-Exe @((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'))
    $dbFileR = Join-Path $RunDir 'db\zero_trust.db'
    function DbProbe([string]$mode) {
        $r = RunTool $nodeR @('--no-warnings', (Join-Path $PSScriptRoot 'db_probe.mjs'), $dbFileR, $mode)
        $line = @($r.Output -split "`n" | Where-Object { $_ -match '^[\[{]' })
        if ($line.Count -eq 0) { throw "db_probe $mode failed: $($r.Output)" }
        $parsed = ConvertFrom-Json -InputObject $line[0]
        if ($parsed -is [System.Array]) { $parsed | ForEach-Object { $_ } } else { $parsed }     # PowerShell 5.1 returns a JSON array as ONE object; enumerate it so callers get rows
    }
    $admR = (Login 'sec_dan').Session
    $polBefore = (Call 'GET' '/admin/policy' $null (Hd $admR)).Json.policy
    $keepThreshold = [int]$polBefore.session.revoke_threshold; $keepBurst = [int]$polBefore.behavior.burst_limit
    try {
        $null = Set-Policy $admR 'session.revoke_threshold' 100000
        $null = Set-Policy $admR 'behavior.burst_limit' 100000
        $gl = Call 'GET' '/admin/grants' $null (Hd $admR)
        foreach ($g in @($gl.Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $admR @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) }

        # ---- R-UI: what each role actually sees in the page (real Chrome, real clicks) --------------------------------------------------------------
        $uiInv = $null
        if ($nodeR -and $chromeR) {
            $credJson = ConvertTo-Json -Compress -InputObject (@{ dr_alice = $creds['dr_alice'].Password; nurse_bob = $creds['nurse_bob'].Password; front_carol = $creds['front_carol'].Password; sec_dan = $creds['sec_dan'].Password })
            $envUi = @{ ZT_TEST_CHROME = $chromeR; ZT_TEST_BASE = $edgeHttp; ZT_TEST_PROFILE = (Join-Path $RunDir 'chrome-profile-ui'); ZT_ROLE_CREDS = $credJson }
            $savedUi = @{}
            foreach ($k in $envUi.Keys) { $savedUi[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $envUi[$k], 'Process') }
            try { $ur = RunTool $nodeR @((Join-Path $PSScriptRoot 'role_ui_inventory.mjs')) }
            finally { foreach ($k in $envUi.Keys) { [Environment]::SetEnvironmentVariable($k, $savedUi[$k], 'Process') } }
            $ul = @($ur.Output -split "`n" | Where-Object { $_ -like 'RESULT_JSON:*' })
            if ($ul.Count -gt 0) { $uiInv = ConvertFrom-Json -InputObject ($ul[0] -replace '^RESULT_JSON:', ''); [System.IO.File]::WriteAllText((Join-Path $OutDir 'role_ui_inventory.json'), ($ul[0] -replace '^RESULT_JSON:', '')) }
            Remove-Item -LiteralPath (Join-Path $RunDir 'chrome-profile-ui') -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($null -eq $uiInv -or $uiInv.error) { Add-Row 'R0' 'R' 'The role UI inventory ran' 'inventory JSON' $(if ($uiInv) { [string]$uiInv.error } else { 'no result (Chrome or Node missing?)' }) 'FAIL' }
        else { Write-Host ('UI inventory written for roles: ' + (($uiInv.roles.PSObject.Properties.Name) -join ', ')) }

        # ---- R-API: what each role actually gets back from the server ---------------------------------------------------------------------------
        $clinRows = @(DbProbe 'clinical')
        $clinStrings = @(); foreach ($c in $clinRows) { foreach ($f in 'diagnosis', 'medication', 'care_notes') { if ($c.$f) { $clinStrings += [string]$c.$f } } }
        $patientNames = @($clinRows | ForEach-Object { [string]$_.name })
        function Leaks([string]$text, [string[]]$needles) { @($needles | Where-Object { $_ -and $text.Contains($_) }) }
        function FlatKeys($o, [string]$prefix = '') {
            $acc = New-Object System.Collections.Generic.List[string]
            if ($o -is [System.Management.Automation.PSCustomObject]) {
                foreach ($p in $o.PSObject.Properties) {
                    $path = if ($prefix) { $prefix + '.' + $p.Name } else { $p.Name }
                    $v = $p.Value
                    if ($v -is [System.Management.Automation.PSCustomObject]) { foreach ($k in @(FlatKeys $v $path)) { $acc.Add($k) } }
                    elseif ($v -is [System.Array]) {
                        if ($v.Count -eq 0) { $acc.Add($path + '[]') }
                        foreach ($el in $v) { if ($el -is [System.Management.Automation.PSCustomObject]) { foreach ($k in @(FlatKeys $el ($path + '[]'))) { $acc.Add($k) } } else { $acc.Add($path + '[]') } }
                    } else { $acc.Add($path) }
                }
            }
            $acc.ToArray() | Sort-Object -Unique
        }
        function Probe($s, [string]$m, [string]$p, $body = $null, [hashtable]$extra = @{}) {
            $x = @{ 'X-StepUp-Pin' = (Pin $s.User) }; foreach ($k in $extra.Keys) { $x[$k] = $extra[$k] }
            $r = Call $m $p $body (Hd $s $x)
            [pscustomobject]@{ Status = $r.Status; Json = $r.Json; Text = $r.Text; Keys = @(FlatKeys $r.Json); Code = $(if ($r.Json -and $r.Json.error) { [string]$r.Json.error } else { '' }) }
        }
        function Surplus([string[]]$actual, [string[]]$allowed) { @($actual | Where-Object { $allowed -notcontains $_ }) }
        function Lost([string[]]$actual, [string[]]$required) { @($required | Where-Object { $actual -notcontains $_ }) }
        function J($a) { (@($a) -join ', ') }
        $LIST = 'patients[].patient_id', 'patients[].name', 'patients[].dob', 'patients[].ward', 'patients[].next_appointment', 'patients[].access_basis'
        $SUMM = 'patient_id', 'name', 'dob', 'ward', 'next_appointment', 'access_basis'

        $sDoc = (Login 'dr_alice').Session; $sNur = (Login 'nurse_bob').Session; $sRec = (Login 'front_carol').Session; $sAdm = (Login 'sec_dan').Session
        $roleSess = [ordered]@{ doctor = $sDoc; nurse = $sNur; receptionist = $sRec; security_admin = $sAdm }
        $surfaces = @(@('session', 'GET', '/ctl/session', $null), @('policy', 'GET', '/ctl/policy', $null), @('public', 'GET', '/api/public/info', $null), @('list', 'GET', '/api/patients/list', $null))
        foreach ($pid_ in 101, 102, 103, 104) { $surfaces += , @("summary_$pid_", 'GET', "/api/patients/$pid_/summary", $null); $surfaces += , @("records_$pid_", 'GET', "/api/patients/$pid_/records", $null); $surfaces += , @("export_$pid_", 'POST', "/api/patients/$pid_/export-pdf", $null) }
        $adminSurf = @(@('admin_summary', 'GET', '/admin/summary', $null), @('admin_sessions', 'GET', '/admin/sessions', $null), @('admin_devices', 'GET', '/admin/devices', $null), @('admin_events', 'GET', '/admin/events?limit=60', $null),
            @('admin_policy', 'GET', '/admin/policy', $null), @('admin_grants', 'GET', '/admin/grants', $null), @('admin_users', 'GET', '/admin/users', $null),
            @('admin_revoke', 'POST', '/admin/sessions/revoke', @{ session_id = 'S-does-not-exist'; reason = 'role review probe' }), @('admin_unlock', 'POST', '/admin/unlock', @{ username = 'nobody-here' }),
            @('admin_policy_set', 'POST', '/admin/policy/set', @{ path = 'bands.allow_below'; value = 40 }), @('admin_grant_revoke', 'POST', '/admin/grants/revoke', @{ grant_id = 'BG-none' }))
        $P = @{}; $apiInv = [ordered]@{}
        foreach ($role in $roleSess.Keys) {
            $apiInv[$role] = [ordered]@{}
            $all = @($surfaces) + @($adminSurf)
            if ($role -ne 'doctor') { $all += , @('breakglass_104', 'POST', '/ctl/break-glass', @{ patient_id = 104; justification = 'Role review probe: what a role without emergency access gets back (synthetic data).' }) }
            foreach ($sf in $all) {
                $pr = Probe $roleSess[$role] $sf[1] $sf[2] $sf[3]
                $P["$role|$($sf[0])"] = $pr
                $apiInv[$role][$sf[0]] = [ordered]@{ call = "$($sf[1]) $($sf[2])"; status = $pr.Status; code = $pr.Code; keys = $pr.Keys }
                if ($sf[0] -eq 'list' -and $pr.Json -and $pr.Json.patients) { $apiInv[$role]['list']['ids'] = (@($pr.Json.patients | ForEach-Object { [string]$_.patient_id }) -join ',') }
            }
        }
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'role_api_inventory.json'), (ConvertTo-Json -InputObject $apiInv -Depth 6))
        $idsOf = { param($pr) (@($pr.Json.patients | ForEach-Object { [string]$_.patient_id }) -join ',') }

        # doctor
        $x = $P['doctor|list']; $ids = & $idsOf $x
        Check 'R1' 'R' 'Doctor: the directory lists only assigned patients and only directory fields' 'ids 101,102; no field beyond id, name, dob, ward, next_appointment, access_basis' ("HTTP {0}; ids {1}; unexpected fields [{2}]" -f $x.Status, $ids, (J (Surplus $x.Keys $LIST))) ($x.Status -eq 200 -and $ids -eq '101,102' -and (Surplus $x.Keys $LIST).Count -eq 0)
        $a = $P['doctor|summary_101']; $b = $P['doctor|summary_103']
        Check 'R2' 'R' 'Doctor: summary of an assigned patient has only demographics; an unassigned patient is refused by the server' '101: 200, fields = demographics; 103: 403 not_assigned' ("101: {0} unexpected [{1}]; 103: {2} {3}" -f $a.Status, (J (Surplus $a.Keys $SUMM)), $b.Status, $b.Code) ($a.Status -eq 200 -and (Surplus $a.Keys $SUMM).Count -eq 0 -and $b.Status -eq 403 -and $b.Code -eq 'not_assigned')
        $a = $P['doctor|records_101']; $b = $P['doctor|records_103']; $want = 'patient_id', 'access_basis', 'diagnosis', 'medication', 'care_notes'
        Check 'R3' 'R' 'Doctor: the clinical record carries the clinical fields and nothing already shown in the summary (no repeated name, date of birth, ward)' '101: 200 with exactly patient_id, access_basis, diagnosis, medication, care_notes; 103: 403' ("101: {0}; unexpected [{1}]; missing [{2}]; 103: {3}" -f $a.Status, (J (Surplus $a.Keys $want)), (J (Lost $a.Keys $want)), $b.Status) ($a.Status -eq 200 -and (Surplus $a.Keys $want).Count -eq 0 -and (Lost $a.Keys $want).Count -eq 0 -and $b.Status -eq 403)
        $a = $P['doctor|export_101']; $b = $P['doctor|export_103']
        Check 'R4' 'R' 'Doctor: the export (the only response with SSN and billing) works for an assigned patient and is refused for an unassigned one' '101: 200 with ssn and billing; 103: 403 not_assigned' ("101: {0} (ssn: {1}, billing: {2}); 103: {3} {4}" -f $a.Status, ($a.Keys -contains 'ssn'), ($a.Keys -contains 'billing'), $b.Status, $b.Code) ($a.Status -eq 200 -and $a.Keys -contains 'ssn' -and $b.Status -eq 403 -and $b.Code -eq 'not_assigned')
        # nurse
        $x = $P['nurse|list']; $ids = & $idsOf $x; $wards = @($x.Json.patients | ForEach-Object { $_.ward } | Sort-Object -Unique) -join ','
        Check 'R5' 'R' 'Nurse: the directory lists only the nurse''s ward (A) and only directory fields' 'ids 101,103,105, ward A only, no extra field' ("HTTP {0}; ids {1}; wards {2}; unexpected [{3}]" -f $x.Status, $ids, $wards, (J (Surplus $x.Keys $LIST))) ($x.Status -eq 200 -and $ids -eq '101,103,105' -and $wards -eq 'A' -and (Surplus $x.Keys $LIST).Count -eq 0)
        $a = $P['nurse|records_101']; $b = $P['nurse|records_102']; $c = $P['nurse|summary_104']; $d = $P['nurse|export_101']; $e = $P['nurse|breakglass_104']; $want = 'patient_id', 'access_basis', 'medication', 'care_notes'
        Check 'R6' 'R' 'Nurse: care record without diagnosis and without repeats; other wards, export and break-glass refused by the server' '101: exactly patient_id, access_basis, medication, care_notes; 102 ward_denied; 104 ward_denied; export role_denied; break-glass role_denied' ("101: {0} unexpected [{1}] missing [{2}]; 102: {3}; 104: {4}; export: {5}; break-glass: {6}" -f $a.Status, (J (Surplus $a.Keys $want)), (J (Lost $a.Keys $want)), $b.Code, $c.Code, $d.Code, $e.Code) ($a.Status -eq 200 -and (Surplus $a.Keys $want).Count -eq 0 -and (Lost $a.Keys $want).Count -eq 0 -and $b.Code -eq 'ward_denied' -and $c.Code -eq 'ward_denied' -and $d.Code -eq 'role_denied' -and $e.Code -eq 'role_denied')
        # receptionist
        $x = $P['receptionist|list']; $ids = & $idsOf $x
        $txt = ($P.Keys | Where-Object { $_ -like 'receptionist|*' } | ForEach-Object { $P[$_].Text }) -join ' '
        $leak = Leaks $txt $clinStrings
        $a = $P['receptionist|records_101']; $b = $P['receptionist|export_101']; $c = $P['receptionist|breakglass_104']; $s1 = $P['receptionist|summary_101']
        Check 'R7' 'R' 'Receptionist: demographics and appointment only; records, export and break-glass refused; no diagnosis, medication or care note anywhere in any response it received' 'list ids 101-105, summary fields = demographics, records/export/break-glass role_denied, 0 clinical values in all responses' ("list ids {0}; unexpected list [{1}]; summary unexpected [{2}]; records {3}; export {4}; break-glass {5}; clinical values found: {6}" -f $ids, (J (Surplus $x.Keys $LIST)), (J (Surplus $s1.Keys $SUMM)), $a.Code, $b.Code, $c.Code, $leak.Count) ($ids -eq '101,102,103,104,105' -and (Surplus $x.Keys $LIST).Count -eq 0 -and (Surplus $s1.Keys $SUMM).Count -eq 0 -and $a.Code -eq 'role_denied' -and $b.Code -eq 'role_denied' -and $c.Code -eq 'role_denied' -and $leak.Count -eq 0)
        # security administrator
        $codes = @('list', 'summary_101', 'records_101', 'export_101', 'breakglass_104') | ForEach-Object { $P["security_admin|$_"].Code }
        Check 'R8' 'R' 'Security administrator: no patient data and no emergency access by default (list, summary, record, export, break-glass)' 'five refusals, all role_denied' ("codes: " + ($codes -join ', ')) (@($codes | Where-Object { $_ -eq 'role_denied' }).Count -eq 5)
        $adminTxt = ($P.Keys | Where-Object { $_ -like 'security_admin|admin_*' -or $_ -eq 'security_admin|session' } | ForEach-Object { $P[$_].Text }) -join ' '
        $evAll = (Call 'GET' '/admin/events?limit=500' $null (Hd $sAdm)).Text
        $adminLeak = @(Leaks ($adminTxt + $evAll) ($clinStrings + $patientNames))
        $secretWords = @(@('pbkdf2', 'password_hash', 'step_up_pin_hash', 'ssn_encrypted', 'billing_encrypted') | Where-Object { ($adminTxt + $evAll).Contains($_) })
        Check 'R9' 'R' 'Security administrator: no patient name, clinical value, credential hash or encrypted identifier in any administration response (sessions, devices, events, grants, users, policy)' '0 hits' ("patient names / clinical values: {0}; credential or encrypted-field words: {1}" -f $adminLeak.Count, $secretWords.Count) ($adminLeak.Count -eq 0 -and $secretWords.Count -eq 0)
        # administration endpoints versus the three clinical roles
        $badAdm = @()
        foreach ($role in 'doctor', 'nurse', 'receptionist') { foreach ($sf in $adminSurf) { $pr = $P["$role|$($sf[0])"]; if ($pr.Code -ne 'role_denied') { $badAdm += "$role $($sf[0]) -> $($pr.Status) $($pr.Code)" } } }
        Check 'R10' 'R' 'Doctor, nurse and receptionist: every administration function (7 reads, 4 changes) is refused by the server' '33 refusals, all role_denied' ("not refused: [{0}]" -f ($badAdm -join '; ')) ($badAdm.Count -eq 0)
        # policy exposure
        $polBad = @()
        foreach ($role in 'doctor', 'nurse', 'receptionist') {
            $pol = $P["$role|policy"]; if ($pol.Code -ne 'role_denied') { $polBad += "$role /ctl/policy -> $($pol.Status)" }
            $leakKeys = @($P["$role|session"].Keys | Where-Object { $_ -match '^policy\.(penalties|device|behavior|login|network|admin)\.' })
            if ($leakKeys.Count -gt 0) { $polBad += "$role /ctl/session carries $($leakKeys.Count) scoring/lockout/network policy fields" }
        }
        Check 'R11' 'R' 'The full risk policy (penalty weights, device scores, login and lockout rules, network rules) is returned to the security administrator only, not to clinical roles' 'clinical roles: /ctl/policy refused and no scoring fields in /ctl/session' ("problems: [{0}]" -f ($polBad -join '; ')) ($polBad.Count -eq 0)
        # unauthenticated / remote surface
        $edgeHdr = @{ 'X-Edge-Key' = $sec.edgeKey; 'X-Forwarded-For' = '203.0.113.9' }
        $ag = Call 'GET' '/ctl/agents' $null $edgeHdr
        $agLocal = Call 'GET' '/ctl/agents' $null @{ 'X-Edge-Key' = $sec.edgeKey; 'X-Forwarded-For' = '127.0.0.1' }
        $nt = Call 'GET' '/api/patients/list' $null @{}
        $noTokKeys = @(FlatKeys $nt.Json)
        $leakedPolicy = @($noTokKeys | Where-Object { $_ -in 'revoke_threshold', 'risk_score', 'session_risk', 'detail' })
        Check 'R12' 'R' 'Before sign-in: a remote client learns nothing about the laptop (agent list is empty for non-local addresses) and nothing about policy thresholds in error bodies' 'remote agents = 0, local agents >= 1, unauthenticated error body without thresholds or scores' ("remote agents {0}; local agents {1}; unauthenticated body fields: {2}; threshold/score fields present: [{3}]" -f @($ag.Json.agents).Count, @($agLocal.Json.agents).Count, ($noTokKeys -join ','), (J $leakedPolicy)) (@($ag.Json.agents).Count -eq 0 -and @($agLocal.Json.agents).Count -ge 1 -and $leakedPolicy.Count -eq 0)
        # lock state must not be readable without the password
        $lockUser = 'front_carol'; $ipL = '10.77.0.9'
        try {
            for ($i = 0; $i -lt 5; $i++) { $null = Login $lockUser $hostDevice 'agent' $ipL 'wrong-password-for-the-review' }
            $wrongPw = Login $lockUser $hostDevice 'agent' $ipL 'wrong-password-for-the-review'
            $rightPw = Login $lockUser $hostDevice 'agent' $ipL
            Check 'R13' 'R' 'A locked account does not announce itself (or why) to someone who does not know the password; the owner with the right password is told' 'wrong password: 401 invalid_credentials without lock details; right password: 423 account_locked' ("wrong password: {0} {1}; right password: {2} {3}" -f $wrongPw.Status, $wrongPw.Json.error, $rightPw.Status, $rightPw.Json.error) ($wrongPw.Status -eq 401 -and $wrongPw.Json.error -eq 'invalid_credentials' -and -not $wrongPw.Json.locked_until -and $rightPw.Status -eq 423)
        } finally { $null = Call 'POST' '/admin/unlock' @{ username = $lockUser } (Hd $sAdm) }

        # ---- R-TAMPER: restricted fields and actions through the front door ---------------------------------------------------------------------
        $tq = '?fields=ssn,billing', '?include=diagnosis', '?expand=all', '?view=full', '?role=doctor', '?admin=1', '?debug=true', '?patient_id=102', '?ssn=1'
        $th = @(@{ 'X-ZT-Role' = 'doctor' }, @{ 'X-ZT-User' = 'dr_alice' }, @{ 'X-ZT-Ward' = 'B' }, @{ 'X-ZT-Basis' = 'break_glass' }, @{ 'X-Role' = 'security_admin' }, @{ 'X-User' = 'sec_dan' }, @{ 'X-Forwarded-User' = 'dr_alice' }, @{ 'X-Original-URL' = '/admin/summary' }, @{ 'X-HTTP-Method-Override' = 'POST' })
        $tamperBad = @()
        foreach ($role in 'doctor', 'nurse', 'receptionist', 'security_admin') {
            $base = $P["$role|records_101"]
            foreach ($q in $tq) { $t = Probe $roleSess[$role] 'GET' ('/api/patients/101/records' + $q); if ($t.Status -ne $base.Status -or (($t.Keys -join ',') -ne ($base.Keys -join ','))) { $tamperBad += "$role records$q -> $($t.Status)" } }
            foreach ($h in $th) { $t = Probe $roleSess[$role] 'GET' '/api/patients/101/records' $null $h; if ($t.Status -ne $base.Status -or (($t.Keys -join ',') -ne ($base.Keys -join ','))) { $tamperBad += "$role records +$(@($h.Keys)[0]) -> $($t.Status)" } }
            $t = Raw '/api/patients/101/records' (Hd $roleSess[$role] @{ 'X-StepUp-Pin' = (Pin $roleSess[$role].User) }) 'GET' '{"role":"doctor","fields":"ssn","patient_id":102}'; if ($t.Status -ne $base.Status) { $tamperBad += "$role records with a JSON body -> $($t.Status)" }
        }
        Check 'R14' 'R' 'Asking for more: field-selection parameters (fields, include, expand, view), role/user claims in the query, body or headers (X-ZT-Role, X-Role, X-User, ...) change nothing for any role' 'every variant returns exactly what the plain request returns (same status, same fields)' ("{0} role/variant combinations; different from the plain request: [{1}]" -f (4 * ($tq.Count + $th.Count + 1)), ($tamperBad -join '; ')) ($tamperBad.Count -eq 0)
        $variants = @(@('POST', '/api/patients/101/records'), @('GET', '/api/patients/101/export-pdf'), @('PUT', '/api/patients/101/summary'), @('DELETE', '/api/patients/101/summary'), @('GET', '/api/patients/101/records/'), @('GET', '//api/patients/101/records'),
            @('GET', '/api/patients/101//records'), @('GET', '/API/PATIENTS/101/RECORDS'), @('GET', '/api/patients/101/records%00'), @('GET', '/api/patients/101/records;x=1'), @('GET', '/api/patients/%31%30%31/records'), @('GET', '/api/patients/101/../102/records'),
            @('GET', '/api/patients/0101/records'), @('GET', '/api/patients/+101/records'), @('GET', '/api/patients/101.0/records'), @('GET', '/api/patients/-1/records'), @('GET', '/api/patients/99999999999/records'), @('GET', '/api/patients/101/records?x=%0d%0aX-ZT-Role:doctor'))
        $pathBad = @()
        foreach ($role in 'doctor', 'nurse', 'receptionist', 'security_admin') {
            foreach ($v in $variants) {
                $r = Raw $v[1] (Hd $roleSess[$role]) $v[0]
                $served = $null; if ($r.Json -and $r.Json.patient_id) { $served = [int]$r.Json.patient_id }
                $isClinical = ($r.Status -eq 200 -and $r.Json -and ($r.Json.PSObject.Properties.Name -contains 'diagnosis' -or $r.Json.PSObject.Properties.Name -contains 'medication' -or $r.Json.PSObject.Properties.Name -contains 'ssn'))
                if ($role -in 'receptionist', 'security_admin' -and $r.Status -eq 200 -and $isClinical) { $pathBad += "$role $($v[0]) $($v[1]) -> clinical data" }
                if ($role -eq 'nurse' -and $isClinical -and $served -ne 101) { $pathBad += "$role $($v[0]) $($v[1]) -> patient $served" }
                if ($role -eq 'doctor' -and $isClinical -and $served -ne 101) { $pathBad += "$role $($v[0]) $($v[1]) -> patient $served" }
                if ($r.Status -eq 200 -and ($v[0] -in 'PUT', 'DELETE', 'POST' -and $v[1] -like '*summary')) { $pathBad += "$role $($v[0]) $($v[1]) -> 200" }
            }
        }
        Check 'R15' 'R' 'Verb and path tricks (wrong method, trailing or doubled slashes, case, encodings, dot segments, header injection) never return clinical data to the receptionist or administrator and never return a different patient to the doctor or nurse' 'no violation' ("{0} requests; violations: [{1}]" -f (4 * $variants.Count), ($pathBad -join '; ')) ($pathBad.Count -eq 0)
        $none = @('records_102', 'records_103', 'summary_104') | ForEach-Object { $P["doctor|$_"].Status }
        Check 'R16' 'R' 'Assignment and ward are decided by the server: the same signed-in doctor/nurse gets 200 for the permitted patient and 403 for the others on the very same call' 'doctor: 101,102 allowed, 103,104 refused; nurse: 101,103 allowed, 102,104 refused' ("doctor: {0}/{1}/{2}/{3}; nurse: {4}/{5}/{6}/{7}" -f $P['doctor|summary_101'].Status, $P['doctor|summary_102'].Status, $P['doctor|summary_103'].Status, $P['doctor|summary_104'].Status, $P['nurse|summary_101'].Status, $P['nurse|summary_102'].Status, $P['nurse|summary_103'].Status, $P['nurse|summary_104'].Status) ($P['doctor|summary_101'].Status -eq 200 -and $P['doctor|summary_102'].Status -eq 200 -and $P['doctor|summary_103'].Status -eq 403 -and $P['doctor|summary_104'].Status -eq 403 -and $P['nurse|summary_101'].Status -eq 200 -and $P['nurse|summary_103'].Status -eq 200 -and $P['nurse|summary_102'].Status -eq 403 -and $P['nurse|summary_104'].Status -eq 403)
        $ex = (Probe $sDoc 'GET' '/api/patients/999/summary'); $ex2 = (Probe $sDoc 'GET' '/api/patients/103/summary')
        $exN = (Probe $sNur 'GET' '/api/patients/999/summary'); $exN2 = (Probe $sNur 'GET' '/api/patients/102/summary')
        Check 'R17' 'R' 'A doctor or nurse cannot tell an existing patient id from a missing one: a missing number gets the same status, code and text as a patient who is not assigned (doctor) or on another ward (nurse); only the front desk, which works with the whole directory, is told "no such patient" (group X checks penalty and audit record as well)' 'doctor: 999 and 103 -> 403 not_assigned, same text; nurse: 999 and 102 -> 403 ward_denied, same text' ("doctor 999 -> {0} {1}; 103 -> {2} {3}; nurse 999 -> {4} {5}; 102 -> {6} {7}" -f $ex.Status, $ex.Code, $ex2.Status, $ex2.Code, $exN.Status, $exN.Code, $exN2.Status, $exN2.Code) ($ex.Status -eq 403 -and $ex.Code -eq 'not_assigned' -and $ex2.Status -eq 403 -and $ex.Json.message -eq $ex2.Json.message -and $exN.Status -eq 403 -and $exN.Code -eq 'ward_denied' -and $exN2.Status -eq 403 -and $exN.Json.message -eq $exN2.Json.message)
        # database: the permission table is the specification
        $perm = @(DbProbe 'permissions')
        $permBad = @()
        foreach ($rp in $perm) { if ($rp.role -eq 'security_admin' -and $rp.path -like '/api/patients/*') { $permBad += 'security_admin has ' + $rp.path }
            if ($rp.role -eq 'receptionist' -and ($rp.path -like '*records' -or $rp.path -like '*export-pdf' -or $rp.path -like '*break-glass')) { $permBad += 'receptionist has ' + $rp.path }
            if ($rp.role -eq 'nurse' -and ($rp.path -like '*export-pdf' -or $rp.path -like '*break-glass')) { $permBad += 'nurse has ' + $rp.path }
            if ($rp.role -ne 'security_admin' -and $rp.path -like '/admin/*') { $permBad += $rp.role + ' has ' + $rp.path }
            if ($rp.path -eq '/ctl/policy' -and $rp.role -ne 'security_admin') { $permBad += $rp.role + ' has /ctl/policy' }
            if ($rp.path -like '*appointment' -and $rp.role -ne 'receptionist') { $permBad += $rp.role + ' has ' + $rp.path } }
        if (-not (@($perm | Where-Object { $_.role -eq 'receptionist' -and $_.path -like '*appointment' }).Count -ge 1)) { $permBad += 'receptionist lacks the appointment permission' }
        Check 'R18' 'R' 'Database role_permissions table: no clinical endpoint for the administrator, no records/export/emergency for the receptionist, no export/emergency for the nurse, no administration for anyone else, /ctl/policy for the administrator only, appointment changes for the receptionist only' 'no violation' ("{0} permission rows; violations: [{1}]" -f $perm.Count, ($permBad -join '; ')) ($permBad.Count -eq 0)

        $clinCols = 'diagnosis|medication|care_notes|ssn_encrypted|billing_encrypted'
        $hits = @(); foreach ($root in @((Join-Path $repo 'pdp\src'), (Join-Path $repo 'protected_app\src'))) { foreach ($f in Get-ChildItem $root -Recurse -Filter '*.java' -File) { if (Select-String -LiteralPath $f.FullName -Pattern $clinCols -Quiet) { $hits += $f.FullName.Substring($repo.Length + 1) } } }
        $allowedFiles = @('protected_app\src\app\http\handlers\PatientDetailHandler.java', 'protected_app\src\app\seed\PatientSeeder.java')
        $unexpectedFiles = @($hits | Where-Object { $allowedFiles -notcontains $_ })
        Check 'R19' 'R' 'Database access (static check of the sources): only the protected app''s patient-detail handler and its seeder name a clinical or encrypted column; the PDP (decisions, administration, events) and the directory query never touch them' 'no other source file mentions diagnosis, medication, care_notes, ssn_encrypted or billing_encrypted' ("files that mention them: [{0}]; unexpected: [{1}]" -f ($hits -join ', '), ($unexpectedFiles -join ', ')) ($unexpectedFiles.Count -eq 0)

        # ---- BG: emergency (break-glass) access: patient scope, permitted actions, duration, session binding, input validation -------------------------
        $bgKeepDuration = [int](Call 'GET' '/admin/policy' $null (Hd $sAdm)).Json.policy.break_glass.duration_seconds
        function GrantIds { @((Call 'GET' '/admin/grants' $null (Hd $sAdm)).Json.grants | ForEach-Object { [string]$_.grant_id }) }
        $just = 'Role review: emergency access test for a synthetic patient (not a real emergency).'
        $d1 = (Login 'dr_alice' 'BGTEST-0001' 'browser' '10.50.0.1').Session
        $g1 = Probe $d1 'POST' '/ctl/break-glass' @{ patient_id = 104; justification = $just }
        $apiInv['doctor']['breakglass_granted'] = [ordered]@{ call = 'POST /ctl/break-glass'; status = $g1.Status; code = $g1.Code; keys = $g1.Keys }
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'role_api_inventory.json'), (ConvertTo-Json -InputObject $apiInv -Depth 6))
        $s104 = Probe $d1 'GET' '/api/patients/104/summary'; $r104 = Probe $d1 'GET' '/api/patients/104/records'
        $o105 = Probe $d1 'GET' '/api/patients/105/records'; $o103 = Probe $d1 'GET' '/api/patients/103/summary'
        Check 'BG1' 'BG' 'Emergency access covers exactly the patient it was granted for: that patient''s summary and record are readable (basis "break_glass"); other unassigned patients stay refused' 'grant 200; 104 summary and records 200; 105 and 103 refused (not_assigned)' ("grant {0}; 104: {1}/{2} basis {3}; 105: {4} {5}; 103: {6} {7}" -f $g1.Status, $s104.Status, $r104.Status, $r104.Json.access_basis, $o105.Status, $o105.Code, $o103.Status, $o103.Code) ($g1.Status -eq 200 -and $s104.Status -eq 200 -and $r104.Status -eq 200 -and $r104.Json.access_basis -eq 'break_glass' -and $o105.Code -eq 'not_assigned' -and $o103.Code -eq 'not_assigned')
        $e104 = Probe $d1 'POST' '/api/patients/104/export-pdf'
        Check 'BG2' 'BG' 'Emergency access does not include the export (the only response that decrypts SSN and billing): reading the record is permitted, exporting is not' 'export of the emergency patient refused (403)' ("export: HTTP {0} {1} (ssn in response: {2})" -f $e104.Status, $e104.Code, ($e104.Keys -contains 'ssn')) ($e104.Status -eq 403 -and $e104.Keys -notcontains 'ssn')
        $g2 = Probe $d1 'POST' '/ctl/break-glass' @{ patient_id = 105; justification = $just; duration_seconds = 86400; expires_ts = 4102444800; seconds = 86400 }
        $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Check 'BG3' 'BG' 'The duration of emergency access is the server''s policy value; duration or expiry fields sent by the client are ignored' ("both grants last exactly the policy duration ({0} s), whatever the client sent" -f $bgKeepDuration) ("grant 1: {0} s; grant 2 (client asked for 86400 s): {1} s, expires in {2} s" -f $g1.Json.seconds, $g2.Json.seconds, ([int64]$g2.Json.expires_ts - $nowTs)) ($g1.Json.seconds -eq $bgKeepDuration -and $g2.Json.seconds -eq $bgKeepDuration -and ([int64]$g2.Json.expires_ts - $nowTs) -le ($bgKeepDuration + 5))

        # the protected app on its own (defence in depth), while d1 still holds its grant
        $apRows = $null
        if ($nodeR) {
            $usersRows = @(DbProbe 'users')
            $userArr = @($usersRows | ForEach-Object { @{ user_id = $_.user_id; username = $_.username; role = $_.role; ward = $_.ward } })
            $envAp = @{ ZT_APP_URL = 'https://127.0.0.1:9000'; ZT_PEP_APP_SECRET = $sec.pepAppSecret; ZT_APP_CERT = (Join-Path $RunDir 'certs\app.cer'); ZT_USERS = (ConvertTo-Json -Compress -InputObject $userArr); ZT_BG_SESSION = $d1.SessionId; ZT_BG_PATIENT = '104'; ZT_CLIN = (ConvertTo-Json -Compress -InputObject @($clinStrings)) }
            $savedAp = @{}
            foreach ($k in $envAp.Keys) { $savedAp[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $envAp[$k], 'Process') }
            try { $ar = RunTool $nodeR @((Join-Path $PSScriptRoot 'app_direct.mjs')) } finally { foreach ($k in $envAp.Keys) { [Environment]::SetEnvironmentVariable($k, $savedAp[$k], 'Process') } }
            $al = @($ar.Output -split "`n" | Where-Object { $_ -like 'RESULT_JSON:*' })
            if ($al.Count -gt 0) { $apRows = ConvertFrom-Json -InputObject ($al[0] -replace '^RESULT_JSON:', ''); foreach ($x in $apRows) { Check $x.id 'AP' $x.title $x.expected $x.actual ($x.ok -eq $true) } }
            else { Add-Row 'AP0' 'AP' 'The direct protected-app test ran' 'RESULT_JSON line' ('no result: ' + (($ar.Output -split "`n" | Select-Object -Last 3) -join ' | ')) 'FAIL' }
        }

        # emergency access belongs to the session that asked for it
        $d2 = (Login 'dr_alice' 'BGTEST-0002' 'browser' '10.50.0.2').Session
        $x2 = Probe $d2 'GET' '/api/patients/104/records'
        $null = Call 'POST' '/ctl/logout' $null (Hd $d1)
        $d3 = (Login 'dr_alice' 'BGTEST-0003' 'browser' '10.50.0.3').Session
        $x3 = Probe $d3 'GET' '/api/patients/104/records'
        Check 'BG4' 'BG' 'Emergency access is tied to the session that requested it: another session of the same doctor, and a new session after the first one ended, do not inherit it' 'both refused (not_assigned)' ("other session: {0} {1}; after the creating session ended: {2} {3}" -f $x2.Status, $x2.Code, $x3.Status, $x3.Code) ($x2.Status -eq 403 -and $x2.Code -eq 'not_assigned' -and $x3.Status -eq 403 -and $x3.Code -eq 'not_assigned')

        # input validation: no grant may come out of a malformed or inflated request
        $d4 = (Login 'dr_alice' 'BGTEST-0004' 'browser' '10.50.0.4').Session
        $before = @(GrantIds)
        $jt = '"justification":"' + $just + '"'
        $bodies = [ordered]@{ 'wrapped integer 4294967399' = ('{"patient_id":4294967399,' + $jt + '}'); 'fraction 103.5' = ('{"patient_id":103.5,' + $jt + '}'); 'text "103"' = ('{"patient_id":"103",' + $jt + '}'); 'negative' = ('{"patient_id":-1,' + $jt + '}'); 'zero' = ('{"patient_id":0,' + $jt + '}')
            'null' = ('{"patient_id":null,' + $jt + '}'); 'array' = ('{"patient_id":[103],' + $jt + '}'); 'missing' = ('{' + $jt + '}'); 'eleven digits' = ('{"patient_id":99999999999,' + $jt + '}'); 'unknown patient 999' = ('{"patient_id":999,' + $jt + '}')
            'justification 5 chars' = '{"patient_id":103,"justification":"short"}'; 'justification 501 chars' = ('{"patient_id":103,"justification":"' + ('x' * 501) + '"}') }
        $accepted = @()
        foreach ($k in $bodies.Keys) { $r = Call 'POST' '/ctl/break-glass' $bodies[$k] (Hd $d4 @{ 'X-StepUp-Pin' = (Pin 'dr_alice') }); if ($r.Status -eq 200) { $accepted += $k } }
        $after = @(GrantIds)
        Check 'BG5' 'BG' 'Malformed or inflated emergency requests (wrapped or fractional ids, text, negative, null, array, unknown patient, too short or too long a justification) never create a grant' '12 refusals, no new grant' ("accepted: [{0}]; new grants: {1}" -f ($accepted -join '; '), @($after | Where-Object { $before -notcontains $_ }).Count) ($accepted.Count -eq 0 -and @($after | Where-Object { $before -notcontains $_ }).Count -eq 0)

        # the approved duration really ends the access (start from no emergency grants at all)
        foreach ($g in @((Call 'GET' '/admin/grants' $null (Hd $sAdm)).Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $sAdm @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) }
        try {
            $null = Set-Policy $sAdm 'break_glass.duration_seconds' 5
            $d5 = (Login 'dr_alice' 'BGTEST-0005' 'browser' '10.50.0.5').Session
            $g5 = Probe $d5 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = $just }
            $in5 = Probe $d5 'GET' '/api/patients/103/records'
            Start-Sleep -Seconds 7
            $out5 = Probe $d5 'GET' '/api/patients/103/records'
            Check 'BG6' 'BG' 'Emergency access ends when the approved time ends (duration set to 5 s for this test)' 'grant 200 (5 s), record readable inside the window, refused (not_assigned) after it' ("grant {0} ({1} s); inside: {2}; after 7 s: {3} {4}" -f $g5.Status, $g5.Json.seconds, $in5.Status, $out5.Status, $out5.Code) ($g5.Status -eq 200 -and $g5.Json.seconds -eq 5 -and $in5.Status -eq 200 -and $out5.Status -eq 403 -and $out5.Code -eq 'not_assigned')
        } finally { $null = Set-Policy $sAdm 'break_glass.duration_seconds' $bgKeepDuration }
        foreach ($g in @((Call 'GET' '/admin/grants' $null (Hd $sAdm)).Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $sAdm @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) }
        foreach ($sx in $d2, $d3, $d4, $d5) { if ($sx) { $null = Call 'POST' '/ctl/logout' $null (Hd $sx) } }

        # ---- UI: assertions on what each page actually showed ----------------------------------------------------------------------------------
        if ($uiInv -and -not $uiInv.error) {
            function UiText($roleObj, [string[]]$tabs, [bool]$withDetails = $true, [bool]$labelsOnly = $false) {
                $parts = New-Object System.Collections.Generic.List[string]
                $fields = if ($labelsOnly) { @('headings', 'buttons', 'inputs', 'tableHeaders', 'kvLabels', 'stats', 'badges') } else { @('headings', 'buttons', 'inputs', 'tableHeaders', 'kvLabels', 'stats', 'badges', 'banners', 'listItems') }
                $collect = { param($v) foreach ($f in $fields) { foreach ($s in @($v.$f)) { $parts.Add([string]$s) } }; if (-not $labelsOnly) { $parts.Add([string]$v.sampleText); $parts.Add([string]$v.fullText) } }
                foreach ($t in $tabs) { $tv = $roleObj.tabs.PSObject.Properties[$t]; if ($tv) { & $collect $tv.Value } }
                if ($withDetails) { foreach ($d in $roleObj.details.PSObject.Properties) { & $collect $d.Value }; foreach ($m in $roleObj.modals.PSObject.Properties) { & $collect $m.Value } }
                $parts -join ' | '
            }
            $ui = $uiInv.roles
            $recepViews = @('Patient registry', 'Appointments')
            $rt = UiText $ui.front_carol $recepViews $true
            $rl = UiText $ui.front_carol $recepViews $true $true
            $bad = @([regex]::Matches($rl, 'Diagnosis|Medication|Care notes|Export|emergency|break-glass|Try to read|Clinical', 'IgnoreCase') | ForEach-Object { $_.Value } | Sort-Object -Unique) + @(Leaks $rt $clinStrings)
            $recepNav = @($ui.front_carol.tabs.PSObject.Properties.Name)
            $recepAppt = @($ui.front_carol.tabs.'Appointments'.buttons | Where-Object { $_ -like 'Reschedule*' }).Count
            Check 'UI1' 'UI' 'Receptionist screens (registry, appointments, every patient view and the reschedule dialog): demographics and appointments only; no clinical heading, field, button, navigation item or value, no emergency or export control' 'navigation = Patient registry | Appointments; none of: Diagnosis, Medication, Care notes, Export, emergency, break-glass, Clinical, clinical values; Reschedule buttons present' ("navigation: [{0}]; reschedule buttons: {1}; found: [{2}]" -f ($recepNav -join ' | '), $recepAppt, ($bad -join ', ')) ((($recepNav -join '|') -eq ($recepViews -join '|')) -and $recepAppt -ge 1 -and $bad.Count -eq 0)
            $nt = UiText $ui.nurse_bob @('Ward patients') $true
            $nl = UiText $ui.nurse_bob @('Ward patients') $true $true
            $nbad = @([regex]::Matches($nl, 'Diagnosis|Export|emergency|break-glass', 'IgnoreCase') | ForEach-Object { $_.Value } | Sort-Object -Unique) + @(Leaks $nt @($clinRows | ForEach-Object { [string]$_.diagnosis }))
            $nneed = @(@('Medication', 'Care notes') | Where-Object { $nt -notmatch $_ })
            Check 'UI2' 'UI' 'Nurse screens: medication and care notes shown, no diagnosis, no export, no emergency-access control; patients of other wards show a refusal' 'no Diagnosis/Export/emergency; Medication and Care notes present; "not on your ward" refusal shown' ("forbidden found: [{0}]; missing: [{1}]; ward refusal shown: {2}" -f ($nbad -join ', '), ($nneed -join ', '), ($nt -match 'not on your ward')) ($nbad.Count -eq 0 -and $nneed.Count -eq 0 -and $nt -match 'not on your ward')
            $dl = ($ui.dr_alice.details.PSObject.Properties | Where-Object { $_.Name -like 'listed *' } | ForEach-Object { UiText ([pscustomobject]@{ tabs = [pscustomobject]@{}; details = [pscustomobject]@{ x = $_.Value }; modals = [pscustomobject]@{} }) @() $true }) -join ' | '
            $du = ($ui.dr_alice.details.PSObject.Properties | Where-Object { $_.Name -like 'unlisted *' } | ForEach-Object { UiText ([pscustomobject]@{ tabs = [pscustomobject]@{}; details = [pscustomobject]@{ x = $_.Value }; modals = [pscustomobject]@{} }) @() $true }) -join ' | '
            Check 'UI3' 'UI' 'Doctor screens: assigned patients show diagnosis, medication, care notes and export; an unassigned patient shows only the refusal and the emergency-access option, with no clinical field' 'listed: Diagnosis, Medication, Care notes, Export present, no emergency button; unlisted: "Request emergency" present, no Diagnosis/Medication/Care notes' ("listed has clinical+export: {0}, emergency button: {1}; unlisted has emergency: {2}, clinical fields: {3}" -f (($dl -match 'Diagnosis') -and ($dl -match 'Medication') -and ($dl -match 'Care notes') -and ($dl -match 'Export clinical summary')), ($dl -match 'Request emergency'), ($du -match 'Request emergency'), ($du -match 'Diagnosis|Medication|Care notes')) (($dl -match 'Diagnosis') -and ($dl -match 'Medication') -and ($dl -match 'Care notes') -and ($dl -match 'Export clinical summary') -and ($dl -notmatch 'Request emergency') -and ($du -match 'Request emergency') -and ($du -notmatch 'Diagnosis|Medication|Care notes'))
            $adminViews = @('Overview', 'Sessions', 'Devices & posture', 'Access decisions', 'Audit log', 'Users & access', 'Policy', 'My session')
            $at = UiText $ui.sec_dan $adminViews $true
            $adminTabs = @($ui.sec_dan.tabs.PSObject.Properties.Name)
            $aleak = @(Leaks $at ($clinStrings + $patientNames))
            $patNav = @($adminTabs | Where-Object { $_ -match 'patient|record|clinical' })
            $polUnderSession = [bool]($ui.sec_dan.tabs.'My session'.headings -match 'olicy')
            Check 'UI4' 'UI' 'Security administrator screens: only the eight security screens, no patient or clinical navigation item, no patient name or clinical value on any screen, and the policy is shown once (Policy), not repeated under My session' 'navigation = Overview | Sessions | Devices & posture | Access decisions | Audit log | Users & access | Policy | My session; 0 patient names/clinical values; no policy card under My session' ("navigation: [{0}]; patient/clinical navigation: {1}; patient names/clinical values: {2}; policy card under My session: {3}" -f ($adminTabs -join ' | '), $patNav.Count, $aleak.Count, $polUnderSession) ((($adminTabs -join '|') -eq ($adminViews -join '|')) -and $patNav.Count -eq 0 -and $aleak.Count -eq 0 -and -not $polUnderSession)
            $pbad = @()
            foreach ($u in 'dr_alice', 'nurse_bob', 'front_carol') {
                $hdr = @($ui.$u.header)
                if ($hdr.Count -ne 2) { $pbad += "$u shows $($hdr.Count - 2) status chip(s) in the top bar" }
                $everything = UiText $ui.$u @($ui.$u.tabs.PSObject.Properties.Name) $true
                foreach ($cs in $clinStrings) { if ($cs) { $everything = $everything.Replace($cs, ' ') } }
                $found = @([regex]::Matches($everything, 'Risk|Posture|Healthy|Degraded|Network|Technical detail|Reference:|Demonstration|Session & access|threshold|penalt|score|heartbeat|firewall|antivirus', 'IgnoreCase') | ForEach-Object { $_.Value.ToLower() } | Sort-Object -Unique)
                if ($found.Count -gt 0) { $pbad += "$u shows [$($found -join ', ')]" }
                if ($u -ne 'dr_alice' -and $everything -match 'mergency|break-glass') { $pbad += "$u shows emergency access (not available to this role)" }
            }
            Check 'UI5' 'UI' 'Clinical roles have no security monitoring in their workspace: no status chips in the top bar and no session, device, risk, network, threshold, policy or technical-detail wording on any screen, patient view or dialog (their session details live in the account menu, see RU12); emergency access is mentioned for the doctor only' 'no chips; none of the security words on any clinical screen' ("problems: [{0}]" -f ($pbad -join '; ')) ($pbad.Count -eq 0)
            $lv = [string]$ui.dr_alice.loginView.sampleText
            Check 'UI6' 'UI' 'Sign-in screen: the demo hints do not reveal which patients or wards a role is assigned to' 'no patient ids or ward names on the sign-in screen' ("patient ids / ward on the page: {0}" -f ($lv -match '10[1-5]|ward [A-C]')) ($lv -notmatch '10[1-5]|ward [A-C]')
            $cn = [string]$env:COMPUTERNAME
            $idBad = @()
            foreach ($u in 'dr_alice', 'nurse_bob', 'front_carol', 'sec_dan') {
                $everything = UiText $ui.$u @($ui.$u.tabs.PSObject.Properties.Name) $true
                if ($cn -and $everything.IndexOf($cn, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $idBad += "$u screens show the computer name" }
                if ($u -ne 'sec_dan' -and $everything -match 'dr_alice|nurse_bob|front_carol|sec_dan') { $idBad += "$u screens show an account name" }
                if ($everything -match 'pbkdf2|password_hash|step_up_pin_hash|Bearer ') { $idBad += "$u screens show credential material" }
                if ($everything -match '\b(DEV|WEB|PHONE)-[A-Za-z0-9]') { $idBad += "$u screens show a raw device identifier" }
            }
            Check 'UI7' 'UI' 'No screen of any role shows the computer name, a raw device identifier, an account name (other than to the security administrator) or credential material' 'none found in any role''s screens, dialogs or patient views' ("problems: [{0}]" -f ($idBad -join '; ')) ($idBad.Count -eq 0)
        }
    } finally {
        $a2 = (Login 'sec_dan').Session
        if ($a2) { $null = Set-Policy $a2 'session.revoke_threshold' $keepThreshold; $null = Set-Policy $a2 'behavior.burst_limit' $keepBurst; $null = Call 'POST' '/ctl/logout' $null (Hd $a2) }
    }
}

# =============================== W: the installable web app inside a real browser engine ============================================
if ($run_W) {
    Write-Host '--- W: browser-level checks (desktop Chrome, headless, throw-away profile and throw-away edge)'
    $chromeExe = Find-Exe @((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'))
    $nodeExe2 = Find-Exe @('C:\Program Files\nodejs\node.exe')
    $javaExe = Join-Path $runInfo.jdkBin 'java.exe'
    if (-not $chromeExe -or -not $nodeExe2) { NotRun 'W0' 'W' 'Browser-level checks of the web app' 'run in Chrome' 'Chrome or Node.js is not installed on this machine' }
    else {
        $testHttp = 8081; $testHttps = 9444
        $envSet = @{
            ZT_TEST_CHROME = $chromeExe; ZT_TEST_JAVA = $javaExe; ZT_TEST_EDGE_CP = (Join-Path $RunDir 'build\java\edge'); ZT_TEST_BASE = "http://127.0.0.1:$testHttp"
            ZT_TEST_PROFILE = (Join-Path $RunDir 'chrome-profile'); ZT_TEST_USER = 'dr_alice'; ZT_TEST_PASS = $creds['dr_alice'].Password; ZT_TEST_PATIENT_DENIED = '105'
            ZT_EDGE_KEYSTORE = (Join-Path $RunDir 'certs\edge.p12'); ZT_EDGE_KEYSTORE_PASSWORD = $sec.edgeKsPass; ZT_EDGE_WEB = (Join-Path $repo 'web'); ZT_EDGE_KEY = $sec.edgeKey
            ZT_EDGE_PEP = 'http://127.0.0.1:5000'; ZT_EDGE_HTTPS_BIND = '127.0.0.1'; ZT_EDGE_HTTPS_PORT = [string]$testHttps; ZT_EDGE_HTTP_PORT = [string]$testHttp
        }
        $savedEnv = @{}
        foreach ($k in $envSet.Keys) { $savedEnv[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $envSet[$k], 'Process') }
        try { $wr = RunTool $nodeExe2 @((Join-Path $PSScriptRoot 'pwa_check.mjs')) }
        finally { foreach ($k in $envSet.Keys) { [Environment]::SetEnvironmentVariable($k, $savedEnv[$k], 'Process') } }
        $jl = @($wr.Output -split "`n" | Where-Object { $_ -like 'RESULT_JSON:*' })
        if ($jl.Count -eq 0) { Add-Row 'W0' 'W' 'The browser check ran and reported results' 'RESULT_JSON line' ("no result; output: " + (($wr.Output -split "`n" | Select-Object -Last 4) -join ' | ')) 'FAIL' }
        else {
            $parsed = ConvertFrom-Json -InputObject ($jl[0] -replace '^RESULT_JSON:', '')   # PowerShell 5.1 returns a JSON array as one object: iterate it with foreach, never wrap it in @()
            foreach ($x in $parsed) { Check $x.id 'W' $x.title $x.expected $x.actual ($x.ok -eq $true) }
        }
        Remove-Item -LiteralPath (Join-Path $RunDir 'chrome-profile') -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =============================== L: the public sign-in screen and the four role sign-ins (real Chrome) ===============================
if ($run_L) {
    Write-Host '--- L: sign-in screen and the four role sign-ins (desktop Chrome, headless, throw-away profile)'
    $chromeL = Find-Exe @((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'))
    $nodeL = Find-Exe @('C:\Program Files\nodejs\node.exe')
    if (-not $chromeL -or -not $nodeL) { NotRun 'L0' 'L' 'Sign-in screen checks in Chrome' 'run in Chrome' 'Chrome or Node.js is not installed on this machine' }
    else {
        $credL = ConvertTo-Json -Compress -InputObject (@{ dr_alice = $creds['dr_alice'].Password; nurse_bob = $creds['nurse_bob'].Password; front_carol = $creds['front_carol'].Password; sec_dan = $creds['sec_dan'].Password })
        $envL = @{ ZT_TEST_CHROME = $chromeL; ZT_TEST_HTTP = $edgeHttp; ZT_TEST_HTTPS = ('https://localhost:' + $edgeHttpsPort); ZT_EDGE_CERT = (Join-Path $RunDir 'certs\edge.crt'); ZT_TEST_PROFILE = (Join-Path $RunDir 'chrome-profile-login'); ZT_ROLE_CREDS = $credL; ZT_COMPUTERNAME = $env:COMPUTERNAME }
        $savedL = @{}
        foreach ($k in $envL.Keys) { $savedL[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, $envL[$k], 'Process') }
        try { $lr = RunTool $nodeL @((Join-Path $PSScriptRoot 'login_ui_check.mjs')) } finally { foreach ($k in $envL.Keys) { [Environment]::SetEnvironmentVariable($k, $savedL[$k], 'Process') } }
        $ll = @($lr.Output -split "`n" | Where-Object { $_ -like 'RESULT_JSON:*' })
        if ($ll.Count -eq 0) { Add-Row 'L0' 'L' 'The sign-in screen check ran and reported results' 'RESULT_JSON line' ('no result: ' + (($lr.Output -split "`n" | Select-Object -Last 4) -join ' | ')) 'FAIL' }
        else { $parsedL = ConvertFrom-Json -InputObject ($ll[0] -replace '^RESULT_JSON:', ''); foreach ($x in $parsedL) { Check $x.id 'L' $x.title $x.expected $x.actual ($x.ok -eq $true) } }
        Remove-Item -LiteralPath (Join-Path $RunDir 'chrome-profile-login') -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =============================== M: phone-width responsiveness (emulation in desktop Chrome; NOT a real phone) =======================
if ($run_M) {
    Write-Host '--- M: responsive layout and mobile usability (360 px phone EMULATION in desktop Chrome, not a real phone)'
    RunBrowserGroup 'M' 'mobile_check.mjs' @{} 'chrome-profile-mobile'
}

# =============================== BR: Everwell Hospital branding (names, tagline, icons, metadata, offline page) ===========================
if ($run_BR) {
    Write-Host '--- BR: Everwell Hospital / Everwell Health Portal branding'
    $webDirBr = Join-Path $repo 'web'
    function Strip-Comments([string]$text, [string]$kind) {
        if ($kind -eq 'js') { $t = [regex]::Replace($text, '/\*[\s\S]*?\*/', ''); return [regex]::Replace($t, '(?m)(^|[\s;{}),])//[^\r\n]*', '$1') }
        if ($kind -eq 'css') { return [regex]::Replace($text, '/\*[\s\S]*?\*/', '') }
        if ($kind -eq 'html') { return [regex]::Replace($text, '<!--[\s\S]*?-->', '') }
        return $text
    }
    $brFiles = [ordered]@{ 'index.html' = 'html'; 'offline.html' = 'html'; 'manifest.webmanifest' = 'json'; 'app.js' = 'js'; 'sw.js' = 'js'; 'styles.css' = 'css' }
    $brText = @{}; $oldIn = @()
    foreach ($bf in $brFiles.Keys) {
        $raw = Get-Content -LiteralPath (Join-Path $webDirBr $bf) -Raw
        $brText[$bf] = $raw
        if ((Strip-Comments $raw $brFiles[$bf]) -match '(?i)zero[ -]?trust|ZT Hospital') { $oldIn += $bf }
    }
    $handler = Get-Content -LiteralPath (Join-Path $repo 'protected_app\src\app\http\handlers\PublicInfoHandler.java') -Raw
    if ($handler -match 'Zero Trust General Hospital') { $oldIn += 'PublicInfoHandler.java' }
    $need = @(@('index.html', 'Everwell Health Portal'), @('index.html', 'Everwell Hospital'), @('index.html', 'Compassionate Care. Trusted Access.'), @('offline.html', 'Everwell Hospital'), @('offline.html', 'Everwell Health Portal'), @('offline.html', 'Compassionate Care. Trusted Access.'),
        @('manifest.webmanifest', 'Everwell Health Portal'), @('manifest.webmanifest', 'Everwell Hospital'), @('app.js', "hospital: 'Everwell Hospital'"), @('app.js', "portal: 'Everwell Health Portal'"), @('app.js', "tagline: 'Compassionate Care. Trusted Access.'"))
    $missing = @($need | Where-Object { -not $brText[$_[0]].Contains($_[1]) } | ForEach-Object { $_[0] + ': ' + $_[1] })
    if (-not $handler.Contains('"Everwell Hospital"')) { $missing += 'PublicInfoHandler.java: "Everwell Hospital"' }
    Check 'BR1' 'BR' 'Static scan of the user-facing files (HTML, manifest, scripts, styles, the public-information handler): the old product name appears nowhere outside source comments, and the new names and tagline are present where they belong' 'no old name outside comments; all 12 required strings present' ("old name in: [{0}]; missing: [{1}]" -f ($oldIn -join ', '), ($missing -join '; ')) ($oldIn.Count -eq 0 -and $missing.Count -eq 0)

    $mfBr = ECall 'GET' '/manifest.webmanifest'
    $mj = $mfBr.Json
    $mOkBr = $mfBr.Status -eq 200 -and $mj.name -eq 'Everwell Health Portal' -and $mj.short_name -eq 'Everwell' -and ([string]$mj.short_name).Length -le 12 -and ([string]$mj.description) -like '*Everwell Hospital*' -and $mj.theme_color -eq '#0b2545' -and $mj.display -eq 'standalone' -and @($mj.icons).Count -eq 3
    Check 'BR2' 'BR' 'The PWA manifest served by the edge names the app "Everwell Health Portal" (install name), "Everwell" (home-screen label, at most 12 characters), describes Everwell Hospital, keeps the navy theme colour and the three icons' 'name, short_name, description, theme colour, 3 icons' ("HTTP {0}; name '{1}'; short_name '{2}'; theme {3}; icons {4}" -f $mfBr.Status, $mj.name, $mj.short_name, $mj.theme_color, @($mj.icons).Count) ([bool]$mOkBr)

    $brDoc = (Login 'dr_alice' 'BR-TEST-DOCTOR' 'browser' '10.62.0.1').Session
    $pubInfo = Call 'GET' '/api/public/info' $null (Hd $brDoc)
    $null = Call 'POST' '/ctl/logout' $null (Hd $brDoc)
    Check 'BR6' 'BR' 'The hospital information the back end returns names the hospital "Everwell Hospital" (and never the old name); the answer is otherwise unchanged' 'hospital = Everwell Hospital; hours and departments present; no old name' ("HTTP {0}; hospital '{1}'; fields: {2}" -f $pubInfo.Status, $pubInfo.Json.hospital, (@($pubInfo.Json.PSObject.Properties.Name) -join ',')) ($pubInfo.Status -eq 200 -and $pubInfo.Json.hospital -eq 'Everwell Hospital' -and $pubInfo.Text -notmatch '(?i)zero[ -]?trust' -and @($pubInfo.Json.PSObject.Properties.Name).Count -eq 3)

    RunBrowserGroup 'BR' 'branding_check.mjs' @{} 'chrome-profile-brand'
}

# =============================== X: authorization matrix, need-to-know and no patient-existence oracle (direct API calls through the front door) ===========
# Every endpoint of the catalogue is called by every role (and by nobody) and the outcome is compared with a table written here, independently of the
# database. Many refusals are provoked on purpose, so the group raises the revoke threshold and burst limit for its own duration and restores every
# policy value it touches in a finally block.
if ($run_X) {
    Write-Host '--- X: authorization matrix, need-to-know, no patient-existence oracle'
    $admX = (Login 'sec_dan' 'X-RUNNER-ADMIN' 'browser' '10.65.0.1').Session
    $polX = (Call 'GET' '/admin/policy' $null (Hd $admX)).Json.policy
    $keepX = [ordered]@{ 'session.revoke_threshold' = $polX.session.revoke_threshold; 'behavior.burst_limit' = $polX.behavior.burst_limit; 'simulation.enabled' = $polX.simulation.enabled
        'bands.allow_below' = $polX.bands.allow_below; 'bands.step_up_below' = $polX.bands.step_up_below; 'device.phone_stale_seconds' = $polX.device.phone_stale_seconds
        'session.lockout_minutes' = $polX.session.lockout_minutes }
    function XReq($s, [string]$m, [string]$p, $body = $null, [bool]$pin = $true) {
        $x = @{}; if ($pin) { $x['X-StepUp-Pin'] = (Pin $s.User) }
        $r = Call $m $p $body (Hd $s $x)
        [pscustomobject]@{ Status = $r.Status; Json = $r.Json; Text = $r.Text; Code = $(if ($r.Json -and $r.Json.error) { [string]$r.Json.error } else { '' }) }
    }
    function XRisk($sessionId) { $r = Call 'GET' '/admin/sessions' $null (Hd $admX); $m = @($r.Json.sessions | Where-Object { $_.session_id -eq $sessionId }); if ($m.Count -gt 0) { [int]$m[0].risk_points } else { -1 } }
    function XLastDecision($sessionId) { $ev = @(Get-Events $admX ('limit=3&type=DECISION&session=' + $sessionId)); if ($ev.Count -gt 0) { $ev[0] } else { $null } }
    $figureKeys = 'risk_score', 'session_risk', 'revoke_threshold', 'detail', 'penalty', 'breakdown'
    $leakWords = '(?i)risk score|threshold|\bpoints?\b|allowed limit|step-up band|heartbeat|posture agent|firewall|antivirus|>=|\b\d{1,3}(\.\d{1,3}){3}\b'
    $unlockAll = { foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $admX) } }
    # a browser device that does not report is stale after phone_stale_seconds: keep every session of this group fresh between phases
    $beat = { foreach ($bs in @($sx.Values) + @($admX)) { if ($null -ne $bs) { $null = Hb $bs } } }
    $endGrants = { foreach ($g in @((Call 'GET' '/admin/grants' $null (Hd $admX)).Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $admX @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) } }
    try {
        $null = Set-Policy $admX 'session.revoke_threshold' 100000
        $null = Set-Policy $admX 'behavior.burst_limit' 100000
        & $unlockAll; & $endGrants
        $roles = 'doctor', 'nurse', 'receptionist', 'security_admin'
        $userOf = @{ doctor = 'dr_alice'; nurse = 'nurse_bob'; receptionist = 'front_carol'; security_admin = 'sec_dan' }
        $sx = @{}
        foreach ($role in $roles) { $sx[$role] = (Login $userOf[$role] ('X-DEVICE-' + $role.ToUpper()) 'browser' '10.65.0.2').Session }
        $okSessions = @($sx.Values | Where-Object { $null -ne $_ }).Count

        # ---- the table: endpoint -> the roles whose permission set contains it (written by hand from the specification) -----------------------------
        $bgText = 'Authorization matrix probe: synthetic data, no real emergency (this text is long enough).'
        $matrix = @(
            @{ M = 'GET';  P = '/api/public/info';                     B = $null; Roles = $roles },
            @{ M = 'GET';  P = '/ctl/session';                         B = $null; Roles = $roles },
            @{ M = 'POST'; P = '/ctl/heartbeat';                       B = @{ signals = @{ secure_context = $true; online = $true; visible = $true; standalone = $false; connection = '4g' } }; Roles = $roles },
            @{ M = 'POST'; P = '/ctl/renew';                           B = $null; Roles = $roles },
            @{ M = 'POST'; P = '/ctl/simulate';                        B = @{ kind = 'bogus' }; Roles = $roles },
            @{ M = 'GET';  P = '/api/patients/list';                   B = $null; Roles = 'doctor', 'nurse', 'receptionist' },
            @{ M = 'GET';  P = '/api/patients/101/summary';            B = $null; Roles = 'doctor', 'nurse', 'receptionist' },
            @{ M = 'GET';  P = '/api/patients/101/records';            B = $null; Roles = 'doctor', 'nurse' },
            @{ M = 'POST'; P = '/api/patients/101/export-pdf';         B = $null; Roles = 'doctor' },
            @{ M = 'POST'; P = '/api/patients/101/appointment';        B = @{}; Roles = 'receptionist' },
            @{ M = 'POST'; P = '/ctl/break-glass';                     B = @{ patient_id = 101; justification = $bgText }; Roles = 'doctor' },
            @{ M = 'GET';  P = '/ctl/policy';                          B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/summary';                       B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/sessions';                      B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/devices';                       B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/events?limit=5';                B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/policy';                        B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/grants';                        B = $null; Roles = 'security_admin' },
            @{ M = 'GET';  P = '/admin/users';                         B = $null; Roles = 'security_admin' },
            @{ M = 'POST'; P = '/admin/sessions/revoke';               B = @{ session_id = 'S-does-not-exist'; reason = 'matrix probe' }; Roles = 'security_admin' },
            @{ M = 'POST'; P = '/admin/policy/set';                    B = @{ path = 'no.such.setting'; value = 1 }; Roles = 'security_admin' },
            @{ M = 'POST'; P = '/admin/grants/revoke';                 B = @{ grant_id = 'BG-none' }; Roles = 'security_admin' },
            @{ M = 'POST'; P = '/admin/unlock';                        B = @{ username = 'nobody-here' }; Roles = 'security_admin' }
        )
        # before: the state the refused requests must not change
        $snap = {
            $pol = (Call 'GET' '/admin/policy' $null (Hd $admX)).Json
            $ses = (Call 'GET' '/admin/sessions' $null (Hd $admX)).Json
            $usr = (Call 'GET' '/admin/users' $null (Hd $admX)).Json
            $grn = (Call 'GET' '/admin/grants' $null (Hd $admX)).Json
            $appt = (XReq $sx['receptionist'] 'GET' '/api/patients/101/summary').Json.next_appointment
            ((ConvertTo-Json -Compress -Depth 8 -InputObject $pol.policy) + '|' + ((@($ses.sessions | ForEach-Object { $_.session_id + ':' + $_.status }) | Sort-Object) -join ',') + '|' + ((@($usr.users | ForEach-Object { $_.username + ':' + $_.locked_until }) | Sort-Object) -join ',') + '|' + ((@($grn.grants | ForEach-Object { $_.grant_id + ':' + $_.status }) | Sort-Object) -join ',') + '|' + $appt)
        }
        $before = & $snap
        $bad = New-Object System.Collections.Generic.List[string]; $n = 0; $permitted = 0; $refused = 0
        foreach ($row in $matrix) {
            foreach ($role in $roles) {
                if ($null -eq $sx[$role]) { continue }
                $r = XReq $sx[$role] $row.M $row.P $row.B
                $n++
                $isRefused = ($r.Status -eq 403 -and $r.Code -eq 'role_denied')
                $shouldRefuse = ($row.Roles -notcontains $role)
                if ($shouldRefuse) { $refused++ } else { $permitted++ }
                if ($isRefused -ne $shouldRefuse) { $bad.Add(("{0} {1} as {2}: HTTP {3} {4} (expected {5})" -f $row.M, $row.P, $role, $r.Status, $r.Code, $(if ($shouldRefuse) { 'role_denied' } else { 'authorized' }))) }
                elseif (-not $shouldRefuse -and $r.Status -in 401, 403 -and $r.Code -ne 'step_up_required') { $bad.Add(("{0} {1} as {2}: authorized role but HTTP {3} {4}" -f $row.M, $row.P, $role, $r.Status, $r.Code)) }
            }
        }
        Check 'X1' 'X' 'Authorization matrix: 23 endpoints of the catalogue (sign-out is X15) x all 4 roles through the front door; every permitted pair passes the role gate and every other pair is refused with role_denied' ("{0} calls: {1} permitted pairs pass, {2} refused pairs are role_denied, no deviation" -f ($matrix.Count * 4), $permitted, $refused) ("{0} sessions; {1} calls; deviations: [{2}]" -f $okSessions, $n, (($bad | Select-Object -First 5) -join '; ')) ($okSessions -eq 4 -and $bad.Count -eq 0 -and $n -eq ($matrix.Count * 4) -and $matrix.Count -eq 23)
        $after = & $snap
        Check 'X2' 'X' 'The refused requests changed nothing: the policy, every session status, every account lock, every emergency grant and the stored appointment are exactly as before (the matrix included 4 refused administrative changes for each clinical role)' 'before = after' $(if ($before -eq $after) { 'identical' } else { 'DIFFERENT' }) ($before -eq $after)

        # ---- nobody signed in: every endpoint says 401 ---------------------------------------------------------------------------------------------
        $noTok = New-Object System.Collections.Generic.List[string]
        foreach ($row in (@($matrix) + @(@{ M = 'POST'; P = '/ctl/logout'; B = $null }))) {
            $r = Call $row.M $row.P $row.B @{ 'X-Device-Id' = 'X-NOBODY-DEVICE' }
            if ($r.Status -ne 401) { $noTok.Add(("{0} {1}: HTTP {2}" -f $row.M, $row.P, $r.Status)) }
        }
        $forged = Call 'GET' '/admin/sessions' $null @{ 'X-Device-Id' = 'X-NOBODY-DEVICE'; Authorization = 'Bearer not.a.real.token' }
        Check 'X3' 'X' 'Without a token (or with a forged one) every one of the 24 endpoints answers 401: no function, patient or administrative, works for an unauthenticated caller' '24 x 401 and the forged token 401' ("not 401: [{0}]; forged token: HTTP {1}" -f ($noTok -join '; '), $forged.Status) ($noTok.Count -eq 0 -and $forged.Status -eq 401)

        # ---- no patient-existence oracle ---------------------------------------------------------------------------------------------------------
        & $beat
        $sd = $sx['doctor']; $sn = $sx['nurse']
        $shape = { param($r) ("{0}|{1}|{2}|{3}|{4}" -f $r.Status, $r.Code, [string]$r.Json.message, [string]$r.Json.decision, [string]$r.Json.step_up_required) }
        $docDiff = New-Object System.Collections.Generic.List[string]; $docRisk = @{}
        foreach ($ep in @(@('GET', '/summary'), @('GET', '/records'), @('POST', '/export-pdf'))) {
            $vals = @{}
            foreach ($pid_ in 999, 998, 103, 104) {
                $r0 = XRisk $sd.SessionId
                $r = XReq $sd $ep[0] ("/api/patients/$pid_" + $ep[1])
                $r1 = XRisk $sd.SessionId
                $vals[$pid_] = [pscustomobject]@{ Shape = (& $shape $r); Delta = ($r1 - $r0); Ev = (XLastDecision $sd.SessionId) }
            }
            $shapes = @($vals.Values | ForEach-Object { $_.Shape } | Sort-Object -Unique)
            $deltas = @($vals.Values | ForEach-Object { $_.Delta } | Sort-Object -Unique)
            $evs = @($vals.Values | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Ev.code, $_.Ev.decision, $_.Ev.risk_delta, $_.Ev.reason } | Sort-Object -Unique)
            if ($shapes.Count -ne 1 -or $deltas.Count -ne 1 -or $evs.Count -ne 1) { $docDiff.Add(("{0} {1}: {2} distinct answers, {3} risk deltas, {4} audit shapes" -f $ep[0], $ep[1], $shapes.Count, $deltas.Count, $evs.Count)) }
            $docRisk[$ep[1]] = ($deltas -join '/')
        }
        Check 'X4' 'X' 'Doctor: a patient number that does not exist (999, 998) is answered exactly like patients who exist but are not assigned (103, 104): same status, code, text, session-risk penalty and audit record, for the summary, the clinical record and the export' 'one answer, one penalty, one audit shape per endpoint' ("differences: [{0}]; penalty per request: summary {1}, records {2}, export {3}" -f ($docDiff -join '; '), $docRisk['/summary'], $docRisk['/records'], $docRisk['/export-pdf']) ($docDiff.Count -eq 0 -and $docRisk['/summary'] -eq '20' -and $docRisk['/records'] -eq '20' -and $docRisk['/export-pdf'] -eq '20')

        $nurDiff = New-Object System.Collections.Generic.List[string]; $nurRisk = @{}
        foreach ($ep in @(@('GET', '/summary'), @('GET', '/records'))) {
            $vals = @{}
            foreach ($pid_ in 999, 998, 102, 104) {
                $r0 = XRisk $sn.SessionId
                $r = XReq $sn $ep[0] ("/api/patients/$pid_" + $ep[1])
                $r1 = XRisk $sn.SessionId
                $vals[$pid_] = [pscustomobject]@{ Shape = (& $shape $r); Delta = ($r1 - $r0); Ev = (XLastDecision $sn.SessionId) }
            }
            $shapes = @($vals.Values | ForEach-Object { $_.Shape } | Sort-Object -Unique)
            $deltas = @($vals.Values | ForEach-Object { $_.Delta } | Sort-Object -Unique)
            $evs = @($vals.Values | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Ev.code, $_.Ev.decision, $_.Ev.risk_delta, $_.Ev.reason } | Sort-Object -Unique)
            if ($shapes.Count -ne 1 -or $deltas.Count -ne 1 -or $evs.Count -ne 1) { $nurDiff.Add(("{0} {1}: {2} distinct answers, {3} risk deltas, {4} audit shapes" -f $ep[0], $ep[1], $shapes.Count, $deltas.Count, $evs.Count)) }
            $nurRisk[$ep[1]] = ($deltas -join '/')
        }
        Check 'X5' 'X' 'Nurse: a patient number that does not exist is answered exactly like a patient on another ward: same status, code, text, session-risk penalty and audit record, for the summary and the clinical record' 'one answer, one penalty, one audit shape per endpoint' ("differences: [{0}]; penalty per request: summary {1}, records {2}" -f ($nurDiff -join '; '), $nurRisk['/summary'], $nurRisk['/records']) ($nurDiff.Count -eq 0 -and $nurRisk['/summary'] -eq '20' -and $nurRisk['/records'] -eq '20')

        # ---- emergency access: the justification comes first, so numbers cannot be probed without one ---------------------------------------------
        $shortJ = 'too short'
        $a = XReq $sd 'POST' '/ctl/break-glass' @{ patient_id = 999; justification = $shortJ }
        $b = XReq $sd 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = $shortJ }
        $riskA0 = XRisk $sd.SessionId
        $c = XReq $sd 'POST' '/ctl/break-glass' @{ patient_id = 999; justification = $bgText }
        $riskA1 = XRisk $sd.SessionId
        $d = XReq $sd 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = $bgText }
        $gid = if ($d.Json) { [string]$d.Json.grant_id } else { '' }
        & $endGrants
        Check 'X6' 'X' 'Emergency access does not reveal which patient numbers exist before a written justification is given (999 and 103 get the same 400 justification_required); with one, a missing number is a 404 that costs the same session risk as asking for an unassigned patient (20), and an existing patient gets a recorded, time-limited grant' 'same refusal without justification; 404 and +20 risk for a missing number; 200 grant for 103' ("without justification: 999 -> {0} {1}, 103 -> {2} {3}; with: 999 -> {4} {5} (+{6} risk), 103 -> {7} grant {8}" -f $a.Status, $a.Code, $b.Status, $b.Code, $c.Status, $c.Code, ($riskA1 - $riskA0), $d.Status, $(if ($gid) { 'created' } else { 'none' })) ($a.Status -eq 400 -and $a.Code -eq 'justification_required' -and $b.Status -eq 400 -and $b.Code -eq 'justification_required' -and [string]$a.Json.message -eq [string]$b.Json.message -and $c.Status -eq 404 -and $c.Code -eq 'not_found' -and ($riskA1 - $riskA0) -eq 20 -and $d.Status -eq 200 -and $gid)

        $e1 = XReq $sx['receptionist'] 'GET' '/api/patients/999/summary'
        $e2 = XReq $sx['receptionist'] 'GET' '/api/patients/101/summary'
        Check 'X7' 'X' 'The front desk works with the whole directory, so for the receptionist (and only for that role) a missing patient number is a plain 404 while an existing one is a 200: the documented exception to the no-oracle rule' '999 -> 404 not_found; 101 -> 200' ("999 -> {0} {1}; 101 -> {2}" -f $e1.Status, $e1.Code, $e2.Status) ($e1.Status -eq 404 -and $e1.Code -eq 'not_found' -and $e2.Status -eq 200)

        # ---- device labels: a client cannot name its own device "Registered laptop" -------------------------------------------------------------------
        $labels = [ordered]@{ 'X-LABEL-SPOOF' = @('Registered laptop', 'Browser'); 'X-LABEL-DESKTOP' = @('Desktop browser', 'Desktop browser'); 'X-LABEL-PHONE' = @('Phone browser', 'Phone browser'); 'X-LABEL-TABLET' = @('Tablet browser', 'Tablet browser'); 'X-LABEL-OLDWEB' = @('Web browser', 'Desktop browser'); 'X-LABEL-FREE' = @('<b>anything</b>', 'Browser') }
        foreach ($k in $labels.Keys) {
            $lb = @{ username = 'dr_alice'; password = $creds['dr_alice'].Password; device_kind = 'browser'; device_label = $labels[$k][0]; platform = 'Windows'; signals = @{ secure_context = $true; online = $true; visible = $true; standalone = $false; connection = '4g' } }
            $lr = Call 'POST' '/ctl/login' $lb @{ 'X-Device-Id' = $k; 'X-Edge-Key' = $sec.edgeKey; 'X-Forwarded-For' = '10.65.0.9' }
            if ($lr.Status -eq 200) { $null = Call 'POST' '/ctl/logout' $null @{ Authorization = 'Bearer ' + $lr.Json.token; 'X-Device-Id' = $k; 'X-Edge-Key' = $sec.edgeKey; 'X-Forwarded-For' = '10.65.0.9' } }
        }
        $devs = @((Call 'GET' '/admin/devices' $null (Hd $admX)).Json.devices)
        $lblBad = @(); foreach ($k in $labels.Keys) { $d1 = @($devs | Where-Object { $_.device_id -eq $k }); if ($d1.Count -eq 0 -or $d1[0].kind -ne 'browser' -or $d1[0].hostname -ne $labels[$k][1]) { $lblBad += ($k + ' -> ' + $(if ($d1.Count) { $d1[0].hostname } else { 'missing' })) } }
        Check 'X8' 'X' 'The device label is the server''s decision: a browser may call itself Phone, Tablet or Desktop browser (an older "Web browser" becomes Desktop browser); "Registered laptop" and free text become plain "Browser", and the kind stays browser' '6 devices, labels as listed' ("deviations: [{0}]" -f ($lblBad -join '; ')) ($lblBad.Count -eq 0)

        # ---- need-to-know: what the server sends to a client that has no business with risk figures -----------------------------------------------
        & $beat
        $onDoc = XReq $sd 'GET' '/api/patients/103/summary'
        $onSes = (XReq $sd 'GET' '/ctl/session').Json
        $onOk = ($onDoc.Status -eq 403 -and $null -ne $onDoc.Json.session_risk -and $null -ne $onDoc.Json.revoke_threshold -and $onSes.detail -eq 'full' -and $null -ne $onSes.device -and $null -ne $onSes.network -and $null -ne $onSes.session.risk_points)
        $null = Set-Policy $admX 'simulation.enabled' $false
        $dd = XReq $sx['doctor'] 'GET' '/api/patients/103/summary'
        $dn = XReq $sx['nurse'] 'GET' '/api/patients/102/summary'
        $dr = XReq $sx['receptionist'] 'GET' '/api/patients/101/records'
        $dx = XReq $sx['doctor'] 'POST' '/api/patients/101/export-pdf' $null $false          # step-up band, no PIN sent
        $da = XReq $sx['security_admin'] 'GET' '/api/patients/101/summary'                       # the administrator is entitled to the figures
        $offBodies = @($dd, $dn, $dr, $dx)
        $leaks = @(); foreach ($ob in $offBodies) { $keys = @(Keys $ob.Json); $kk = @($keys | Where-Object { $figureKeys -contains $_ }); if ($kk.Count -gt 0) { $leaks += ($ob.Code + ': has ' + ($kk -join ',')) } elseif ([string]$ob.Json.message -match $leakWords) { $leaks += ($ob.Code + ': message "' + $ob.Json.message + '"') } }
        $adminKeeps = ($da.Status -eq 403 -and $null -ne $da.Json.session_risk -and $null -ne $da.Json.revoke_threshold)
        Check 'X9' 'X' 'Need-to-know: with the evaluation tools ON a refused clinical request carries the session risk and the revoke limit; with them OFF the same refusals (not assigned, other ward, role, step-up) carry no risk figure, no limit, no scoring detail and no policy wording, while the security administrator still receives the figures' 'ON: figures present; OFF: none for doctor, nurse, receptionist; admin keeps them' ("ON ok: {0}; OFF leaks: [{1}]; admin keeps figures: {2}; statuses {3}/{4}/{5}/{6}" -f $onOk, ($leaks -join '; '), $adminKeeps, $dd.Status, $dn.Status, $dr.Status, $dx.Status) ($onOk -and $leaks.Count -eq 0 -and $adminKeeps -and $dd.Code -eq 'not_assigned' -and $dn.Code -eq 'ward_denied' -and $dr.Code -eq 'role_denied' -and $dx.Code -eq 'step_up_required')

        $sesLim = @{}; foreach ($role in 'doctor', 'nurse', 'receptionist', 'security_admin') { $sesLim[$role] = (XReq $sx[$role] 'GET' '/ctl/session').Json }
        $limBad = @()
        foreach ($role in 'doctor', 'nurse', 'receptionist') {
            $j = $sesLim[$role]
            if ($j.detail -ne 'limited') { $limBad += "$role detail=$($j.detail)" }
            foreach ($bad_ in 'device', 'network') { if ($null -ne $j.$bad_) { $limBad += "$role has $bad_" } }
            foreach ($bad_ in 'risk_points', 'revoke_threshold', 'last_score', 'status', 'lockout_minutes', 'session_id') { if ($null -ne $j.session.$bad_) { $limBad += "$role has session.$bad_" } }
            if ($null -ne $j.policy.bands -or $null -ne $j.policy.session.revoke_threshold) { $limBad += "$role has policy thresholds" }
            if (-not ($j.session.idle_timeout_seconds -gt 0 -and $j.session.absolute_expires_at -gt $j.session.created_at -and [math]::Abs([long]$j.server_time - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -lt 30 -and $j.simulation_enabled -eq $false)) { $limBad += "$role lacks the session timing" }
        }
        if ($null -eq $sesLim['doctor'].policy.break_glass) { $limBad += 'doctor lost the emergency-access rules' }
        $aj = $sesLim['security_admin']
        if ($aj.detail -ne 'full' -or $null -eq $aj.device -or $null -eq $aj.network -or $null -eq $aj.session.risk_points -or $null -eq $aj.policy.penalties) { $limBad += 'the administrator no longer gets the full session view' }
        Check 'X10' 'X' 'Need-to-know: with the evaluation tools OFF the session call of a clinical role returns who they are, the idle and maximum session limits, the server clock and (doctors) the emergency-access rules, and no risk points, no device posture, no network address, no thresholds; the security administrator still gets the full view' 'limited for 3 clinical roles, full for the administrator' ("problems: [{0}]" -f ($limBad -join '; ')) ($limBad.Count -eq 0)

        $simOff = @(); foreach ($role in 'doctor', 'nurse', 'receptionist', 'security_admin') { $sr = XReq $sx[$role] 'POST' '/ctl/simulate' @{ kind = 'network'; ip = 'reset' }; if ($sr.Status -ne 403 -or $sr.Code -ne 'simulation_disabled') { $simOff += ("{0}: HTTP {1} {2}" -f $role, $sr.Status, $sr.Code) } }
        $null = Set-Policy $admX 'simulation.enabled' $true
        $simA = XReq $sx['doctor'] 'POST' '/ctl/simulate' @{ kind = 'network'; ip = '10.65.9.9' }
        $adminView = @((Call 'GET' '/admin/sessions' $null (Hd $admX)).Json.sessions)
        $simDoc = @($adminView | Where-Object { $_.session_id -eq $sx['doctor'].SessionId })[0]; $simNur = @($adminView | Where-Object { $_.session_id -eq $sx['nurse'].SessionId })[0]
        $simB = XReq $sx['doctor'] 'POST' '/ctl/simulate' @{ kind = 'network'; ip = 'reset' }
        Check 'X11' 'X' 'The simulation switch is enforced by the server, not by the page: with the evaluation tools OFF every role is refused (simulation_disabled); ON, a simulated address changes only the caller''s own session (the nurse''s session is untouched) and is removed again by "reset"' 'OFF: 4 x 403 simulation_disabled; ON: only the doctor session carries the simulated address' ("OFF problems: [{0}]; ON: HTTP {1}; doctor session simulated_ip '{2}', nurse session '{3}'; reset HTTP {4}" -f ($simOff -join '; '), $simA.Status, $simDoc.simulated_ip, $simNur.simulated_ip, $simB.Status) ($simOff.Count -eq 0 -and $simA.Status -eq 200 -and $simDoc.simulated_ip -eq '10.65.9.9' -and [string]::IsNullOrEmpty([string]$simNur.simulated_ip) -and $simB.Status -eq 200)

        # ---- need-to-know while the session is ended by the server (risk revocation, account lock) ---------------------------------------------
        & $beat
        $null = Set-Policy $admX 'simulation.enabled' $false
        $null = Set-Policy $admX 'session.revoke_threshold' 30
        & $unlockAll
        $victim = (Login 'dr_alice' 'X-DEVICE-VICTIM' 'browser' '10.65.0.5').Session
        $v1 = XReq $victim 'GET' '/api/patients/103/summary'
        $v2 = XReq $victim 'GET' '/api/patients/104/summary'        # 2 x 20 points >= 30: the server revokes the session here
        $v3 = XReq $victim 'GET' '/api/patients/101/summary'        # the old token again
        $v4 = Login 'dr_alice' 'X-DEVICE-VICTIM2' 'browser' '10.65.0.6'      # sign-in during the lockout
        $endedBodies = @($v2, $v3); $endLeaks = @()
        foreach ($eb in $endedBodies) { $kk = @(Keys $eb.Json | Where-Object { $figureKeys -contains $_ }); if ($kk.Count -gt 0 -or [string]$eb.Json.message -match $leakWords) { $endLeaks += ($eb.Code + ': ' + ($kk -join ',') + ' "' + $eb.Json.message + '"') } }
        if ([string]$v4.Json.message -match $leakWords -or $v4.Status -ne 423) { $endLeaks += ('lockout sign-in: HTTP ' + $v4.Status + ' "' + $v4.Json.message + '"') }
        Check 'X12' 'X' 'Revocation and lockout with the evaluation tools OFF: the response that revokes the session, a later call with the dead token and a sign-in during the lockout all say plainly that the session ended or the account is locked until a time, without risk points, limits or the lock reason; the session really is dead and the account really is locked' 'v2 session_revoked; v3 refused; sign-in 423; no figures' ("v1 {0} {1}; v2 {2} {3}; v3 {4} {5}; sign-in {6}; leaks: [{7}]" -f $v1.Status, $v1.Code, $v2.Status, $v2.Code, $v3.Status, $v3.Code, $v4.Status, ($endLeaks -join '; ')) ($v1.Code -eq 'not_assigned' -and $v2.Code -eq 'session_revoked' -and $v3.Status -eq 401 -and $v4.Status -eq 423 -and $endLeaks.Count -eq 0)
        & $unlockAll

        # a device that stopped reporting: the refusal does not describe the device (heartbeat age, limit, agent) to the user
        $null = Set-Policy $admX 'session.revoke_threshold' 100000
        $null = Set-Policy $admX 'device.phone_stale_seconds' 5
        $null = Hb $admX                                     # the administrator's own browser device would be stale under the new limit
        $stale = (Login 'nurse_bob' 'X-DEVICE-STALE' 'browser' '10.65.0.7').Session
        Start-Sleep -Seconds 7
        $null = Hb $admX
        $st1 = XReq $stale 'GET' '/api/patients/list'
        $null = Set-Policy $admX 'device.phone_stale_seconds' $keepX['device.phone_stale_seconds']
        $stSes = (XReq $stale 'GET' '/ctl/session').Json
        Check 'X13' 'X' 'A device that stopped reporting is refused (posture_blocked) with a plain sentence for the user (this device does not currently meet the security requirements), without the heartbeat age, the limit or the way the device is measured; the status call still works and tells the user nothing about posture' 'HTTP 403 posture_blocked, no leak; /ctl/session limited' ("HTTP {0} {1}; message '{2}'; session call detail '{3}'" -f $st1.Status, $st1.Code, $st1.Json.message, $stSes.detail) ($st1.Status -eq 403 -and $st1.Code -eq 'posture_blocked' -and [string]$st1.Json.message -notmatch $leakWords -and $stSes.detail -eq 'limited')

        # network change while the tools are off: the step-up request does not quote the addresses
        $moved = $sx['doctor'].PSObject.Copy(); $moved.Ip = '10.99.7.7'
        $nm = XReq $moved 'GET' '/api/patients/101/summary' $null $false
        Check 'X14' 'X' 'A session that suddenly comes from another subnet is asked for the step-up PIN in plain words, without quoting the old and the new network address' 'HTTP 401 step_up_required; message without an address' ("HTTP {0} {1}; message '{2}'" -f $nm.Status, $nm.Code, $nm.Json.message) ($nm.Status -eq 401 -and $nm.Code -eq 'step_up_required' -and [string]$nm.Json.message -notmatch '\d{1,3}(\.\d{1,3}){3}')
        # ---- sign-out: every role can end its own session, and the old token is dead afterwards ------------------------------------------------------
        $null = Call 'POST' '/ctl/logout' $null (Hd $stale)
        $loBad = @()
        foreach ($role in $roles) {
            $so = $sx[$role]; if ($null -eq $so) { $loBad += "$role has no session"; continue }
            if ($role -eq 'doctor') { $null = Hb $so }
            $lo = Call 'POST' '/ctl/logout' $null (Hd $so)
            $again = Call 'GET' '/ctl/session' $null (Hd $so)
            if ($lo.Status -ne 200 -or $again.Status -ne 401 -or [string]$again.Json.error -ne 'session_ended') { $loBad += ("{0}: sign-out HTTP {1}, old token HTTP {2} {3}" -f $role, $lo.Status, $again.Status, $again.Json.error) }
        }
        Check 'X15' 'X' 'Every role can sign out, and the signed-out token is refused afterwards (401 session_ended): the end of a session is decided by the server' '4 x sign-out 200, then 401' ("problems: [{0}]" -f ($loBad -join '; ')) ($loBad.Count -eq 0)
    } finally {
        $admF = (Login 'sec_dan' 'X-RUNNER-ADMIN2' 'browser' '10.65.0.8').Session
        if ($admF) {
            foreach ($k in $keepX.Keys) { $null = Set-Policy $admF $k $keepX[$k] }
            foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $admF) }
            foreach ($g in @((Call 'GET' '/admin/grants' $null (Hd $admF)).Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $admF @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) }
            $null = Call 'POST' '/ctl/logout' $null (Hd $admF)
        }
    }
}

# =============================== RU: role-specific interfaces (real Chrome): clinical workspaces without security monitoring, the security console with its evidence ===========
# The browser script signs in through the real pages and, for the expiry and evidence checks, changes a few policy values through the API; the runner
# restores every one of them (and unlocks the demo accounts) whatever happens.
if ($run_RU) {
    Write-Host '--- RU: role-specific interfaces (headless desktop Chrome; phone-sized views are emulation)'
    $admRU = (Login 'sec_dan' 'RU-RUNNER-ADMIN' 'browser' '10.66.0.1').Session
    $polRU = (Call 'GET' '/admin/policy' $null (Hd $admRU)).Json.policy
    $keepRU = [ordered]@{ 'session.revoke_threshold' = $polRU.session.revoke_threshold; 'session.idle_timeout_seconds' = $polRU.session.idle_timeout_seconds; 'session.absolute_timeout_seconds' = $polRU.session.absolute_timeout_seconds
        'simulation.enabled' = $polRU.simulation.enabled; 'device.phone_stale_seconds' = $polRU.device.phone_stale_seconds; 'device.laptop_stale_seconds' = $polRU.device.laptop_stale_seconds }
    foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $admRU) }
    $null = Call 'POST' '/ctl/logout' $null (Hd $admRU)
    try { RunBrowserGroup 'RU' 'role_ux_check.mjs' @{} 'chrome-profile-roleux' }
    finally {
        $admRU2 = (Login 'sec_dan' 'RU-RUNNER-ADMIN2' 'browser' '10.66.0.2').Session
        if ($admRU2) {
            foreach ($k in $keepRU.Keys) { $null = Set-Policy $admRU2 $k $keepRU[$k] }
            foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $admRU2) }
            $null = Call 'POST' '/ctl/logout' $null (Hd $admRU2)
        }
    }
}

# =============================== T: appointment management (the only write of the portal) through the front door =======================
if ($run_T) {
    Write-Host '--- T: appointment management (receptionist) through the PEP'
    $tAdm = (Login 'sec_dan' 'T-TEST-ADMIN' 'browser' '10.60.0.10').Session
    foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $tAdm) }
    $tRec = (Login 'front_carol' 'T-TEST-RECEPTION' 'browser' '10.60.0.11').Session
    $tDoc = (Login 'dr_alice' 'T-TEST-DOCTOR' 'browser' '10.60.0.12').Session
    $tNur = (Login 'nurse_bob' 'T-TEST-NURSE' 'browser' '10.60.0.13').Session
    $tPid = 104
    $keepThrT = [int](Call 'GET' '/admin/policy' $null (Hd $tAdm)).Json.policy.session.revoke_threshold
    function TStamp([int]$days, [string]$hhmm) { (Get-Date).AddDays($days).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) + ' ' + $hhmm }
    function TPost($s, $body, [int]$id = 104) { Call 'POST' "/api/patients/$id/appointment" $body (Hd $s) }
    $t0 = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    try {
        $before = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec)
        $orig = [string]$before.Json.next_appointment
        $want = TStamp 9 '11:45'
        $ch = TPost $tRec @{ next_appointment = $want }
        $after = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec)
        $chKeys = (@($ch.Json.PSObject.Properties.Name) | Sort-Object) -join ','
        $sameOther = ($before.Json.name -eq $after.Json.name) -and ($before.Json.dob -eq $after.Json.dob) -and ($before.Json.ward -eq $after.Json.ward)
        Check 'T1' 'T' 'Receptionist moves the next appointment of a patient to a valid future time: the server stores it, the summary shows it, only the appointment changes, and the answer carries no clinical field' '200; summary shows the new time; name/date of birth/ward unchanged; answer fields = message, next_appointment, patient_id' ("HTTP {0}; stored '{1}' (wanted '{2}'); identity unchanged {3}; answer fields: {4}" -f $ch.Status, $after.Json.next_appointment, $want, $sameOther, $chKeys) ($ch.Status -eq 200 -and $after.Json.next_appointment -eq $want -and $sameOther -and $chKeys -eq 'message,next_appointment,patient_id')

        $rf = @()
        foreach ($pair in @(@('doctor', $tDoc), @('nurse', $tNur), @('administrator', $tAdm))) { $x = TPost $pair[1] @{ next_appointment = (TStamp 10 '10:00') }; $rf += [pscustomobject]@{ Who = $pair[0]; Status = $x.Status; Code = [string]$x.Json.error } }
        $afterRf = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec)
        Check 'T2' 'T' 'Doctor, nurse and security administrator cannot change an appointment: the policy engine refuses them (role_denied) before the application is reached, and nothing is stored' 'three refusals 403 role_denied; stored time unchanged' (("{0}; stored unchanged: {1}" -f (($rf | ForEach-Object { $_.Who + ' ' + $_.Status + ' ' + $_.Code }) -join ', '), ($afterRf.Json.next_appointment -eq $want))) (@($rf | Where-Object { $_.Status -eq 403 -and $_.Code -eq 'role_denied' }).Count -eq 3 -and $afterRf.Json.next_appointment -eq $want)

        $bodies = [ordered]@{
            'past date' = '{"next_appointment":"2020-01-01 10:00"}'; 'more than 12 months ahead' = ('{"next_appointment":"' + (TStamp 400 '10:00') + '"}'); 'impossible date' = '{"next_appointment":"2026-13-45 99:99"}'
            'wrong format' = '{"next_appointment":"next tuesday"}'; 'ISO with a T' = ('{"next_appointment":"' + (TStamp 12 '10:00').Replace(' ', 'T') + '"}'); 'number' = '{"next_appointment":20261013}'; 'null' = '{"next_appointment":null}'
            'array' = '{"next_appointment":["2026-12-01 10:00"]}'; 'missing field' = '{"note":"x"}'; 'empty object' = '{}'; 'not JSON' = '{oops'; 'oversized body (5000 characters)' = ('{"next_appointment":"' + ('x' * 5000) + '"}')
        }
        $acceptedT = @(); $wrongCode = @()
        foreach ($k in $bodies.Keys) { $x = TPost $tRec $bodies[$k]; if ($x.Status -ne 400) { $acceptedT += "$k -> $($x.Status)" } elseif ($x.Json.error -ne 'invalid_appointment') { $wrongCode += "$k -> $($x.Json.error)" } }
        $afterBad = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec)
        Check 'T3' 'T' 'Invalid appointment input is refused with a clear message and stores nothing: past dates, beyond 12 months, impossible dates, wrong format or type, missing field, malformed JSON, oversized body' '12 inputs -> 400 invalid_appointment; stored time unchanged' ("not refused: [{0}]; other error code: [{1}]; stored unchanged: {2}" -f ($acceptedT -join '; '), ($wrongCode -join '; '), ($afterBad.Json.next_appointment -eq $want)) ($acceptedT.Count -eq 0 -and $wrongCode.Count -eq 0 -and $afterBad.Json.next_appointment -eq $want)

        $unk = TPost $tRec @{ next_appointment = (TStamp 10 '10:00') } 999
        $noTok = Call 'POST' "/api/patients/$tPid/appointment" @{ next_appointment = (TStamp 10 '10:00') } @{ 'X-Device-Id' = 'T-TEST-NOTOKEN' }
        $badTok = Call 'POST' "/api/patients/$tPid/appointment" @{ next_appointment = (TStamp 10 '10:00') } @{ 'X-Device-Id' = 'T-TEST-BADTOKEN'; Authorization = 'Bearer not.a.real.token' }
        Check 'T4' 'T' 'An unknown patient is 404, and a request without a token or with a forged token is 401: no change without a verified identity' '404 not_found; 401; 401' ("unknown patient: {0} {1}; no token: {2}; forged token: {3}" -f $unk.Status, $unk.Json.error, $noTok.Status, $badTok.Status) ($unk.Status -eq 404 -and $unk.Json.error -eq 'not_found' -and $noTok.Status -eq 401 -and $badTok.Status -eq 401)

        $evs = @(Get-Events $tAdm 'limit=500&type=DECISION' | Where-Object { $_.path -eq "/api/patients/$tPid/appointment" -and $_.ts -ge $t0 })
        $okEv = @($evs | Where-Object { $_.username -eq 'front_carol' -and $_.decision -eq 'ALLOW' })
        $denyWho = @($evs | Where-Object { $_.decision -eq 'DENY' -and $_.code -eq 'role_denied' } | ForEach-Object { [string]$_.username } | Sort-Object -Unique)
        Check 'T5' 'T' 'The change is audited: the receptionist''s allowed change and each refused attempt (doctor, nurse, administrator) appear in the security events with user, request and reason' 'ALLOW by front_carol; DENY role_denied for dr_alice, nurse_bob, sec_dan' ("allowed events by front_carol: {0}; role_denied by: [{1}]" -f $okEv.Count, ($denyWho -join ', ')) ($okEv.Count -ge 1 -and ($denyWho -join ',') -eq 'dr_alice,nurse_bob,sec_dan')

        $pb = @('records', 'export-pdf') | ForEach-Object { if ($_ -eq 'records') { Call 'GET' "/api/patients/$tPid/records" $null (Hd $tRec) } else { Call 'POST' "/api/patients/$tPid/export-pdf" $null (Hd $tRec) } }
        $bg = Call 'POST' '/ctl/break-glass' @{ patient_id = $tPid; justification = 'Appointment test: a receptionist must not get emergency access to a patient record.' } (Hd $tRec)
        Check 'T6' 'T' 'Changing appointments grants the receptionist nothing else: records, export and emergency access stay refused (role_denied)' 'three refusals, all role_denied' ("records {0} {1}; export {2} {3}; emergency {4} {5}" -f $pb[0].Status, $pb[0].Json.error, $pb[1].Status, $pb[1].Json.error, $bg.Status, $bg.Json.error) ($pb[0].Json.error -eq 'role_denied' -and $pb[1].Json.error -eq 'role_denied' -and $bg.Json.error -eq 'role_denied')

        # risk escalation: a doctor who keeps trying to change appointments is scored and finally revoked (default threshold)
        $tDoc2 = (Login 'dr_alice' 'T-TEST-DOCTOR-2' 'browser' '10.60.0.22').Session
        $esc = @(); for ($i = 0; $i -lt 4; $i++) { $x = TPost $tDoc2 @{ next_appointment = (TStamp 11 '10:00') }; $esc += ("{0} {1}" -f $x.Status, $x.Json.error) }
        $after2 = Call 'GET' '/ctl/session' $null (Hd $tDoc2)
        $relogin = Login 'dr_alice' 'T-TEST-DOCTOR-3' 'browser' '10.60.0.23'
        Check 'T7' 'T' 'Repeated forbidden appointment changes add to the session risk and finally revoke the session and lock the account (risk escalation on the new endpoint)' 'three role_denied, then session_revoked (401); the old session is dead; a new sign-in is refused (423)' ("attempts: {0}; old session afterwards: {1} {2}; new sign-in: {3} {4}" -f ($esc -join ' | '), $after2.Status, $after2.Json.error, $relogin.Status, $relogin.Json.error) ($esc[0] -eq '403 role_denied' -and $esc[1] -eq '403 role_denied' -and $esc[2] -eq '403 role_denied' -and $esc[3] -eq '401 session_revoked' -and $after2.Status -eq 401 -and $relogin.Status -eq 423)
        $null = Call 'POST' '/admin/unlock' @{ username = 'dr_alice' } (Hd $tAdm)

        # verb and path tricks (a raised revoke threshold keeps the session alive so every variant really reaches the server)
        $null = Set-Policy $tAdm 'session.revoke_threshold' 100000
        $tRec2 = (Login 'front_carol' 'T-TEST-RECEPTION-2' 'browser' '10.60.0.24').Session
        $variants = @(@('GET', "/api/patients/$tPid/appointment"), @('PUT', "/api/patients/$tPid/appointment"), @('DELETE', "/api/patients/$tPid/appointment"), @('PATCH', "/api/patients/$tPid/appointment"), @('POST', "/api/patients/$tPid/appointment/"),
            @('POST', "/api/patients/+$tPid/appointment"), @('POST', "/API/PATIENTS/$tPid/APPOINTMENT"), @('POST', "//api/patients/$tPid/appointment"), @('POST', "/api/patients/$tPid/appointment%00"),
            @('POST', "/api/patients/$tPid/summary"), @('POST', "/api/patients/$tPid/appointments"), @('POST', "/api/patients/$tPid/../103/appointment"), @('POST', "/api/patients/$tPid.0/appointment"))
        $trickBad = @()
        $other103 = [string](Call 'GET' '/api/patients/103/summary' $null (Hd $tRec2)).Json.next_appointment
        foreach ($v in $variants) { $r = Raw $v[1] (Hd $tRec2) $v[0] ('{"next_appointment":"' + (TStamp 20 '09:00') + '"}'); if ($r.Status -eq 200) { $trickBad += "$($v[0]) $($v[1]) -> 200" } }
        $afterTrick = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec2)
        $after103 = [string](Call 'GET' '/api/patients/103/summary' $null (Hd $tRec2)).Json.next_appointment
        Check 'T8' 'T' 'Verb and path tricks (other methods, trailing or doubled slashes, case, encodings, plus sign, dot segments, look-alike paths) never change an appointment, neither the targeted patient''s nor a neighbour''s' 'no variant returns 200; the stored times of patients 104 and 103 are unchanged' ("{0} variants; answered 200: [{1}]; patient 104 unchanged: {2}; patient 103 unchanged: {3}" -f $variants.Count, ($trickBad -join '; '), ($afterTrick.Json.next_appointment -eq $want), ($after103 -eq $other103)) ($trickBad.Count -eq 0 -and $afterTrick.Json.next_appointment -eq $want -and $after103 -eq $other103)
        # a leading zero is the same number (the doctor/nurse record routes behave the same, see R15): it must address exactly that patient and no other
        $alias = TStamp 21 '08:15'
        $ra = Raw "/api/patients/0$tPid/appointment" (Hd $tRec2) 'POST' ('{"next_appointment":"' + $alias + '"}')
        $afterAlias = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec2)
        $after103b = [string](Call 'GET' '/api/patients/103/summary' $null (Hd $tRec2)).Json.next_appointment
        Check 'T8b' 'T' 'A leading-zero patient number (0104) is the same number as 104: the change lands on that patient only, never on another one' 'status 200 or refused; if accepted, only patient 104 holds the new time; patient 103 unchanged' ("HTTP {0}; patient 104 now '{1}' (alias value '{2}'); patient 103 unchanged: {3}" -f $ra.Status, $afterAlias.Json.next_appointment, $alias, ($after103b -eq $other103)) ((($ra.Status -eq 200 -and $afterAlias.Json.next_appointment -eq $alias) -or ($ra.Status -ne 200 -and $afterAlias.Json.next_appointment -eq $want)) -and $after103b -eq $other103)

        # put the demonstration data back
        $origDate = [datetime]::MinValue
        if ($orig -and [datetime]::TryParseExact($orig, 'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$origDate) -and $origDate -gt (Get-Date)) {
            $rs = TPost $tRec2 @{ next_appointment = $orig }
            $back = Call 'GET' "/api/patients/$tPid/summary" $null (Hd $tRec2)
            Check 'T9' 'T' 'The demonstration data is put back after the appointment tests (the original appointment of the test patient is restored)' "restore 200; summary shows '$orig'" ("restore {0}; summary shows '{1}'" -f $rs.Status, $back.Json.next_appointment) ($rs.Status -eq 200 -and $back.Json.next_appointment -eq $orig)
        } else { NotRun 'T9' 'T' 'The demonstration data is put back after the appointment tests' 'original appointment restored' ("the original appointment ('{0}') is already in the past, which the server refuses by design, so it stays at the test value" -f $orig) }
    } finally {
        $null = Set-Policy $tAdm 'session.revoke_threshold' $keepThrT
        foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $tAdm) }
        foreach ($s in @($tRec, $tDoc, $tNur, $tRec2, $tDoc2)) { if ($s) { $null = Call 'POST' '/ctl/logout' $null (Hd $s) } }
        $null = Call 'POST' '/ctl/logout' $null (Hd $tAdm)
    }
}

# =============================== U: scenarios through the real screens (posture, network, risk, revocation, emergency access, appointments) ===========
if ($run_U) {
    Write-Host '--- U: scenarios through the real screens (headless desktop Chrome, phone-sized viewport for U1-U3)'
    $admU = (Login 'sec_dan' 'U-RUNNER-ADMIN' 'browser' '10.61.0.1').Session
    $keepBgU = [int](Call 'GET' '/admin/policy' $null (Hd $admU)).Json.policy.break_glass.duration_seconds
    foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $admU) }
    function U-RevokeGrants { foreach ($g in @((Call 'GET' '/admin/grants' $null (Hd $admU)).Json.grants | Where-Object { $_.status -eq 'ACTIVE' })) { $null = Call 'POST' '/admin/grants/revoke' @{ grant_id = $g.grant_id } (Hd $admU @{ 'X-StepUp-Pin' = (Pin 'sec_dan') }) } }
    U-RevokeGrants
    try {
        $null = Set-Policy $admU 'break_glass.duration_seconds' 8
        RunBrowserGroup 'U' 'ui_scenarios.mjs' @{ ZT_BG_SECONDS = '8' } 'chrome-profile-scenarios'
    } finally {
        $null = Set-Policy $admU 'break_glass.duration_seconds' $keepBgU
        foreach ($u in @($creds.Keys)) { $null = Call 'POST' '/admin/unlock' @{ username = $u } (Hd $admU) }
        U-RevokeGrants
        $null = Call 'POST' '/ctl/logout' $null (Hd $admU)
    }
}

# =============================== B: roles, least privilege, direct API calls =========================================================
if ($run_B) {
    Write-Host '--- B: authentication, roles, least privilege'
    $adm = (Login 'sec_dan').Session
    $doc = (Login 'dr_alice').Session; $nur = (Login 'nurse_bob').Session; $rec = (Login 'front_carol').Session
    Check 'B1' 'B' 'Sign-in works for doctor, nurse, receptionist and security administrator' 'four sessions, roles doctor/nurse/receptionist/security_admin' ("{0} {1} {2} {3}" -f $doc.Role, $nur.Role, $rec.Role, $adm.Role) ($doc -and $nur -and $rec -and $adm -and $doc.Role -eq 'doctor' -and $nur.Role -eq 'nurse' -and $rec.Role -eq 'receptionist' -and $adm.Role -eq 'security_admin')
    $bad = Login 'dr_alice' -Password 'definitely-wrong'
    Check 'B2' 'B' 'Wrong password is refused with a clear message' '401 invalid_credentials' (Desc $bad) ($bad.Status -eq 401 -and $bad.Json.error -eq 'invalid_credentials')
    $r = Call 'GET' '/api/patients/list'
    Check 'B3' 'B' 'Protected API without a token is refused' '401 token_missing' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'token_missing')

    # receptionist
    $r = Call 'GET' '/api/patients/list' $null (Hd $rec)
    $okKeys = @('patient_id', 'name', 'dob', 'ward', 'next_appointment', 'access_basis')
    $extra = @(); foreach ($p in @($r.Json.patients)) { $extra += @(Keys $p | Where-Object { $okKeys -notcontains $_ }) }
    Check 'B4' 'B' 'Receptionist gets the directory (5 patients) with no clinical field' '200, 5 patients, only demographic keys' ("{0}, {1} patients, extra keys: {2}" -f (Desc $r), @($r.Json.patients).Count, ($extra -join ',')) ($r.Status -eq 200 -and @($r.Json.patients).Count -eq 5 -and $extra.Count -eq 0)
    $r = Call 'GET' '/api/patients/101/summary' $null (Hd $rec)
    Check 'B5' 'B' 'Receptionist can read demographics and appointment of a patient' '200 with name and next_appointment, no diagnosis' ("{0}, keys: {1}" -f (Desc $r), ((Keys $r.Json) -join ',')) ($r.Status -eq 200 -and $r.Json.next_appointment -and -not ($r.Json.PSObject.Properties.Name -contains 'diagnosis'))
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $rec)
    Check 'B6' 'B' 'Receptionist cannot read clinical records through a direct API call' '403 role_denied, no clinical data in the body' ("{0}; body has diagnosis: {1}" -f (Desc $r), ($r.Text -match 'diagnosis|Diabetes|Metformin')) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied' -and $r.Text -notmatch 'Diabetes|Metformin|diagnosis"')
    $r = Call 'POST' '/api/patients/101/export-pdf' $null (Hd $rec)
    Check 'B7' 'B' 'Receptionist cannot export a patient record (SSN/billing)' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')

    # doctor
    $r = Call 'GET' '/api/patients/list' $null (Hd $doc)
    $ids = @($r.Json.patients | ForEach-Object { $_.patient_id }) -join ','
    Check 'B8' 'B' 'Doctor sees only assigned patients in the directory' '200, patients 101,102' ("{0}, patients {1}" -f (Desc $r), $ids) ($r.Status -eq 200 -and $ids -eq '101,102')
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc)
    Check 'B9' 'B' 'Doctor can read the clinical record of an assigned patient' '200 with diagnosis, access_basis assigned' ("{0}, diagnosis={1}, basis={2}" -f (Desc $r), $r.Json.diagnosis, $r.Json.access_basis) ($r.Status -eq 200 -and $r.Json.diagnosis -and $r.Json.access_basis -eq 'assigned')
    $r = Call 'GET' '/api/patients/103/records' $null (Hd $doc)
    Check 'B10' 'B' 'Same doctor cannot read an UNASSIGNED patient (server-side)' '403 not_assigned and no clinical data' ("{0}; clinical data leaked: {1}" -f (Desc $r), ($r.Text -match 'Asthma|Albuterol')) ($r.Status -eq 403 -and $r.Json.error -eq 'not_assigned' -and $r.Text -notmatch 'Asthma|Albuterol')
    $r = Call 'GET' '/api/patients/104/summary' $null (Hd $doc)
    Check 'B11' 'B' 'Unassigned patient is denied even for the low-sensitivity summary' '403 not_assigned' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'not_assigned')
    # A patient number that does not exist is answered (and charged to the session risk) exactly like an unassigned patient, 20 points each: asking
    # for 999 and for 103 in the same fresh session costs 40 of the 60 points, so this check does not share the session above (B10 and B11 spent 40).
    $doc3 = (Login 'dr_alice').Session
    $r = Call 'GET' '/api/patients/999/records' $null (Hd $doc3)
    $r2 = Call 'GET' '/api/patients/103/records' $null (Hd $doc3)
    Check 'B12' 'B' 'Unknown patient id is answered exactly like an unassigned one (no existence oracle for a doctor)' '403 not_assigned for 999 and for 103, same text, no "not found" wording' ("999: {0}; 103: {1}; same text: {2}" -f (Desc $r), (Desc $r2), ($r.Json.message -eq $r2.Json.message)) ($r.Status -eq 403 -and $r.Json.error -eq 'not_assigned' -and $r2.Status -eq 403 -and $r.Json.message -eq $r2.Json.message -and $r.Text -notmatch 'not_found|No such patient')
    if ($doc3) { $null = Call 'POST' '/ctl/logout' $null (Hd $doc3) }

    # nurse
    $r = Call 'GET' '/api/patients/list' $null (Hd $nur)
    $ids = @($r.Json.patients | ForEach-Object { $_.patient_id }) -join ','
    Check 'B13' 'B' 'Nurse sees only patients of her ward (A) in the directory' '200, patients 101,103,105' ("{0}, patients {1}" -f (Desc $r), $ids) ($r.Status -eq 200 -and $ids -eq '101,103,105')
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $nur)
    Check 'B14' 'B' 'Nurse reads the nursing view (medication, care notes) but not the diagnosis' '200, medication and care_notes present, diagnosis absent' ("{0}, keys: {1}" -f (Desc $r), ((Keys $r.Json) -join ',')) ($r.Status -eq 200 -and $r.Json.medication -and $r.Json.care_notes -and -not ($r.Json.PSObject.Properties.Name -contains 'diagnosis'))
    $r = Call 'GET' '/api/patients/105/records' $null (Hd $nur)
    Check 'B15' 'B' 'Nurse may read an unassigned patient that is on her ward' '200, access_basis ward' ("{0}, basis={1}" -f (Desc $r), $r.Json.access_basis) ($r.Status -eq 200 -and $r.Json.access_basis -eq 'ward')
    $r = Call 'GET' '/api/patients/102/records' $null (Hd $nur)
    Check 'B16' 'B' 'Nurse cannot read a patient on another ward' '403 ward_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'ward_denied')
    $r = Call 'POST' '/api/patients/101/export-pdf' $null (Hd $nur)
    Check 'B17' 'B' 'Nurse cannot export (SSN/billing)' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')

    # security administrator
    $r = Call 'GET' '/api/patients/list' $null (Hd $adm)
    Check 'B18' 'B' 'Security administrator has NO automatic clinical access' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')
    $r = Call 'GET' '/admin/sessions' $null (Hd $adm)
    Check 'B19' 'B' 'Security administrator can use the security management functions' '200 with sessions' ("{0}, {1} sessions" -f (Desc $r), @($r.Json.sessions).Count) ($r.Status -eq 200 -and @($r.Json.sessions).Count -ge 4)
    $doc2 = (Login 'dr_alice').Session   # a fresh session: the doctor session above has collected penalty points from the denials (that is B10-B12 working as designed)
    $r = Call 'GET' '/admin/sessions' $null (Hd $doc2)
    Check 'B20' 'B' 'A doctor cannot call administrative endpoints' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')
    $r = Call 'GET' '/admin/sessions'
    Check 'B21' 'B' 'Administrative endpoints need authentication' '401 token_missing' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'token_missing')

    # client-side role claims are ignored
    $forged = Hd $rec @{ 'X-Role' = 'doctor'; 'X-ZT-Role' = 'doctor'; 'X-ZT-User' = 'U-DOC-001'; 'X-User-Role' = 'doctor' }
    $r = Call 'GET' '/api/patients/101/records' $null $forged
    Check 'B22' 'B' 'Forged role headers sent by a receptionist are ignored' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')
    $r = Call 'POST' '/ctl/login' @{ username = 'front_carol'; password = $creds['front_carol'].Password; device_kind = 'agent'; role = 'doctor' } @{ 'X-Device-Id' = $hostDevice }
    Check 'B23' 'B' 'A role supplied by the client at sign-in is ignored' 'session role is receptionist' ("role=" + $r.Json.user.role) ($r.Status -eq 200 -and $r.Json.user.role -eq 'receptionist')
    $r = Call 'POST' '/api/patients/101/export-pdf' $null (Hd $doc2)
    Check 'B24' 'B' 'Doctor export includes decrypted synthetic SSN/billing (highest sensitivity: step-up expected)' '401 step_up_required, then 200 with the PIN' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'step_up_required')
    $r = Call 'POST' '/api/patients/101/export-pdf' $null (Hd $doc2 @{ 'X-StepUp-Pin' = (Pin 'dr_alice') })
    Check 'B25' 'B' 'Export with the correct step-up PIN succeeds' '200 with ssn and billing' ("{0}, ssn present: {1}" -f (Desc $r), [bool]$r.Json.ssn) ($r.Status -eq 200 -and $r.Json.ssn -and $r.Json.billing)
    foreach ($s in @($adm, $doc, $doc2, $nur, $rec)) { if ($s) { $null = Call 'POST' '/ctl/logout' $null (Hd $s) } }
}

# =============================== E: break-glass ======================================================================================
if ($run_E) {
    Write-Host '--- E: break-glass'
    $adm = (Login 'sec_dan').Session; $doc = (Login 'dr_alice').Session; $nur = (Login 'nurse_bob').Session; $rec = (Login 'front_carol').Session
    $r = Call 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = 'too short' } (Hd $doc)
    Check 'E1' 'E' 'Break-glass without a real justification is refused' '400 justification_required' (Desc $r) ($r.Status -eq 400 -and $r.Json.error -eq 'justification_required')
    $r = Call 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = 'Patient collapsed in corridor, covering for absent colleague' } (Hd $nur)
    Check 'E2' 'E' 'A nurse cannot use break-glass' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')
    $r = Call 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = 'Patient collapsed in corridor, covering for absent colleague' } (Hd $rec)
    Check 'E3' 'E' 'A receptionist cannot use break-glass' '403 role_denied' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'role_denied')
    $r = Call 'POST' '/ctl/break-glass' @{ patient_id = 101; justification = 'Patient collapsed in corridor, covering for absent colleague' } (Hd $doc)
    Check 'E4' 'E' 'Break-glass for a patient the doctor already may see is refused as unnecessary' '400 not_needed' (Desc $r) ($r.Status -eq 400 -and $r.Json.error -eq 'not_needed')
    $null = Set-Policy $adm 'break_glass.duration_seconds' 6
    $just = 'Cardiac arrest on ward, assigned doctor unreachable <img src=x onerror=alert(1)>'
    $r = Call 'POST' '/ctl/break-glass' @{ patient_id = 103; justification = $just } (Hd $doc)
    Check 'E5' 'E' 'Break-glass with a justification creates a time-limited, audited grant' '200 with grant_id and expires_ts' ("{0}, grant {1}" -f (Desc $r), $r.Json.grant_id) ($r.Status -eq 200 -and $r.Json.grant_id)
    $gid = $r.Json.grant_id
    $r = Call 'GET' '/api/patients/103/records' $null (Hd $doc)
    Check 'E6' 'E' 'The granted patient can now be read, and the access basis says break_glass' '200, access_basis break_glass' ("{0}, basis={1}" -f (Desc $r), $r.Json.access_basis) ($r.Status -eq 200 -and $r.Json.access_basis -eq 'break_glass' -and $r.Json.diagnosis)
    $r = Call 'GET' '/api/patients/104/records' $null (Hd $doc)
    Check 'E7' 'E' 'The grant covers only that patient, not another unassigned one' '403 not_assigned' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'not_assigned')
    $ev = @(Get-Events $adm 'limit=100&type=BREAK_GLASS')
    Check 'E8' 'E' 'The break-glass grant is recorded server-side with the justification and the user' 'a BREAK_GLASS event naming dr_alice, patient 103 and the justification' ("{0} event(s); first: {1}" -f $ev.Count, $(if ($ev.Count) { $ev[0].reason } else { '-' })) ($ev.Count -ge 1 -and $ev[0].username -eq 'dr_alice' -and $ev[0].reason -like '*patient 103*' -and $ev[0].reason -like '*Cardiac arrest*')
    Start-Sleep -Seconds 7
    $r = Call 'GET' '/api/patients/103/records' $null (Hd $doc)
    Check 'E9' 'E' 'After the grant expires the access is denied again' '403 not_assigned' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'not_assigned')
    $null = Set-Policy $adm 'break_glass.duration_seconds' 600
    $doc = (Login 'dr_alice').Session   # a fresh session: the denials above already added risk to the previous one
    $r = Call 'POST' '/ctl/break-glass' @{ patient_id = 104; justification = 'Second emergency, trauma patient brought to the wrong ward' } (Hd $doc)
    $gid2 = $r.Json.grant_id
    $r = Call 'POST' '/admin/grants/revoke' @{ grant_id = $gid2 } (Hd $adm)
    $r2 = Call 'GET' '/api/patients/104/records' $null (Hd $doc)
    Check 'E10' 'E' 'A security administrator can revoke an active grant; access ends at once' 'revoke 200, then 403 not_assigned' ("revoke HTTP {0}; then {1}" -f $r.Status, (Desc $r2)) ($r.Status -eq 200 -and $r2.Status -eq 403 -and $r2.Json.error -eq 'not_assigned')
    $g = Call 'GET' '/admin/grants' $null (Hd $adm)
    Check 'E11' 'E' 'The grants list shows status and justification as plain text (XSS payload is data, not markup)' 'justification returned as a JSON string, content-type application/json' ("content-type {0}; contains payload text: {1}" -f $g.Headers['content-type'], ($g.Text -match 'onerror')) ($g.Status -eq 200 -and $g.Headers['content-type'] -like 'application/json*' -and $g.Text -match 'onerror')
    $null = Set-Policy $adm 'break_glass.duration_seconds' 900
    foreach ($s in @($adm, $doc, $nur, $rec)) { if ($s) { $null = Call 'POST' '/ctl/logout' $null (Hd $s) } }
}

# =============================== C: posture and network ==============================================================================
if ($run_C) {
    Write-Host '--- C: device posture and network changes'
    # the administrator works from a browser device here, so that stopping the laptop agent does not block the administration calls
    $adm = (Login 'sec_dan' 'ADMIN-E2E-0001' 'browser' '10.0.0.2').Session
    $doc = (Login 'dr_alice').Session
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc)
    Check 'C1' 'C' 'Healthy laptop (posture MEASURED by the agent): allowed without step-up' '200' ("{0}, score {1}" -f (Desc $r), $r.Json.access_basis) ($r.Status -eq 200)
    $s = Call 'GET' '/ctl/session' $null (Hd $doc)
    $fw = @($s.Json.device.signals | Where-Object { $_.name -eq 'firewall' })[0]
    Check 'C2' 'C' 'The session view labels the origin of every posture signal (measured / self-reported / simulated)' 'firewall is labelled as measured by the posture agent' ("firewall source: " + $fw.source) ($s.Status -eq 200 -and $fw.source -like 'measured*')

    # real agent restarted with a demo flag: the firewall is reported OFF (signed, marked simulated)
    Stop-RunAgent
    Start-RunAgent @('--fake-firewall-off')
    $dev = Wait-Device $adm { param($d) $d.heartbeat_age -le 3 -and -not $d.firewall -and $d.agent_simulated } 25
    Check 'C3' 'C' 'Posture change reaches the PDP: the agent reports the firewall OFF and marks itself SIMULATED' 'device row firewall=false, agent_simulated=true' $(if ($dev) { "firewall=$($dev.firewall) simulated=$($dev.agent_simulated) posture=$($dev.posture)" } else { 'no matching heartbeat within 25 s' }) ($null -ne $dev)
    $r = Call 'GET' '/api/patients/list' $null (Hd $doc)
    Check 'C4' 'C' 'Firewall off: the next protected request needs step-up (device score 45 + endpoint 10 = 55)' '401 step_up_required' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'step_up_required' -and $r.Json.risk_score -eq 55)
    $r = Call 'GET' '/api/patients/list' $null (Hd $doc @{ 'X-StepUp-Pin' = (Pin 'dr_alice') })
    Check 'C5' 'C' 'With the correct step-up PIN the request is allowed' '200' (Desc $r) ($r.Status -eq 200)
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc @{ 'X-StepUp-Pin' = (Pin 'dr_alice') })
    Check 'C6' 'C' 'Firewall off: a more sensitive request (45 + 30 = 75) is denied even with the PIN' '403 risk_too_high' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'risk_too_high')
    Stop-RunAgent
    Start-RunAgent
    $dev = Wait-Device $adm { param($d) $d.heartbeat_age -le 3 -and $d.firewall -and -not $d.agent_simulated } 25
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc)
    Check 'C7' 'C' 'Posture restored: access works again without step-up' '200' (Desc $r) ($null -ne $dev -and $r.Status -eq 200)

    # agent stopped -> heartbeat stale -> hard block; policy decides DENY vs REVOKE
    Stop-RunAgent
    Start-Sleep -Seconds 8
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc)
    Check 'C8' 'C' 'Agent stopped (heartbeat stale): protected access is denied' '403 posture_blocked mentioning the stopped agent' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'posture_blocked' -and $r.Json.message -like '*agent stopped*')
    $s = Call 'GET' '/ctl/session' $null (Hd $doc)
    Check 'C9' 'C' 'The session status call still works while blocked and says why' '200, device posture blocked with a reason' ("{0}, posture {1}: {2}" -f (Desc $s), $s.Json.device.posture, $s.Json.device.block_reason) ($s.Status -eq 200 -and $s.Json.device.posture -eq 'blocked' -and $s.Json.device.block_reason)
    $null = Set-Policy $adm 'device.on_blocked' 'REVOKE'
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc)
    Check 'C10' 'C' 'Policy device.on_blocked = REVOKE: the same event revokes the session on the server' '401 session_revoked' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'session_revoked' -and $r.Json.session_revoked)
    $null = Set-Policy $adm 'device.on_blocked' 'DENY'
    Start-RunAgent
    $null = Wait-Device $adm { param($d) $d.heartbeat_age -le 3 -and $d.firewall } 25

    # laptop identity cannot be claimed by another machine / a browser
    $r = Login 'dr_alice' $hostDevice 'browser'
    Check 'C11' 'C' 'A browser cannot take over the identity of the measured laptop' '403 posture_blocked' (Desc $r) ($r.Status -eq 403)
    $r = Login 'dr_alice' $hostDevice 'agent' '192.168.1.77'
    Check 'C12' 'C' 'The laptop identity used from another address (another machine) is refused' '403 posture_blocked' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'posture_blocked')

    # phone: browser device, self-reported + simulated posture
    $ph = (Login 'dr_alice' 'PHONE-E2E00001' 'browser' '10.20.30.40').Session
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C13' 'C' 'Phone (self-reported posture, base score 5): clinical record is allowed' '200' (Desc $r) ($r.Status -eq 200)
    $r = Call 'POST' '/ctl/simulate' @{ kind = 'posture'; screen_lock = $false } (Hd $ph)
    $r2 = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C14' 'C' 'SIMULATED phone posture "screen lock off" (+30): the record now needs step-up' '401 step_up_required, risk 65' ("{0}; {1}" -f (Desc $r), (Desc $r2)) ($r.Status -eq 200 -and $r2.Status -eq 401 -and $r2.Json.error -eq 'step_up_required' -and $r2.Json.risk_score -eq 65)
    $null = Call 'POST' '/ctl/simulate' @{ kind = 'posture'; os_current = $false; protection = $false } (Hd $ph)
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph @{ 'X-StepUp-Pin' = (Pin 'dr_alice') })
    Check 'C15' 'C' 'More simulated degradation (outdated OS, protection off) pushes the score past the deny limit' '403 risk_too_high' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'risk_too_high')
    $null = Call 'POST' '/ctl/simulate' @{ kind = 'posture'; screen_lock = $true; os_current = $true; protection = $true } (Hd $ph)
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C16' 'C' 'Simulated posture restored: allowed again' '200' (Desc $r) ($r.Status -eq 200)
    $doc3 = (Login 'dr_alice').Session
    $r = Call 'POST' '/ctl/simulate' @{ kind = 'posture'; screen_lock = $false } (Hd $doc3)
    Check 'C17' 'C' 'The measured laptop posture cannot be "simulated" from the portal' '400 not_simulatable' (Desc $r) ($r.Status -eq 400 -and $r.Json.error -eq 'not_simulatable')
    $null = Call 'POST' '/ctl/logout' $null (Hd $doc3)

    # network changes (the client address is supplied by the trusted edge; here by the test with the per-run edge key)
    $null = Hb $ph
    $ph.Ip = '10.20.30.77'
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C18' 'C' 'Address change inside the same /24 (DHCP-like) is only scored (+5), not blocked' '200' (Desc $r) ($r.Status -eq 200)
    $ph.Ip = '10.99.1.5'
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C19' 'C' 'Move to a different subnet: policy network.different_subnet_action = STEP_UP asks for the PIN' '401 step_up_required mentioning the network change' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'step_up_required' -and $r.Json.message -like '*network changed*')
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph @{ 'X-StepUp-Pin' = (Pin 'dr_alice') })
    $r2 = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C20' 'C' 'After a verified PIN the session adopts the new network as its baseline' '200 with the PIN, then 200 without it' ("{0}; then {1}" -f (Desc $r), (Desc $r2)) ($r.Status -eq 200 -and $r2.Status -eq 200)
    $null = Set-Policy $adm 'network.different_subnet_action' 'DENY'
    $null = Hb $ph
    $ph.Ip = '172.16.5.5'
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C21' 'C' 'Policy changed to DENY: a new network is refused, the session stays valid' '403 network_blocked' (Desc $r) ($r.Status -eq 403 -and $r.Json.error -eq 'network_blocked' -and -not $r.Json.session_revoked)
    $ph.Ip = '10.99.1.5'
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C22' 'C' 'Returning to the previous network restores access (same session)' '200' (Desc $r) ($r.Status -eq 200)
    $null = Set-Policy $adm 'network.different_subnet_action' 'REVOKE'
    $ph.Ip = '172.16.5.5'
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $ph)
    Check 'C23' 'C' 'Policy changed to REVOKE: the network change ends the session on the server' '401 session_revoked' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'session_revoked' -and $r.Json.session_revoked)
    $null = Set-Policy $adm 'network.different_subnet_action' 'STEP_UP'
    # simulated network change from the portal itself (laptop session, baseline 127.0.0.1)
    $doc2 = (Login 'dr_alice').Session
    $r = Call 'POST' '/ctl/simulate' @{ kind = 'network'; ip = '198.51.100.23' } (Hd $doc2)
    $r2 = Call 'GET' '/api/patients/101/records' $null (Hd $doc2)
    Check 'C24' 'C' 'SIMULATED network change from the portal: the server evaluates the session as coming from the new subnet' '200 simulate, then 401 step_up_required' ("{0}; {1}" -f (Desc $r), (Desc $r2)) ($r.Status -eq 200 -and $r2.Status -eq 401 -and $r2.Json.error -eq 'step_up_required')
    $null = Call 'POST' '/ctl/simulate' @{ kind = 'network'; ip = 'reset' } (Hd $doc2)
    $r = Call 'GET' '/api/patients/101/records' $null (Hd $doc2)
    Check 'C25' 'C' 'Removing the simulated network restores normal evaluation' '200' (Desc $r) ($r.Status -eq 200)
    foreach ($s in @($adm, $doc, $doc2, $ph)) { if ($s) { $null = Call 'POST' '/ctl/logout' $null (Hd $s) } }
}

# =============================== D: risk accumulation and automatic revocation =======================================================
if ($run_D) {
    Write-Host '--- D: risk accumulation, automatic revocation, lockout'
    $adm = (Login 'sec_dan').Session
    $pol = Call 'GET' '/ctl/policy' $null (Hd $adm)
    $thr = $pol.Json.policy.session.revoke_threshold
    Check 'D1' 'D' 'The risk policy and the revoke threshold are visible through the API' 'policy with session.revoke_threshold = 60 and penalties' ("threshold {0}, role_denied penalty {1}, not_assigned penalty {2}" -f $thr, $pol.Json.policy.penalties.role_denied, $pol.Json.policy.penalties.not_assigned) ($thr -eq 60 -and $pol.Json.policy.penalties.role_denied -eq 15)
    $rec = (Login 'front_carol').Session
    $seen = @(); $last = $null
    for ($i = 1; $i -le 4; $i++) { $last = Call 'GET' ('/api/patients/10' + $i + '/records') $null (Hd $rec); $seen += $last.Json.session_risk }
    Check 'D2' 'D' 'Repeated denied requests raise the session risk step by step (15, 30, 45, 60)' 'session_risk 15,30,45,60' ('session_risk ' + ($seen -join ',')) (($seen -join ',') -eq '15,30,45,60')
    Check 'D3' 'D' 'Reaching the threshold revokes the session on the server and says so' '401 session_revoked, message with the reason and the lockout time' ((Desc $last) + ' | ' + $last.Json.message) ($last.Status -eq 401 -and $last.Json.error -eq 'session_revoked' -and $last.Json.session_revoked -and $last.Json.message -like '*risk threshold*' -and $last.Json.message -like '*locked until*')
    $r = Call 'GET' '/api/public/info' $null (Hd $rec)
    Check 'D4' 'D' 'The revoked token cannot be used again (even for the public endpoint)' '401 session_revoked' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'session_revoked')
    $r = Call 'POST' '/ctl/renew' $null (Hd $rec)
    Check 'D5' 'D' 'The revoked session cannot be renewed' '401 session_revoked' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'session_revoked')
    $r = Call 'GET' '/ctl/session' $null (Hd $rec)
    Check 'D6' 'D' 'Session status of a revoked session (what a refresh / back-navigation / second tab with the old token would see)' '401 session_revoked' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'session_revoked')
    $r = Call 'GET' '/api/patients/list'
    Check 'D7' 'D' 'A new tab or a refreshed page has no token and is simply unauthenticated' '401 token_missing' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'token_missing')
    $l = Login 'front_carol'
    Check 'D8' 'D' 'Signing in again during the lockout is refused with a clear message' '423 account_locked' ((Desc $l) + ' | ' + $l.Json.message) ($l.Status -eq 423 -and $l.Json.error -eq 'account_locked' -and $l.Json.message -like '*locked until*')
    $r = Call 'POST' '/admin/unlock' @{ username = 'front_carol' } (Hd $adm)
    $l = Login 'front_carol'
    Check 'D9' 'D' 'A security administrator can unlock the account; a NEW session is issued' 'unlock 200, sign-in 200 with a different session id' ("unlock {0}; sign-in {1}; new session differs: {2}" -f $r.Status, $l.Status, ($l.Session.SessionId -ne $rec.SessionId)) ($r.Status -eq 200 -and $l.Status -eq 200 -and $l.Session.SessionId -ne $rec.SessionId)
    $r = Call 'GET' '/api/patients/list' $null (Hd $rec)
    Check 'D10' 'D' 'The old token stays dead after the account was unlocked' '401 session_revoked' (Desc $r) ($r.Status -eq 401 -and $r.Json.error -eq 'session_revoked')
    $null = Call 'POST' '/ctl/logout' $null (Hd $l.Session)

    # doctor probing unassigned patients
    $doc = (Login 'dr_alice').Session
    $codes = @(); for ($i = 0; $i -lt 3; $i++) { $x = Call 'GET' '/api/patients/104/records' $null (Hd $doc); $codes += $x.Json.error }
    Check 'D11' 'D' 'Three attempts on an unassigned patient (20 points each) revoke the doctor session' 'not_assigned, not_assigned, session_revoked' ($codes -join ', ') (($codes -join ',') -eq 'not_assigned,not_assigned,session_revoked')
    $null = Call 'POST' '/admin/unlock' @{ username = 'dr_alice' } (Hd $adm)

    # wrong step-up PIN
    $doc = (Login 'dr_alice').Session
    $null = Call 'POST' '/ctl/simulate' @{ kind = 'network'; ip = '203.0.113.9' } (Hd $doc)
    $codes = @(); for ($i = 0; $i -lt 3; $i++) { $x = Call 'GET' '/api/patients/101/records' $null (Hd $doc @{ 'X-StepUp-Pin' = '000000' }); $codes += $x.Json.error }
    Check 'D12' 'D' 'Three wrong step-up PINs (25 points each) revoke the session' 'bad_step_up_pin, bad_step_up_pin, session_revoked' ($codes -join ', ') (($codes -join ',') -eq 'bad_step_up_pin,bad_step_up_pin,session_revoked')
    $null = Call 'POST' '/admin/unlock' @{ username = 'dr_alice' } (Hd $adm)

    # suspicious requests: unknown endpoints and malformed bodies
    $nur = (Login 'nurse_bob').Session
    $codes = @()
    $codes += (Raw '/api/patients/101/records/../../admin/sessions' (Hd $nur)).Json.error
    $codes += (Raw '/api/patients/101/%2e%2e/102/records' (Hd $nur)).Json.error
    $codes += (Call 'POST' '/ctl/simulate' '{not json' (Hd $nur)).Json.error
    $codes += (Call 'GET' '/api/does/not/exist' $null (Hd $nur)).Json.error
    Check 'D13' 'D' 'Path-traversal style, unknown and malformed requests are refused and scored as suspicious' 'unknown_endpoint, unknown_endpoint, bad_request, unknown_endpoint (no data returned)' ($codes -join ', ') ($codes[0] -eq 'unknown_endpoint' -and $codes[1] -eq 'unknown_endpoint' -and $codes[2] -eq 'bad_request' -and $codes[3] -eq 'unknown_endpoint')
    $s = Call 'GET' '/ctl/session' $null (Hd $nur)
    $nr = $s.Json.session.risk_points
    Check 'D14' 'D' 'Those suspicious requests accumulated session risk (3 x 10 for unknown endpoints + 10 for the malformed body)' 'risk_points = 40' "risk_points = $nr" ($nr -eq 40)
    $null = Call 'POST' '/admin/unlock' @{ username = 'nurse_bob' } (Hd $adm)

    # policy is configurable: lower the threshold, show the effect, restore
    $null = Set-Policy $adm 'session.revoke_threshold' 30
    $rec = (Login 'front_carol').Session
    $a = Call 'GET' '/api/patients/101/records' $null (Hd $rec); $b = Call 'GET' '/api/patients/101/records' $null (Hd $rec)
    Check 'D15' 'D' 'Configurable policy: with the threshold lowered to 30, two denials revoke the session' 'role_denied, then session_revoked' ("{0}, {1}" -f $a.Json.error, $b.Json.error) ($a.Json.error -eq 'role_denied' -and $b.Json.error -eq 'session_revoked')
    $null = Set-Policy $adm 'session.revoke_threshold' 60
    $null = Call 'POST' '/admin/unlock' @{ username = 'front_carol' } (Hd $adm)
    $r = Set-Policy $adm 'session.revoke_threshold' 'abc'
    Check 'D16' 'D' 'An invalid policy change is rejected with a reason and changes nothing' '400 bad_policy_change' (Desc $r) ($r.Status -eq 400 -and $r.Json.error -eq 'bad_policy_change')
    $r = Set-Policy $adm 'bands.allow_below' 90
    Check 'D17' 'D' 'An inconsistent policy (allow band above the step-up band) is rejected' '400 bad_policy_change' (Desc $r) ($r.Status -eq 400 -and $r.Json.error -eq 'bad_policy_change')

    # burst of requests relative to the policy
    $null = Set-Policy $adm 'behavior.burst_limit' 5
    $doc = (Login 'dr_alice').Session
    $scores = @(); for ($i = 0; $i -lt 8; $i++) { $x = Call 'GET' '/api/public/info' $null (Hd $doc); $scores += $x.Json.session_risk }
    $s = Call 'GET' '/ctl/session' $null (Hd $doc)
    Check 'D18' 'D' 'A burst above the configured rate is scored as suspicious behaviour and adds session risk' 'session risk > 0 after 8 requests with burst_limit 5' ("session risk now: " + $s.Json.session.risk_points) ($s.Status -eq 200 -and $s.Json.session.risk_points -gt 0)
    $null = Set-Policy $adm 'behavior.burst_limit' 25
    $null = Call 'POST' '/ctl/logout' $null (Hd $doc)

    # admin revokes a session by hand
    $nur2 = (Login 'nurse_bob').Session
    $r = Call 'POST' '/admin/sessions/revoke' @{ session_id = $nur2.SessionId; reason = 'manual demo revocation' } (Hd $adm)
    $r2 = Call 'GET' '/api/patients/list' $null (Hd $nur2)
    Check 'D19' 'D' 'A security administrator can revoke any session; it dies on the very next request' 'revoke 200, then 401 session_revoked' ("revoke {0}; then {1}" -f $r.Status, (Desc $r2)) ($r.Status -eq 200 -and $r2.Status -eq 401 -and $r2.Json.error -eq 'session_revoked')

    # background calls of the page (token renewal, heartbeat) are not user activity
    try {
        $null = Set-Policy $adm 'session.idle_timeout_seconds' 6
        $short = Set-Policy $adm 'session.idle_timeout_seconds' 1               # the administrator session is still fresh here
        Check 'D20b' 'D' 'A policy that would end every session at once (idle timeout below 5 s) is refused' '400 bad_policy_change' (Desc $short) ($short.Status -eq 400 -and $short.Json.error -eq 'bad_policy_change')
        $ph = (Login 'dr_alice' 'IDLE-E2E-0001' 'browser' '10.20.30.40').Session
        $null = Call 'GET' '/api/patients/list' $null (Hd $ph)                  # the last USER request, at t = 0
        Start-Sleep -Seconds 3
        $rn = Call 'POST' '/ctl/renew' $null (Hd $ph)                           # timer calls at t = 3
        $hb = Hb $ph
        Start-Sleep -Seconds 4                                                  # t = 7: more than 6 s after the user request, only 4 s after the timer calls
        $late = Call 'GET' '/api/patients/list' $null (Hd $ph)
        Check 'D20' 'D' 'Token renewal and heartbeat do not count as user activity: with a 6 s idle timeout the session still expires' 'renew 200, heartbeat 200, then 401 session_expired' ("renew {0}, heartbeat {1}, then {2}" -f $rn.Status, $hb.Status, (Desc $late)) ($rn.Status -eq 200 -and $hb.Status -eq 200 -and $late.Status -eq 401 -and $late.Json.error -eq 'session_expired')
    } finally {
        $adm = (Login 'sec_dan').Session                                        # the previous administrator session has idled out under the 6 s policy
        $null = Set-Policy $adm 'session.idle_timeout_seconds' 900
    }

    # a renewal refused because of the DEVICE STATE is not suspicious behaviour; a user request on the same device still is
    $pd = (Login 'dr_alice' 'STATE-E2E-0001' 'browser' '10.20.30.41').Session
    $null = Call 'POST' '/ctl/simulate' @{ kind = 'posture'; screen_lock = $false; os_current = $false; protection = $false } (Hd $pd)
    $codes = @(); for ($i = 0; $i -lt 8; $i++) { $x = Call 'POST' '/ctl/renew' $null (Hd $pd); $codes += [string]$x.Json.error }
    $st = Call 'GET' '/ctl/session' $null (Hd $pd)
    $uq = Call 'GET' '/api/patients/101/records' $null (Hd $pd)
    $st2 = Call 'GET' '/ctl/session' $null (Hd $pd)
    $refused = @($codes | Where-Object { $_ -eq 'risk_too_high' -or $_ -eq 'posture_blocked' }).Count
    Check 'D21' 'D' 'Eight timer-driven renewals refused for device state add no risk (no lockout of an idle degraded device); a user request on it does add risk' 'refused 8 of 8, session risk 0 -> after one user request > 0' ("refused {0} of 8; risk {1} -> {2} (user request: {3})" -f $refused, $st.Json.session.risk_points, $st2.Json.session.risk_points, (Desc $uq)) ($refused -eq 8 -and $st.Json.session.risk_points -eq 0 -and $uq.Status -eq 403 -and $st2.Json.session.risk_points -gt 0)
    $null = Call 'POST' '/ctl/simulate' @{ kind = 'posture'; screen_lock = $true; os_current = $true; protection = $false } (Hd $pd)
    $r1 = Call 'POST' '/ctl/renew' $null (Hd $pd)
    $before = (Call 'GET' '/ctl/session' $null (Hd $pd)).Json.session.risk_points
    $r2 = Call 'POST' '/ctl/renew' $null (Hd $pd @{ 'X-StepUp-Pin' = '000000' })
    $after = (Call 'GET' '/ctl/session' $null (Hd $pd)).Json.session.risk_points
    Check 'D22' 'D' 'A wrong step-up PIN sent with a renewal is still penalised (the renewal endpoint cannot be used to guess the PIN for free)' 'step_up_required without PIN; bad_step_up_pin with a wrong PIN; risk +25' ("{0}; {1}; risk {2} -> {3}" -f (Desc $r1), (Desc $r2), $before, $after) ($r1.Json.error -eq 'step_up_required' -and $r2.Json.error -eq 'bad_step_up_pin' -and ($after - $before) -eq 25)
    $null = Call 'POST' '/ctl/logout' $null (Hd $pd)
    $null = Call 'POST' '/ctl/logout' $null (Hd $adm)
}

# =============================== F: evidence, dashboard data, hygiene ================================================================
if ($run_F) {
    Write-Host '--- F: evidence, dashboard data and hygiene'
    $adm = (Login 'sec_dan').Session
    $ev = @(Get-Events $adm 'limit=500')
    $codes = @($ev | ForEach-Object { $_.code } | Sort-Object -Unique)
    $need = @('role_denied', 'not_assigned', 'ward_denied', 'session_revoked', 'step_up_required', 'posture_blocked', 'network_blocked', 'bad_step_up_pin', 'risk_threshold', 'break_glass_granted')
    $missing = @($need | Where-Object { $codes -notcontains $_ })
    Check 'F1' 'F' 'Security events were recorded server-side for every kind of decision exercised above' ('events with all of: ' + ($need -join ', ')) ("{0} events; missing: {1}" -f $ev.Count, ($missing -join ', ')) ($missing.Count -eq 0)
    $one = @($ev | Where-Object { $_.code -eq 'risk_threshold' })[0]
    Check 'F2' 'F' 'A revocation event states the reason, the accumulated risk and the user' 'SESSION_REVOKED with reason "risk threshold reached (60 >= 60) ..."' $(if ($one) { $one.reason } else { 'none' }) ($one -and $one.reason -like '*risk threshold reached*' -and $one.session_risk -ge 30 -and $one.username)
    $dn = @($ev | Where-Object { $_.type -eq 'DECISION' -and $_.decision -eq 'DENY' -and $_.session_id })
    $cplt = @($dn | Where-Object { $_.username -and $null -ne $_.risk_delta -and $_.method -and $_.path -and $_.reason })
    Check 'F3' 'F' 'Each denial of a signed-in user carries session, user, request, risk change and reason' 'all DENY decision events complete' ("{0} of {1} complete" -f $cplt.Count, $dn.Count) ($dn.Count -gt 0 -and $cplt.Count -eq $dn.Count)
    $un = @($ev | Where-Object { $_.type -eq 'DECISION' -and $_.decision -eq 'DENY' -and -not $_.session_id })
    $unOk = @($un | Where-Object { $_.origin_ip -and $_.reason })
    Check 'F3b' 'F' 'Denials without a session (no token, bad token) still record the address and the reason' 'every such event has origin_ip and reason' ("{0} of {1} complete" -f $unOk.Count, $un.Count) ($un.Count -gt 0 -and $unOk.Count -eq $un.Count)
    $ss = Call 'GET' '/admin/sessions' $null (Hd $adm)
    $rv = @($ss.Json.sessions | Where-Object { $_.status -eq 'REVOKED' -and $_.revoke_reason })
    Check 'F4' 'F' 'The session list shows active and revoked sessions with the revocation reason and who did it' 'revoked sessions with revoke_reason and revoked_by' ("{0} revoked with reason; sample: {1}" -f $rv.Count, $(if ($rv.Count) { $rv[0].revoked_by + ': ' + $rv[0].revoke_reason } else { '-' })) ($rv.Count -ge 3)
    $dv = Call 'GET' '/admin/devices' $null (Hd $adm)
    $kinds = @($dv.Json.devices | ForEach-Object { $_.kind }) | Sort-Object -Unique
    Check 'F5' 'F' 'The device list shows the laptop (agent) and the phone (browser) with posture and simulated flags' 'kinds agent and browser, each with posture and signals' ("kinds: {0}; first signals: {1}" -f ($kinds -join ','), @($dv.Json.devices[0].signals).Count) ($kinds -contains 'agent' -and $kinds -contains 'browser' -and @($dv.Json.devices[0].signals).Count -gt 0)
    $sm = Call 'GET' '/admin/summary' $null (Hd $adm)
    Check 'F6' 'F' 'The summary counts sessions, denials, revocations and lockouts' '200 with counters' ("{0}: revoked={1}, denials_last_hour={2}, revocations_total={3}" -f (Desc $sm), $sm.Json.revoked_sessions, $sm.Json.denials_last_hour, $sm.Json.revocations_total) ($sm.Status -eq 200 -and $sm.Json.revocations_total -ge 3)
    $pe = @(Get-Events $adm 'limit=100&type=POLICY_CHANGE')
    Check 'F7' 'F' 'Policy changes by the administrator are audited (who, what, old and new value)' 'POLICY_CHANGE events' ("{0} event(s); latest: {1}" -f $pe.Count, $(if ($pe.Count) { $pe[0].reason } else { '-' })) ($pe.Count -ge 3 -and $pe[0].username -eq 'sec_dan')
    # hygiene
    $o = Call 'OPTIONS' '/api/patients/list'
    Check 'F8' 'F' 'No CORS: a cross-origin preflight gets no Access-Control-Allow-Origin header' 'no access-control-allow-origin' ("status {0}, header: {1}" -f $o.Status, $o.Headers['access-control-allow-origin']) (-not $o.Headers.ContainsKey('access-control-allow-origin'))
    $x = Call 'GET' '/api/public/info' $null (Hd $adm)
    Check 'F9' 'F' 'API responses are not cacheable and not sniffable' 'Cache-Control: no-store, X-Content-Type-Options: nosniff' ("cache-control={0}, nosniff={1}" -f $x.Headers['cache-control'], $x.Headers['x-content-type-options']) ($x.Headers['cache-control'] -eq 'no-store' -and $x.Headers['x-content-type-options'] -eq 'nosniff')
    $ip = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $lst = @($ip.GetActiveTcpListeners() | Where-Object { $_.Port -in 5000, 8443, 9000 })
    $nonLoop = @($lst | Where-Object { $_.Address.ToString() -ne '127.0.0.1' })
    Check 'F10' 'F' 'PEP, PDP and protected app listen on the loopback interface only (the phone can never reach them directly)' 'listeners on 5000, 8443, 9000 all 127.0.0.1' ("{0}" -f (($lst | ForEach-Object { $_.Address.ToString() + ':' + $_.Port }) -join ', ')) ($lst.Count -eq 3 -and $nonLoop.Count -eq 0)
    $web = Join-Path $repo 'web'
    if (Test-Path (Join-Path $web 'app.js')) {
        $js = Get-Content (Join-Path $web 'app.js') -Raw
        $inner = ([regex]::Matches($js, '\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write')).Count
        Check 'F11' 'F' 'The portal code never inserts untrusted data as HTML (no innerHTML/outerHTML/insertAdjacentHTML/document.write)' '0 occurrences' ("$inner occurrences") ($inner -eq 0)
        $store = [regex]::Matches($js, 'localStorage|sessionStorage|indexedDB|document\.cookie') | ForEach-Object { $_.Value } | Sort-Object -Unique
        Check 'F12' 'F' 'Only a non-secret device id may be stored in the browser; no token storage' 'storage used only for the device id key' ("storage APIs referenced: " + ($store -join ',')) ($js -notmatch 'localStorage\.setItem\([^)]*[Tt]oken' -and $js -notmatch 'sessionStorage|indexedDB|document\.cookie')
    } else {
        NotRun 'F11' 'F' 'The portal code never inserts untrusted data as HTML' '0 occurrences' 'web/app.js does not exist yet'
        NotRun 'F12' 'F' 'No token storage in the browser' 'none' 'web/app.js does not exist yet'
    }
    $null = Call 'POST' '/ctl/logout' $null (Hd $adm)
}

# ---- items that cannot be checked by this runner ------------------------------------------------------------------------------------
NotRun 'P1' 'P' 'Install the portal on the Android phone over HTTPS' 'PWA installs from the browser menu and opens standalone' 'needs the phone (manual step, not yet done)'
NotRun 'P2' 'P' 'Offline fallback on the phone' 'airplane mode shows the offline page, no patient data' 'needs the phone (manual step, not yet done)'
NotRun 'P3' 'P' 'Live scenario on the phone: sign in, permitted patient, denied patient, revocation' 'matches the matrix rows of groups B and D' 'needs the phone (manual step, not yet done)'

# ---- results of checks that were performed by hand (browser pane or phone): merged in, labelled with their method ---------------------
$manualFile = if ($ManualResults) { $ManualResults } else { Join-Path $RunDir 'reports\manual_results.json' }
if (Test-Path -LiteralPath $manualFile) {
    $manual = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $manualFile -Raw)   # a JSON array stays one object in PowerShell 5.1: iterate with foreach
    foreach ($mr in $manual) {
        $existing = @($rows | Where-Object { $_.Id -eq $mr.Id })
        foreach ($e in $existing) { $null = $rows.Remove($e) }
        $rows.Add([pscustomobject]@{ Id = $mr.Id; Group = $mr.Group; Title = $mr.Title; Expected = $mr.Expected; Actual = $mr.Actual; Result = $mr.Result; Method = $mr.Method })
        Write-Host ('{0,-6} {1,-9} {2}  [{3}]' -f $mr.Id, $mr.Result, $mr.Title, $mr.Method)
    }
}

$pass = @($rows | Where-Object Result -eq 'PASS').Count; $fail = @($rows | Where-Object Result -eq 'FAIL').Count; $nr = @($rows | Where-Object Result -eq 'NOT RUN').Count
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$md = New-Object System.Collections.Generic.List[string]
$md.Add("# Scenario matrix (end-to-end tests against the disposable run folder)")
$md.Add("")
$md.Add("Run: $stamp | $RunDir | PASS $pass, FAIL $fail, NOT RUN $nr | $([math]::Round($sw.Elapsed.TotalSeconds)) s")
$md.Add("")
$md.Add("| ID | Scenario | Expected | Actual | Method | Result |")
$md.Add("|---|---|---|---|---|---|")
foreach ($r in $rows) { $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $r.Id, ($r.Title -replace '\|', '/'), ($r.Expected -replace '\|', '/'), (($r.Actual -replace '\|', '/') -replace "[\r\n]+", ' '), $r.Method, $r.Result)) }
[System.IO.File]::WriteAllLines((Join-Path $OutDir 'scenario_matrix.md'), [string[]]$md)
[System.IO.File]::WriteAllText((Join-Path $OutDir 'scenario_matrix.json'), (ConvertTo-Json -InputObject $rows.ToArray() -Depth 4))
Write-Host ''
Write-Host ("RESULT: PASS {0}, FAIL {1}, NOT RUN {2}  ({3} s); matrix: {4}" -f $pass, $fail, $nr, [math]::Round($sw.Elapsed.TotalSeconds), (Join-Path $OutDir 'scenario_matrix.md'))
if ($fail -gt 0) { exit 1 } else { exit 0 }
