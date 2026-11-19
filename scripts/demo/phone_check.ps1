<#
.SYNOPSIS
  READ-ONLY diagnostics before putting the portal on a phone: the laptop's Wi-Fi IPv4, the HTTPS listener, the certificate (SAN coverage, name
  constraints, validity), a real TLS handshake validated against the demo CA only, and the facts Chrome needs to offer "Install app".
.DESCRIPTION
  Changes nothing: no firewall rule, network setting, certificate store, listener or file in the project is created or modified.
  Windows Firewall rules and network profiles are only listed. The only thing written is an optional report file in the current run folder
  (reports\phone_check.txt). No credentials are read or printed. Nothing here proves what a physical phone will do: rows P1-P3 stay NOT RUN.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\phone_check.ps1
#>
[CmdletBinding()]
param(
    [string]$RunDir,
    [int]$HttpsPort = 9443,
    [int]$HttpPort = 8080,
    [switch]$NoReportFile
)
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:LOCALAPPDATA 'zt-demo'
if (-not $RunDir) { $RunDir = (Get-Content (Join-Path $base 'current.txt') -TotalCount 1).Trim() }
$caCrt = Join-Path $base 'ca\ca.crt'
$edgeCrt = Join-Path $RunDir 'certs\edge.crt'
$lines = New-Object System.Collections.Generic.List[string]
function Out([string]$text) { $lines.Add($text); Write-Host $text }
function Head([string]$text) { Out ''; Out ('=== ' + $text) }
function RunTool([string]$Exe, [string[]]$ToolArgs) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $o = & $Exe @ToolArgs 2>&1 | ForEach-Object { $_.ToString() }; $c = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $c; Output = (@($o) -join "`n") }
}
function Find-Exe([string[]]$Candidates) { foreach ($c in $Candidates) { if (Test-Path -LiteralPath $c) { return $c } }; $null }
$openssl = Find-Exe @('C:\Program Files\Git\mingw64\bin\openssl.exe', 'C:\Program Files\Git\usr\bin\openssl.exe')
$curl = Find-Exe @((Join-Path $env:SystemRoot 'System32\curl.exe'))
function ParseCertDate([string]$line) {
    $s = ($line -replace '^\w+=', '') -replace '\s+', ' ' -replace ' GMT$', ''
    [datetime]::SpecifyKind([datetime]::ParseExact($s, 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture), 'Utc')
}

Out ("phone_check (READ-ONLY) {0}   run folder: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $RunDir)

# ------------------------------------------------------------------------------------------------ 1. the laptop's addresses
Head '1. Laptop network (read-only)'
$nics = @()
foreach ($c in @(Get-NetIPConfiguration | Where-Object { $_.IPv4Address })) {
    $prof = Get-NetConnectionProfile -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue
    $ad = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue
    $ip = [string]$c.IPv4Address[0].IPAddress
    $row = [pscustomobject]@{ Name = $c.InterfaceAlias; Ip = $ip; Prefix = [int]$c.IPv4Address[0].PrefixLength; Gateway = (($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ','); Category = [string]$prof.NetworkCategory; Network = [string]$prof.Name; Desc = [string]$ad.InterfaceDescription; Up = ([string]$ad.Status -eq 'Up') }
    $nics += $row
    Out ("{0,-26} IPv4 {1}/{2}  gateway {3}  profile {4} ({5})  [{6}]" -f $row.Name, $row.Ip, $row.Prefix, $(if ($row.Gateway) { $row.Gateway } else { '-' }), $(if ($row.Category) { $row.Category } else { '-' }), $(if ($row.Network) { $row.Network } else { '-' }), $row.Desc)
}
$wifi = @($nics | Where-Object { $_.Up -and $_.Gateway -and $_.Ip -notlike '169.254.*' -and $_.Desc -notmatch 'VirtualBox|Virtual|VMware|Hyper-V|Bluetooth' })
if ($wifi.Count -eq 1) { Out ("-> the address a phone on the same Wi-Fi would use: {0}   (network '{1}', category {2})" -f $wifi[0].Ip, $wifi[0].Network, $wifi[0].Category) }
elseif ($wifi.Count -gt 1) { Out ("-> several candidate addresses: {0}" -f (($wifi | ForEach-Object { $_.Ip + ' (' + $_.Name + ')' }) -join ', ')) }
else { Out '-> no connected adapter with a default gateway: the laptop is not on a Wi-Fi/LAN network right now (the USB route does not need one)' }
$wifiIp = if ($wifi.Count -ge 1) { $wifi[0].Ip } else { $null }

# ------------------------------------------------------------------------------------------------ 2. the listeners
Head '2. HTTPS and HTTP listeners of the portal (read-only)'
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in $HttpsPort, $HttpPort, 5000, 8443, 9000 })
foreach ($l in ($listen | Sort-Object LocalPort, LocalAddress)) {
    $pn = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Out ("listening {0,-15}:{1,-5}  process {2}" -f $l.LocalAddress, $l.LocalPort, $pn)
}
$httpsAddrs = @($listen | Where-Object { $_.LocalPort -eq $HttpsPort } | ForEach-Object { $_.LocalAddress })
$httpAddrs = @($listen | Where-Object { $_.LocalPort -eq $HttpPort } | ForEach-Object { $_.LocalAddress })
$loopHttps = $httpsAddrs -contains '127.0.0.1'; $loopHttp = $httpAddrs -contains '127.0.0.1'
$wifiBound = $false
if ($wifiIp) { $wifiBound = ($httpsAddrs -contains $wifiIp) -or ($httpsAddrs -contains '0.0.0.0') }
Out ("HTTPS {0} on loopback: {1};  HTTP {2} on loopback: {3};  HTTPS reachable on the Wi-Fi address{4}: {5}" -f $HttpsPort, $loopHttps, $HttpPort, $loopHttp, $(if ($wifiIp) { ' ' + $wifiIp } else { '' }), $wifiBound)
if (-not $wifiBound) { Out '   (the edge listens on loopback only: a phone on Wi-Fi cannot connect until it is started with -BindAddress <Wi-Fi IPv4>; the USB route needs only the loopback listener)' }
$exposed = @($listen | Where-Object { $_.LocalPort -in 5000, 8443, 9000 -and $_.LocalAddress -notin '127.0.0.1', '::1' })
Out ("internal ports (5000, 8443, 9000) listening on a non-loopback address: {0}" -f $(if ($exposed.Count) { ($exposed | ForEach-Object { $_.LocalAddress + ':' + $_.LocalPort }) -join ', ' } else { 'none (good: only the edge may be reachable)' }))

# ------------------------------------------------------------------------------------------------ 3. certificate
Head '3. Certificates (read-only, openssl)'
$certOk = $false
if (-not $openssl) { Out 'openssl.exe (Git for Windows) not found: certificate checks NOT RUN' }
elseif (-not (Test-Path -LiteralPath $edgeCrt)) { Out ("no edge certificate in this run folder ({0}): run  demo.ps1 -Action start  first" -f $edgeCrt) }
elseif (-not (Test-Path -LiteralPath $caCrt)) { Out ("no demo CA file ({0})" -f $caCrt) }
else {
    $txt = (RunTool $openssl @('x509', '-in', $edgeCrt, '-noout', '-text')).Output
    $m = [regex]::Match($txt, 'Subject Alternative Name:\s*\r?\n\s*([^\r\n]+)')
    $sanLine = $m.Groups[1].Value.Trim()
    Out ("edge certificate SAN : {0}" -f $sanLine)
    $sd = (RunTool $openssl @('x509', '-in', $edgeCrt, '-noout', '-startdate')).Output; $ed = (RunTool $openssl @('x509', '-in', $edgeCrt, '-noout', '-enddate')).Output
    $from = ParseCertDate $sd.Trim(); $until = ParseCertDate $ed.Trim()
    Out ("edge certificate valid: {0:yyyy-MM-dd HH:mm} UTC  to  {1:yyyy-MM-dd HH:mm} UTC   ({2:N1} days left)" -f $from, $until, ($until - [datetime]::UtcNow).TotalDays)
    $csd = (RunTool $openssl @('x509', '-in', $caCrt, '-noout', '-enddate')).Output; $cuntil = ParseCertDate $csd.Trim()
    Out ("demo CA valid until   : {0:yyyy-MM-dd HH:mm} UTC   ({1:N1} days left)" -f $cuntil, ($cuntil - [datetime]::UtcNow).TotalDays)
    Out ("demo CA fingerprint   : {0}" -f ((RunTool $openssl @('x509', '-in', $caCrt, '-noout', '-fingerprint', '-sha256')).Output.Trim()))
    $caTxt = (RunTool $openssl @('x509', '-in', $caCrt, '-noout', '-text')).Output
    $caLines = @($caTxt -split '\r?\n'); $ncIdx = -1
    for ($i = 0; $i -lt $caLines.Count; $i++) { if ($caLines[$i] -match 'Name Constraints') { $ncIdx = $i; break } }
    $ncItems = New-Object System.Collections.Generic.List[string]
    if ($ncIdx -ge 0) { for ($j = $ncIdx + 1; $j -lt $caLines.Count; $j++) { if ($caLines[$j] -match 'X509v3 |Signature Algorithm') { break }; $t2 = $caLines[$j].Trim(); if ($t2) { $ncItems.Add($t2) } } }
    Out ("demo CA name constraints (the only names/addresses it may vouch for): {0}" -f $(if ($ncItems.Count) { $ncItems -join ' ' } else { 'NONE' }))
    Out ("demo CA may issue sub-CAs: {0}" -f $(if ($caTxt -match 'pathlen:0') { 'no (pathlen 0)' } else { 'NOT limited' }))
    $check = New-Object System.Collections.Generic.List[string]
    $targets = @(@{ N = 'localhost'; T = 'host' }, @{ N = '127.0.0.1'; T = 'ip' })
    foreach ($n in $nics) { if ($n.Ip -notlike '169.254.*') { $targets += @{ N = $n.Ip; T = 'ip' } } }
    $allOk = $true
    foreach ($t in $targets) {
        $flag = if ($t.T -eq 'host') { '-verify_hostname' } else { '-verify_ip' }
        $r = RunTool $openssl @('verify', '-CAfile', $caCrt, $flag, $t.N, $edgeCrt)
        $ok = ($r.Code -eq 0 -and $r.Output -match ': OK')
        Out ("   chain + name check for {0,-16}: {1}" -f $t.N, $(if ($ok) { 'OK (signed by the demo CA, name covered, within the CA name constraints)' } else { 'NOT OK  ' + (($r.Output -split "`n" | Select-Object -Last 2) -join ' ') }))
        if ($t.N -eq $wifiIp -or $t.N -in 'localhost', '127.0.0.1') { $allOk = $allOk -and $ok }
    }
    $certOk = $allOk
    Out ("-> certificate covers localhost, 127.0.0.1{0}: {1}" -f $(if ($wifiIp) { ' and the Wi-Fi address ' + $wifiIp } else { '' }), $certOk)
}

# ------------------------------------------------------------------------------------------------ 4. a real TLS handshake validated only against the demo CA
Head '4. TLS handshakes from this laptop, validated ONLY against the demo CA file (curl; the Windows trust store is not used or changed)'
if ($curl -and (Test-Path -LiteralPath $caCrt)) {
    $urls = New-Object System.Collections.Generic.List[string]
    if ($loopHttps) { $urls.Add("https://localhost:$HttpsPort/"); $urls.Add("https://127.0.0.1:$HttpsPort/") }
    if ($wifiBound) { $urls.Add("https://${wifiIp}:$HttpsPort/") }
    if ($urls.Count -eq 0) { Out 'no HTTPS listener found: NOT RUN' }
    foreach ($u in $urls) {
        $r = RunTool $curl @('-sS', '--cacert', $caCrt, '--ssl-no-revoke', '--max-time', '15', '-o', 'NUL', '-w', '%{http_code}|%{ssl_verify_result}|%{scheme}', $u)
        $last = ($r.Output -split "`n")[-1]
        Out ("   {0,-34} curl exit {1}, HTTP|verify|scheme = {2}   {3}" -f $u, $r.Code, $last, $(if ($r.Code -eq 0 -and $last -like '200|0|*') { 'OK' } else { 'NOT OK' }))
    }
    $r = RunTool $curl @('-sS', '--max-time', '15', '-o', 'NUL', '-w', '%{http_code}', "http://127.0.0.1:$HttpPort/")
    Out ("   {0,-34} curl exit {1}, HTTP {2}   (plain loopback HTTP; Chrome on a phone treats http://localhost as a secure context only through the USB forward)" -f "http://127.0.0.1:$HttpPort/", $r.Code, ($r.Output -split "`n")[-1])
} else { Out 'curl.exe or the CA file is missing: NOT RUN' }

# ------------------------------------------------------------------------------------------------ 5. installability facts
Head '5. Installability facts served by the portal (read-only GET over loopback HTTP; Chrome decides on the phone)'
try {
    Add-Type -AssemblyName System.Net.Http
    $http = New-Object System.Net.Http.HttpClient; $http.Timeout = [TimeSpan]::FromSeconds(15)
    $b = "http://127.0.0.1:$HttpPort"
    function Get-Http([string]$p) { $resp = $http.GetAsync($b + $p).GetAwaiter().GetResult(); [pscustomobject]@{ Status = [int]$resp.StatusCode; Type = [string]$resp.Content.Headers.ContentType; Body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult(); Len = $resp.Content.Headers.ContentLength } }
    $idx = Get-Http '/'
    Out ("   /                      HTTP {0}  {1}  viewport meta: {2}  manifest link: {3}  theme-color: {4}" -f $idx.Status, $idx.Type, ($idx.Body -match 'name="viewport"'), ($idx.Body -match 'rel="manifest"'), ($idx.Body -match 'name="theme-color"'))
    $mf = Get-Http '/manifest.webmanifest'
    $man = $null; try { $man = $mf.Body | ConvertFrom-Json } catch { }
    if ($man) {
        Out ("   /manifest.webmanifest  HTTP {0}  {1}  name '{2}'  short_name '{3}'  start_url '{4}'  scope '{5}'  display '{6}'" -f $mf.Status, $mf.Type, $man.name, $man.short_name, $man.start_url, $man.scope, $man.display)
        foreach ($ic in @($man.icons)) {
            $ir = Get-Http ('/' + ([string]$ic.src).TrimStart('/'))
            Out ("   icon {0,-26} {1,-9} {2,-9} -> HTTP {3} {4}" -f $ic.src, $ic.sizes, $ic.purpose, $ir.Status, $ir.Type)
        }
    } else { Out ("   /manifest.webmanifest  HTTP {0}: not valid JSON" -f $mf.Status) }
    $sw = Get-Http '/sw.js'
    Out ("   /sw.js                 HTTP {0}  {1}  cache name: {2}" -f $sw.Status, $sw.Type, ([regex]::Match($sw.Body, "VERSION = '([^']+)'").Groups[1].Value))
    $off = Get-Http '/offline.html'
    Out ("   /offline.html          HTTP {0}  {1}" -f $off.Status, $off.Type)
    $http.Dispose()
} catch { Out ("   installability facts: could not read the portal: {0}" -f $_.Exception.Message) }
Out '   Chrome offers "Install app" only on HTTPS or on localhost, with the manifest, icons and service worker above. The desktop Chrome installability check passed in test W4;'
Out '   whether the PHONE offers installation, and whether it creates a full WebAPK or only a shortcut for a private origin, is NOT RUN until you try it (rows P1-P3).'

# ------------------------------------------------------------------------------------------------ 6. firewall (listed only)
Head '6. Windows Firewall (LISTED ONLY - nothing was added, changed or removed)'
$fwp = @(Get-NetFirewallProfile)
Out ("   profiles: " + (($fwp | ForEach-Object { '{0}: enabled={1}' -f $_.Name, $_.Enabled }) -join ';  '))
$allFw = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)
$zt = @($allFw | Where-Object { $_.DisplayName -like 'ZT*' })
Out ("   rules named ZT*: {0}" -f $zt.Count)
foreach ($z in $zt) { Out ("      {0}  enabled={1} action={2} direction={3} profile={4}" -f $z.DisplayName, $z.Enabled, $z.Action, $z.Direction, $z.Profile) }
$jv = @($allFw | Where-Object { $_.DisplayName -like '*Java*' -and $_.Direction -eq 'Inbound' })
Out ("   inbound rules with 'Java' in the name: {0}" -f $jv.Count)
foreach ($j in ($jv | Select-Object -First 8)) { Out ("      {0}  enabled={1} action={2} profile={3}" -f $j.DisplayName, $j.Enabled, $j.Action, $j.Profile) }

# ------------------------------------------------------------------------------------------------ verdict
Head 'Verdict (what these read-only checks can and cannot say)'
Out ("USB route (Chrome port forwarding, no Windows change): loopback listeners present = {0}; certificate valid for localhost = see section 3." -f ($loopHttps -and $loopHttp))
Out ("Wi-Fi route: edge listening on the Wi-Fi address = {0}; a firewall rule for it would have to be created by YOU after approval (none exists: {1}); campus Wi-Fi client isolation cannot be read from here." -f $wifiBound, ($zt.Count -eq 0))
Out 'Physical-phone behaviour (install, offline page, live scenario, certificate installation on the phone) is NOT RUN: only you can run it.'

if (-not $NoReportFile) {
    $rep = Join-Path $RunDir 'reports'
    $null = New-Item -ItemType Directory -Force -Path $rep
    [System.IO.File]::WriteAllLines((Join-Path $rep 'phone_check.txt'), [string[]]$lines)
    Write-Host ''
    Write-Host ("report written to {0}" -f (Join-Path $rep 'phone_check.txt'))
}
