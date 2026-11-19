<#
.SYNOPSIS
  Isolated, disposable run harness for the Zero Trust Hospital Portal demo.
.DESCRIPTION
  Every action works on a run folder below %LOCALAPPDATA%\zt-demo\runs\<stamp>; the legacy live database and the project's
  db folder are never opened. Secrets are generated per run (never compiled in, never written to the project).
    setup  : create a run folder, per-run secrets and TLS keystores for the internal hops, write run.json
    build  : build the components into <run>\build (scripts\build.ps1 for the legacy components; this script for the edge)
    certs  : create (once) the demo CA in %LOCALAPPDATA%\zt-demo\ca and issue this run's edge server certificate; prints the CA fingerprint
    start  : start PDP, protected app, PEP, the TLS edge and the posture agent from the run folder
    agent  : restart only the laptop posture agent (-AgentArgs --fake-firewall-off = SIMULATED "firewall off"; without it: real measurement)
    stop   : stop exactly the processes this harness started (by recorded pid and image path)
    status : show the recorded processes and the listeners
  The edge listens on 127.0.0.1 only unless -BindAddress lists extra local addresses. Windows Firewall still decides who can reach
  such an address, and this script never adds or changes a firewall rule, network profile or certificate store: the demo CA lives in
  files only and is installed (by the user) on the phone only.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action setup
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('setup', 'build', 'certs', 'start', 'agent', 'stop', 'status')][string]$Action,
    [string]$RunDir,
    [string]$SchemaFile = 'schema_demo.sql',
    [switch]$NoAgent,
    [switch]$NoEdge,
    [switch]$EdgeUseJavaw,
    [switch]$NewCa,
    [switch]$NoNameConstraints,
    [string[]]$AgentArgs = @(),
    [string[]]$Component = @('all'),
    [string[]]$BindAddress = @(),
    [int]$HttpsPort = 9443,
    [int]$HttpPort = 8080
)
$ErrorActionPreference = 'Stop'
$AgentArgs = @($AgentArgs | ForEach-Object { $_ -split ',' } | Where-Object { $_ })       # -File mode passes "a,b" as one string
$Component = @($Component | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$BindAddress = @($BindAddress | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$base = Join-Path $env:LOCALAPPDATA 'zt-demo'
$pointer = Join-Path $base 'current.txt'

function Find-JdkBin {
    $cands = @()
    if ($env:JAVA_HOME) { $cands += (Join-Path $env:JAVA_HOME 'bin') }
    $cands += @(Get-ChildItem 'C:\Program Files\Java' -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'bin' })
    foreach ($c in $cands) { if ((Test-Path (Join-Path $c 'java.exe')) -and (Test-Path (Join-Path $c 'keytool.exe')) -and (Test-Path (Join-Path $c 'javac.exe'))) { return $c } }
    throw 'no JDK with java, javac and keytool found'
}

function New-Secret([int]$bytes = 32) {
    $b = New-Object byte[] $bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($b); $rng.Dispose()
    return ([Convert]::ToBase64String($b)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-RunDir {
    if ($RunDir) { return (Resolve-Path -LiteralPath $RunDir).Path }
    if (-not (Test-Path -LiteralPath $pointer)) { throw 'no current run: use -Action setup first' }
    return (Get-Content -LiteralPath $pointer -TotalCount 1).Trim()
}

function Read-Run($run) { return (Get-Content -LiteralPath (Join-Path $run 'run.json') -Raw | ConvertFrom-Json) }

function ConvertTo-Quoted([string[]]$a) { return (($a | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ') }

function Get-ListenerPorts {
    $ipp = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    return @($ipp.GetActiveTcpListeners() | ForEach-Object { [pscustomobject]@{ Address = $_.Address.ToString(); Port = $_.Port } })
}

function Wait-Listener([int]$port, [int]$seconds = 40) {
    $until = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $until) {
        if (@(Get-ListenerPorts | Where-Object { $_.Port -eq $port }).Count -gt 0) { return $true }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

function Start-DemoProc([string]$run, [string]$name, [string]$file, [string[]]$argList, [hashtable]$envMap) {
    $saved = @{}
    foreach ($k in $envMap.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, [string]$envMap[$k], 'Process') }
    try {
        $sp = @{ FilePath = $file; WorkingDirectory = $run; RedirectStandardOutput = (Join-Path $run "logs\$name.out.log"); RedirectStandardError = (Join-Path $run "logs\$name.err.log"); WindowStyle = 'Hidden'; PassThru = $true }
        if (@($argList).Count -gt 0) { $sp.ArgumentList = (ConvertTo-Quoted $argList) }
        $p = Start-Process @sp
        $null = $p.Handle
    } finally {
        foreach ($k in $envMap.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
    Add-Content -LiteralPath (Join-Path $run 'pids.tsv') -Value ("{0}`t{1}`t{2}`t{3}" -f $name, $p.Id, $file, (Get-Date -Format 'o'))
    return $p
}

# Runs a native tool without letting its stderr progress text abort the script; secrets go in through environment variables, never the command line.
function Invoke-Tool([string]$exe, [string[]]$argList, [hashtable]$envMap = @{}) {
    $saved = @{}
    foreach ($k in $envMap.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process'); [Environment]::SetEnvironmentVariable($k, [string]$envMap[$k], 'Process') }
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $out = & $exe @argList 2>&1 | ForEach-Object { $_.ToString() }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
        foreach ($k in $envMap.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
    return [pscustomobject]@{ Code = $code; Output = (@($out) -join "`n") }
}

function Find-OpenSsl {
    foreach ($p in @('C:\Program Files\Git\mingw64\bin\openssl.exe', 'C:\Program Files\Git\usr\bin\openssl.exe')) { if (Test-Path -LiteralPath $p) { return $p } }
    $c = Get-Command openssl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    throw 'openssl.exe not found (Git for Windows ships it); nothing was downloaded or installed'
}

function Get-LocalIPv4 {
    $res = @()
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up' -or ([string]$nic.NetworkInterfaceType) -in @('Loopback', 'Tunnel')) { continue }
        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
            $ip = $ua.Address.ToString()
            if ($ip -like '169.254.*' -or $ip -like '127.*') { continue }
            $res += [pscustomobject]@{ Adapter = $nic.Name; Ip = $ip; Prefix = [int]$ua.PrefixLength }
        }
    }
    return $res            # callers wrap the call in @() so zero or one result still behaves as an array
}
function IpToLong([string]$ip) { $b = [System.Net.IPAddress]::Parse($ip).GetAddressBytes(); return ([int64]$b[0] * 16777216 + [int64]$b[1] * 65536 + [int64]$b[2] * 256 + [int64]$b[3]) }
function LongToIp([int64]$n) {
    $o4 = $n % 256; $n = [int64][math]::Floor($n / 256)
    $o3 = $n % 256; $n = [int64][math]::Floor($n / 256)
    $o2 = $n % 256; $o1 = [int64][math]::Floor($n / 256)
    return "$o1.$o2.$o3.$o4"
}
function Test-PrivateIPv4([string]$ip) {
    $n = IpToLong $ip
    return (($n -ge (IpToLong '10.0.0.0') -and $n -le (IpToLong '10.255.255.255')) -or ($n -ge (IpToLong '172.16.0.0') -and $n -le (IpToLong '172.31.255.255')) -or ($n -ge (IpToLong '192.168.0.0') -and $n -le (IpToLong '192.168.255.255')))
}

# The demo CA is a FILE-ONLY authority: it is never added to the Windows certificate store. Only the phone is asked to trust it (user action).
# It is short-lived and NAME-CONSTRAINED (localhost, loopback, private ranges and the subnets this machine is on now), so even if the CA key
# leaked it could not be used to impersonate public web sites to the phone.
function Initialize-DemoCa {
    $caDir = Join-Path $base 'ca'
    $null = New-Item -ItemType Directory -Force -Path $caDir
    $key = Join-Path $caDir 'ca.key'; $crt = Join-Path $caDir 'ca.crt'
    $ossl = Find-OpenSsl
    $create = [bool]$NewCa -or -not (Test-Path -LiteralPath $key) -or -not (Test-Path -LiteralPath $crt)
    if (-not $create) {
        $r = Invoke-Tool $ossl @('x509', '-in', $crt, '-noout', '-checkend', '172800')
        if ($r.Code -ne 0) { $create = $true; Write-Host 'the demo CA expires within 2 days: creating a new one (the phone must install the new ca.crt)' }
    }
    if ($create) {
        $nc = @('permitted;DNS.1 = localhost', 'permitted;IP.1 = 127.0.0.0/255.0.0.0', 'permitted;IP.2 = 10.0.0.0/255.0.0.0', 'permitted;IP.3 = 172.16.0.0/255.240.0.0', 'permitted;IP.4 = 192.168.0.0/255.255.0.0')
        $n = 5
        foreach ($a in @(Get-LocalIPv4)) {
            if (Test-PrivateIPv4 $a.Ip) { continue }
            $size = [int64][math]::Pow(2, 32 - $a.Prefix)
            $netw = (IpToLong $a.Ip) - ((IpToLong $a.Ip) % $size)
            $nc += ('permitted;IP.{0} = {1}/{2}' -f $n, (LongToIp $netw), (LongToIp (4294967296 - $size))); $n++
        }
        $cnf = @('[req]', 'distinguished_name = dn', 'prompt = no', 'x509_extensions = v3_ca', '[dn]', 'CN = ZT Demo Root CA (academic demo, name-constrained)', 'O = Zero Trust Hospital Portal demo - not for production',
            '[v3_ca]', 'basicConstraints = critical, CA:TRUE, pathlen:0', 'keyUsage = critical, keyCertSign, cRLSign', 'subjectKeyIdentifier = hash')
        if (-not $NoNameConstraints) { $cnf += 'nameConstraints = critical, @nc'; $cnf += '[nc]'; $cnf += $nc }
        $cnfFile = Join-Path $caDir 'ca.cnf'
        [System.IO.File]::WriteAllLines($cnfFile, [string[]]$cnf)
        $r = Invoke-Tool $ossl @('genrsa', '-out', $key, '3072'); if ($r.Code -ne 0) { throw "openssl genrsa (CA) failed: $($r.Output)" }
        $r = Invoke-Tool $ossl @('req', '-x509', '-new', '-key', $key, '-sha256', '-days', '14', '-config', $cnfFile, '-out', $crt); if ($r.Code -ne 0) { throw "openssl req (CA) failed: $($r.Output)" }
        Remove-Item -LiteralPath (Join-Path $caDir 'ca.srl') -ErrorAction SilentlyContinue
        Write-Host "created the demo CA in $caDir (valid 14 days; name-constrained: $(-not $NoNameConstraints))"
    }
    $fp = (Invoke-Tool $ossl @('x509', '-in', $crt, '-noout', '-fingerprint', '-sha256')).Output.Trim()
    $until = (Invoke-Tool $ossl @('x509', '-in', $crt, '-noout', '-enddate')).Output.Trim()
    return [pscustomobject]@{ Dir = $caDir; Key = $key; Crt = $crt; Fingerprint = $fp; Until = $until; Openssl = $ossl }
}

# Issues (or re-issues when the local addresses changed) the edge's server certificate for this run: SANs = localhost, 127.0.0.1 and every local IPv4.
function New-EdgeCert([string]$run, $sec) {
    $ca = Initialize-DemoCa
    $ossl = $ca.Openssl
    $certs = Join-Path $run 'certs'
    $ips = @('127.0.0.1') + @(@(Get-LocalIPv4) | ForEach-Object { $_.Ip }) | Sort-Object -Unique
    $sanFile = Join-Path $certs 'edge.san.txt'
    $want = 'localhost;' + ($ips -join ';')
    $p12 = Join-Path $certs 'edge.p12'
    if ((Test-Path -LiteralPath $p12) -and (Test-Path -LiteralPath $sanFile) -and ((Get-Content -LiteralPath $sanFile -Raw).Trim() -eq $want)) {
        $r = Invoke-Tool $ossl @('verify', '-CAfile', $ca.Crt, (Join-Path $certs 'edge.crt'))
        if ($r.Code -eq 0) { return $ca }
    }
    $key = Join-Path $certs 'edge.key'; $csr = Join-Path $certs 'edge.csr'; $crt = Join-Path $certs 'edge.crt'
    $san = @('DNS.1 = localhost'); $i = 1
    foreach ($ip in $ips) { $san += ('IP.{0} = {1}' -f $i, $ip); $i++ }
    $cnf = @('[req]', 'distinguished_name = dn', 'prompt = no', '[dn]', 'CN = ZT Hospital Portal (academic demo)', 'O = Zero Trust Hospital Portal demo',
        '[v3_srv]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, keyEncipherment', 'extendedKeyUsage = serverAuth',
        'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid', 'subjectAltName = @san', '[san]') + $san
    $cnfFile = Join-Path $certs 'edge.cnf'
    [System.IO.File]::WriteAllLines($cnfFile, [string[]]$cnf)
    $r = Invoke-Tool $ossl @('genrsa', '-out', $key, '2048'); if ($r.Code -ne 0) { throw "openssl genrsa (edge) failed: $($r.Output)" }
    $r = Invoke-Tool $ossl @('req', '-new', '-key', $key, '-config', $cnfFile, '-out', $csr); if ($r.Code -ne 0) { throw "openssl req (edge) failed: $($r.Output)" }
    $r = Invoke-Tool $ossl @('x509', '-req', '-in', $csr, '-CA', $ca.Crt, '-CAkey', $ca.Key, '-CAcreateserial', '-days', '14', '-sha256', '-extfile', $cnfFile, '-extensions', 'v3_srv', '-out', $crt)
    if ($r.Code -ne 0) { throw "openssl x509 (edge) failed: $($r.Output)" }
    $r = Invoke-Tool $ossl @('pkcs12', '-export', '-inkey', $key, '-in', $crt, '-certfile', $ca.Crt, '-name', 'edge', '-out', $p12, '-passout', 'env:ZT_P12_PASS') @{ ZT_P12_PASS = $sec.edgeKsPass }
    if ($r.Code -ne 0) { throw "openssl pkcs12 failed: $($r.Output)" }
    $r = Invoke-Tool $ossl @('verify', '-CAfile', $ca.Crt, $crt); if ($r.Code -ne 0) { throw "the issued edge certificate does not verify against the demo CA: $($r.Output)" }
    Copy-Item -LiteralPath $ca.Crt -Destination (Join-Path $certs 'ca.crt') -Force
    Remove-Item -LiteralPath $key, $csr -ErrorAction SilentlyContinue                       # the private key stays only inside edge.p12
    [System.IO.File]::WriteAllText($sanFile, $want)
    Write-Host ("issued the edge certificate for: localhost, {0} (valid 14 days)" -f ($ips -join ', '))
    return $ca
}

function Build-Edge([string]$run) {
    $ri = Read-Run $run
    $out = Join-Path $run 'build\java\edge'
    $null = New-Item -ItemType Directory -Force -Path $out, (Join-Path $run 'build\reports')
    $files = @(Get-ChildItem -LiteralPath (Join-Path $repo 'edge\src') -Recurse -Filter '*.java' -File | Sort-Object FullName | ForEach-Object { $_.FullName })
    $argFile = Join-Path $run 'build\java\edge.sources.txt'
    [System.IO.File]::WriteAllLines($argFile, [string[]]@($files | ForEach-Object { '"' + ($_ -replace '\\', '/') + '"' }))
    $r = Invoke-Tool (Join-Path $ri.jdkBin 'javac.exe') @('-encoding', 'UTF-8', '-Xlint:all', '-d', $out, ('@' + $argFile))
    [System.IO.File]::WriteAllText((Join-Path $run 'build\reports\build-edge.log'), $r.Output)
    $ok = ($r.Code -eq 0) -and (Test-Path -LiteralPath (Join-Path $out 'edge\Main.class'))
    $warn = ([regex]::Matches($r.Output, 'warning:')).Count
    Write-Host ("edge: {0}; {1} sources, javac warnings: {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $files.Count, $warn)
    if (-not $ok) { Write-Host $r.Output }
    return $ok
}

switch ($Action) {
    'setup' {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $run = Join-Path $base "runs\$stamp"
        foreach ($d in @('db', 'certs', 'logs', 'build', 'secrets')) { $null = New-Item -ItemType Directory -Force -Path (Join-Path $run $d) }
        $jdk = Find-JdkBin
        $sec = [ordered]@{
            agentSecret = New-Secret; tokenSecret = New-Secret; pepAppSecret = New-Secret; internalKey = New-Secret; edgeKey = New-Secret
            patientPassphrase = New-Secret; pdpKsPass = New-Secret 18; appKsPass = New-Secret 18; edgeKsPass = New-Secret 18
        }
        [System.IO.File]::WriteAllText((Join-Path $run 'secrets\secrets.json'), ($sec | ConvertTo-Json))
        # TLS keystores for the two internal hops (self-signed, loopback only; the PEP's WinHTTP client does not validate them: documented limitation)
        $kt = Join-Path $jdk 'keytool.exe'
        foreach ($k in @(@('pdp', $sec.pdpKsPass), @('app', $sec.appKsPass))) {
            $ks = Join-Path $run ("certs\{0}_keystore.jks" -f $k[0])
            $prevPref = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # keytool prints progress on stderr
            & $kt -genkeypair -alias $k[0] -keyalg RSA -keysize 2048 -validity 30 -dname "CN=localhost" -ext "san=ip:127.0.0.1,dns:localhost" -storetype JKS -keystore $ks -storepass $k[1] -keypass $k[1] 2>$null | Out-Null
            $ktCode = $LASTEXITCODE
            $ErrorActionPreference = $prevPref
            if ($ktCode -ne 0 -or -not (Test-Path -LiteralPath $ks)) { throw "keytool failed for $($k[0]) (exit $ktCode)" }
            # public certificate of the internal hop, used by the test runner to PIN the connection (validation stays on, nothing is trusted system-wide)
            $ErrorActionPreference = 'Continue'
            & $kt -exportcert -alias $k[0] -keystore $ks -storepass $k[1] -rfc -file (Join-Path $run ("certs\{0}.cer" -f $k[0])) 2>$null | Out-Null
            $ErrorActionPreference = $prevPref
        }
        # Demo accounts (SYNTHETIC people). Passwords and PINs are generated per run; the PDP hashes them (salted PBKDF2) and deletes seed_users.json.
        # The presenter's sheet demo_credentials.txt stays in the run folder (outside the project and the evidence) and is never printed by this script.
        $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
        function New-Pass([int]$n) { $b = New-Object byte[] $n; $r = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $r.GetBytes($b); $r.Dispose(); -join ($b | ForEach-Object { $alphabet[$_ % $alphabet.Length] }) }
        function New-Pin { $b = New-Object byte[] 6; $r = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $r.GetBytes($b); $r.Dispose(); -join ($b | ForEach-Object { [string]($_ % 10) }) }
        $accounts = @(
            @{ username = 'dr_alice';    display_name = 'Dr. Alice Morgan';  role = 'doctor';         ward = $null },
            @{ username = 'nurse_bob';   display_name = 'Bob Rivera, RN';    role = 'nurse';          ward = 'A' },
            @{ username = 'front_carol'; display_name = 'Carol Singh';       role = 'receptionist';   ward = $null },
            @{ username = 'sec_dan';     display_name = 'Dan Okafor';        role = 'security_admin'; ward = $null }
        )
        $seed = @(); $sheet = @("Demo accounts for this run (synthetic people). Keep this file private; it is not part of the project or the evidence.", "")
        foreach ($a in $accounts) {
            $pw = New-Pass 12; $pin = New-Pin
            $seed += [ordered]@{ username = $a.username; display_name = $a.display_name; role = $a.role; ward = $a.ward; password = $pw; pin = $pin }
            $sheet += ("{0,-12} {1,-15} password: {2}   step-up PIN: {3}" -f $a.username, $a.role, $pw, $pin)
        }
        [System.IO.File]::WriteAllText((Join-Path $run 'secrets\seed_users.json'), (ConvertTo-Json -InputObject $seed -Depth 4))
        [System.IO.File]::WriteAllLines((Join-Path $run 'demo_credentials.txt'), [string[]]$sheet)
        $runInfo = [ordered]@{
            created = (Get-Date -Format 'o'); runDir = $run; jdkBin = $jdk; repo = $repo; schema = (Join-Path $repo "db\$SchemaFile")
            ports = [ordered]@{ pdp = 8443; app = 9000; pep = 5000; edgeHttps = 8443 + 1000; edgeHttp = 8080 }
        }
        [System.IO.File]::WriteAllText((Join-Path $run 'run.json'), ($runInfo | ConvertTo-Json -Depth 4))
        [System.IO.File]::WriteAllText($pointer, $run)
        Write-Output "run folder: $run"
        Write-Output "secrets generated (not printed), keystores: pdp_keystore.jks, app_keystore.jks"
    }
    'build' {
        $run = Get-RunDir
        $out = Join-Path $run 'build'
        $selected = @($Component)
        if ($selected -contains 'all') { $selected = @('tools', 'pdp', 'protected_app', 'pep_proxy', 'agent', 'edge') }
        $code = 0
        foreach ($c in @($selected | Where-Object { $_ -ne 'edge' })) {
            & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'scripts\build.ps1') -OutDir $out -Component $c
            if ($LASTEXITCODE -ne 0) { $code = $LASTEXITCODE }
        }
        if ($selected -contains 'edge') { if (-not (Build-Edge $run)) { $code = 1 } }
        exit $code
    }
    'certs' {
        $run = Get-RunDir
        $sec = Get-Content -LiteralPath (Join-Path $run 'secrets\secrets.json') -Raw | ConvertFrom-Json
        $ca = New-EdgeCert $run $sec
        Write-Output ("demo CA certificate (public, give this file to the phone): {0}" -f $ca.Crt)
        Write-Output ("CA {0}" -f $ca.Fingerprint)
        Write-Output ("CA {0}" -f $ca.Until)
        Write-Output ("edge certificate and PKCS12 keystore: {0}" -f (Join-Path $run 'certs'))
    }
    'start' {
        $run = Get-RunDir
        $ri = Read-Run $run
        $sec = Get-Content -LiteralPath (Join-Path $run 'secrets\secrets.json') -Raw | ConvertFrom-Json
        $jdk = $ri.jdkBin
        $java = Join-Path $jdk 'java.exe'
        $lib = @(Get-ChildItem (Join-Path $repo 'lib') -Filter '*.jar' | ForEach-Object { $_.FullName }) -join ';'
        $pidFile = Join-Path $run 'pids.tsv'
        $schema = Join-Path $repo "db\$SchemaFile"
        if (Test-Path -LiteralPath $schema) { $schemaPath = $schema } else { $schemaPath = $ri.schema }
        $common = @{ ZT_DB = (Join-Path $run 'db\zero_trust.db') }
        $pdpEnv = $common + @{
            ZT_AGENT_SECRET = $sec.agentSecret; ZT_TOKEN_SECRET = $sec.tokenSecret; ZT_SCHEMA = $schemaPath
            ZT_PDP_KEYSTORE = (Join-Path $run 'certs\pdp_keystore.jks'); ZT_PDP_KEYSTORE_PASSWORD = $sec.pdpKsPass
            ZT_INTERNAL_KEY = $sec.internalKey; ZT_RUN_DIR = $run
            ZT_SEED_USERS = (Join-Path $run 'secrets\seed_users.json')
        }
        $appEnv = $common + @{
            ZT_APP_KEYSTORE = (Join-Path $run 'certs\app_keystore.jks'); ZT_APP_KEYSTORE_PASSWORD = $sec.appKsPass
            ZT_PEP_APP_SECRET = $sec.pepAppSecret; ZT_PATIENT_PASSPHRASE = $sec.patientPassphrase
        }
        $pepEnv = @{ ZT_PEP_APP_SECRET = $sec.pepAppSecret; ZT_INTERNAL_KEY = $sec.internalKey; ZT_EDGE_KEY = $sec.edgeKey }
        $agentEnv = @{ ZT_AGENT_SECRET = $sec.agentSecret }
        $jflags = @('--enable-native-access=ALL-UNNAMED')
        $p = Start-DemoProc $run 'pdp' $java ($jflags + @('-cp', ((Join-Path $run 'build\java\pdp') + ';' + $lib), 'pdp.Main')) $pdpEnv
        if (-not (Wait-Listener 8443 60)) { throw "PDP did not start listening on 8443; see $run\logs\pdp.err.log" }
        $p = Start-DemoProc $run 'app' $java ($jflags + @('-cp', ((Join-Path $run 'build\java\protected_app') + ';' + $lib), 'app.Main')) $appEnv
        if (-not (Wait-Listener 9000 60)) { throw "protected app did not start listening on 9000; see $run\logs\app.err.log" }
        $p = Start-DemoProc $run 'pep' (Join-Path $run 'build\cpp\pep_proxy.exe') @() $pepEnv
        if (-not (Wait-Listener 5000 30)) { throw "PEP did not start listening on 5000; see $run\logs\pep.err.log" }
        if (-not $NoAgent) {
            $p = Start-DemoProc $run 'agent' (Join-Path $run 'build\cpp\agent.exe') $AgentArgs $agentEnv
            Start-Sleep -Seconds 3
        }
        if (-not $NoEdge) {
            $ca = New-EdgeCert $run $sec
            $local = @(@(Get-LocalIPv4) | ForEach-Object { $_.Ip })
            foreach ($b in $BindAddress) { if ($b -ne '127.0.0.1' -and $local -notcontains $b) { throw "-BindAddress $b is not an address of this machine ($($local -join ', '))" } }
            $binds = @('127.0.0.1') + @($BindAddress | Where-Object { $_ -ne '127.0.0.1' })
            $edgeEnv = @{
                ZT_EDGE_KEYSTORE = (Join-Path $run 'certs\edge.p12'); ZT_EDGE_KEYSTORE_PASSWORD = $sec.edgeKsPass
                ZT_EDGE_WEB = (Join-Path $repo 'web'); ZT_EDGE_KEY = $sec.edgeKey; ZT_EDGE_PEP = 'http://127.0.0.1:5000'
                ZT_EDGE_HTTPS_BIND = ($binds -join ','); ZT_EDGE_HTTPS_PORT = [string]$HttpsPort; ZT_EDGE_HTTP_PORT = [string]$HttpPort
            }
            # -EdgeUseJavaw: run the edge under javaw.exe (a different program than java.exe, which has Windows Firewall Block rules on this machine),
            # so that a firewall rule written for exactly that program and port can work. Nothing is changed by choosing it.
            $edgeExe = if ($EdgeUseJavaw) { Join-Path $jdk 'javaw.exe' } else { $java }
            $p = Start-DemoProc $run 'edge' $edgeExe @('-cp', (Join-Path $run 'build\java\edge'), 'edge.Main') $edgeEnv
            if (-not (Wait-Listener $HttpsPort 30)) { throw "the edge did not start listening on $HttpsPort; see $run\logs\edge.err.log" }
            $ri.ports.edgeHttps = $HttpsPort; $ri.ports.edgeHttp = $HttpPort
            [System.IO.File]::WriteAllText((Join-Path $run 'run.json'), ($ri | ConvertTo-Json -Depth 4))
        }
        Write-Output "started from $run"
        Get-ListenerPorts | Where-Object { $_.Port -in 5000, 8443, 9000, $HttpsPort, $HttpPort } | ForEach-Object { Write-Output ("listening {0}:{1}" -f $_.Address, $_.Port) }
        if (-not $NoEdge) {
            Write-Output ("portal on this laptop : https://localhost:{0}/   (certificate issued by the demo CA; the Windows trust store is untouched)" -f $HttpsPort)
            Write-Output ("plain loopback HTTP    : http://127.0.0.1:{0}/   (this machine only; local tests and a USB port forward)" -f $HttpPort)
            foreach ($b in $BindAddress) { Write-Output ("also listening on      : https://{0}:{1}/   (Windows Firewall decides whether other devices can connect; no rule was added)" -f $b, $HttpsPort) }
        }
    }
    'agent' {
        # Restarts ONLY the laptop posture agent of this run. With -AgentArgs --fake-firewall-off it reports a SIMULATED "firewall off" (flagged as simulated
        # in the signed heartbeat); the real Windows Firewall is never touched. Run again without -AgentArgs to return to the real measurement.
        $run = Get-RunDir
        $sec = Get-Content -LiteralPath (Join-Path $run 'secrets\secrets.json') -Raw | ConvertFrom-Json
        $pidFile = Join-Path $run 'pids.tsv'
        if (Test-Path -LiteralPath $pidFile) {
            foreach ($l in @(Get-Content -LiteralPath $pidFile | Where-Object { $_.Trim() })) {
                $f = $l -split "`t"
                if ($f[0] -like 'agent*') {
                    $p = Get-Process -Id ([int]$f[1]) -ErrorAction SilentlyContinue
                    $img = $null; if ($p) { try { $img = $p.Path } catch { } }
                    if ($p -and $img -and ($img -ieq $f[2])) { Stop-Process -Id $p.Id -Force; Write-Output ("agent (pid {0}): stopped" -f $p.Id) }
                }
            }
        }
        $null = Start-DemoProc $run 'agent' (Join-Path $run 'build\cpp\agent.exe') $AgentArgs @{ ZT_AGENT_SECRET = $sec.agentSecret }
        Write-Output ("agent started{0}" -f $(if (@($AgentArgs).Count -gt 0) { ' with: ' + ($AgentArgs -join ' ') } else { ' (real measurement)' }))
    }
    'stop' {
        $run = Get-RunDir
        $pidFile = Join-Path $run 'pids.tsv'
        if (-not (Test-Path -LiteralPath $pidFile)) { Write-Output 'no recorded processes'; break }
        $lines = @(Get-Content -LiteralPath $pidFile | Where-Object { $_.Trim() })
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            $f = $lines[$i] -split "`t"
            $procId = [int]$f[1]
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($null -eq $p) { Write-Output ("{0} (pid {1}): already gone" -f $f[0], $procId); continue }
            $img = $null; try { $img = $p.Path } catch { }
            if ($img -and ($img -ieq $f[2])) { Stop-Process -Id $procId -Force; Write-Output ("{0} (pid {1}): stopped" -f $f[0], $procId) }
            else { Write-Output ("{0} (pid {1}): NOT stopped - image path differs from the recorded one ({2})" -f $f[0], $procId, $img) }
        }
        Move-Item -LiteralPath $pidFile -Destination (Join-Path $run ("pids.stopped.{0}.tsv" -f (Get-Date -Format 'HHmmss')))
    }
    'status' {
        $run = Get-RunDir
        Write-Output "run folder: $run"
        $pidFile = Join-Path $run 'pids.tsv'
        if (Test-Path -LiteralPath $pidFile) {
            Get-Content -LiteralPath $pidFile | ForEach-Object { $f = $_ -split "`t"; Write-Output ("{0,-6} pid {1,6} alive={2}" -f $f[0], $f[1], [bool](Get-Process -Id ([int]$f[1]) -ErrorAction SilentlyContinue)) }
        } else { Write-Output 'no recorded processes' }
        Get-ListenerPorts | Where-Object { $_.Port -in 5000, 8080, 8443, 9000, 9443 } | ForEach-Object { Write-Output ("listening {0}:{1}" -f $_.Address, $_.Port) }
    }
}
