# smoke_legacy.ps1 - baseline smoke test of the LEGACY decision logic, run against the disposable run folder only.
# Credentials are read from the legacy schema comment at run time and are never printed.
param([string]$Pep = 'http://127.0.0.1:5000', [string]$Device = ('DEV-' + $env:COMPUTERNAME))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$http = New-Object System.Net.Http.HttpClient
$http.Timeout = [TimeSpan]::FromSeconds(20)
$schema = Get-Content -LiteralPath 'C:\Ap project\db\schema.sql' -Raw
$pw = [regex]::Match($schema, 'Password for all demo accounts:\s*(\S+)').Groups[1].Value
$pin = [regex]::Match($schema, 'Step-up PIN for all demo accounts:\s*(\S+)').Groups[1].Value

function Call([string]$method, [string]$path, $body, [hashtable]$headers) {
    $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::new($method), ($Pep + $path))
    foreach ($k in $headers.Keys) { $null = $req.Headers.TryAddWithoutValidation($k, [string]$headers[$k]) }
    if ($null -ne $body) { $req.Content = New-Object System.Net.Http.StringContent ((ConvertTo-Json -Compress -InputObject $body), [System.Text.Encoding]::UTF8, 'application/json') }
    $resp = $http.SendAsync($req).GetAwaiter().GetResult()
    $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $obj = $null; try { $obj = $text | ConvertFrom-Json } catch { }
    [pscustomobject]@{ Status = [int]$resp.StatusCode; Json = $obj; Text = $text }
}
function Login([string]$user) { $r = Call 'POST' '/login' @{ username = $user; password = $pw; device_id = $Device } @{}; $r }

$results = New-Object System.Collections.Generic.List[object]
function Check([string]$id, [string]$what, [bool]$ok, [string]$detail) { $script:results.Add([pscustomobject]@{ Id = $id; Check = $what; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail }) }

$r = Call 'GET' '/api/patients/list' $null @{}
Check 'L1' 'no token -> denied' ($r.Status -eq 401) "status $($r.Status)"

$doc = Login 'dr_alice'
Check 'L2' 'doctor login with a healthy agent device' ($doc.Status -eq 200 -and $doc.Json.token) "status $($doc.Status)"
$h = @{ Authorization = 'Bearer ' + $doc.Json.token; 'X-Device-Id' = $Device }
$r = Call 'GET' '/api/patients/list' $null $h
Check 'L3' 'doctor patient list' ($r.Status -eq 200) "status $($r.Status)"
$r = Call 'GET' '/api/patients/101/records' $null $h
Check 'L4' 'assigned patient records need step-up (legacy: sensitivity 40)' ($r.Status -eq 401) "status $($r.Status)"
$h2 = $h.Clone(); $h2['X-StepUp-Pin'] = $pin
$r = Call 'GET' '/api/patients/101/records' $null $h2
Check 'L5' 'assigned patient records with step-up PIN' ($r.Status -eq 200 -and $r.Json.diagnosis) "status $($r.Status)"
$r = Call 'GET' '/api/patients/104/records' $null $h2
Check 'L6' 'LEGACY WEAKNESS: unassigned patient is reachable with the step-up PIN (soft assignment rule)' ($r.Status -eq 200) "status $($r.Status) (the new design makes this a hard deny)"

$rec = Login 'front_carol'
$hr = @{ Authorization = 'Bearer ' + $rec.Json.token; 'X-Device-Id' = $Device }
$r = Call 'GET' '/api/patients/101/records' $null $hr
Check 'L7' 'receptionist cannot read clinical records (RBAC)' ($r.Status -eq 403) "status $($r.Status)"

$r = Call 'GET' '/sessions' $null @{}
Check 'L8' 'LEGACY WEAKNESS: session list readable without authentication' ($r.Status -eq 200) "status $($r.Status) (to be closed)"

$results | Format-Table -AutoSize -Wrap | Out-String -Width 220
$f = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
"legacy smoke: {0} checks, {1} FAIL" -f $results.Count, $f
