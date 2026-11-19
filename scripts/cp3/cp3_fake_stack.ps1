# cp3_fake_stack.ps1 - TEST-ONLY model of the legacy PEP + PDP + API, used for the harness dry run.
# It opens no socket and starts no process: requests are byte arrays handed to a scriptblock, answers are byte arrays.
# It encodes MY PREDICTIONS about the legacy behaviour (read from the source), so it can only show that the scenario engine and the
# verdict logic work as designed; it proves nothing about the real system. Dot-source it AFTER cp3_lib.ps1 and cp3_engine.ps1.
# Windows PowerShell 5.1, ASCII only.

function New-Cp3FakeStack {
    param([hashtable]$Creds, [string]$Device, [hashtable]$Mutations = @{})
    $st = [pscustomobject]@{
        Mut = $Mutations; Creds = $Creds; Device = $Device
        Users = @{
            dr_alice = @{ Id = 'U-DOC-001'; Role = 'doctor' }; nurse_bob = @{ Id = 'U-NUR-001'; Role = 'nurse' }
            front_carol = @{ Id = 'U-REC-001'; Role = 'receptionist' }; audit_dan = @{ Id = 'U-AUD-001'; Role = 'auditor' }
        }
        Assign = @('U-DOC-001|101', 'U-DOC-001|102', 'U-NUR-001|101', 'U-NUR-001|103')
        Perms = @{
            doctor = @('GET|/api/public/info', 'GET|/api/patients/list', 'GET|/api/patients/*/records', 'POST|/api/patients/*/export-pdf')
            nurse = @('GET|/api/public/info', 'GET|/api/patients/list', 'GET|/api/patients/*/records')
            receptionist = @('GET|/api/public/info', 'GET|/api/patients/list')
            auditor = @('GET|/api/public/info', 'GET|/api/audit/events')
        }
        Sens = @{ 'GET|/api/public/info' = 0; 'GET|/api/patients/list' = 20; 'GET|/api/patients/*/records' = 40; 'POST|/api/patients/*/export-pdf' = 60; 'GET|/api/audit/events' = 10 }
        PepAlive = $true; PepExit = $null; ApiUp = $true; PdpUp = $true
        Window = ''; Calls = (New-Object System.Collections.Generic.List[string]); OpenWindowRequests = (New-Object System.Collections.Generic.List[string])
        AgentAlive = $true; AgentStart = (Get-Cp3Now); FrozenBeat = $null
        Sessions = (New-Object System.Collections.Generic.List[object]); Events = (New-Object System.Collections.Generic.List[object])
        EventSeq = 0; ModelSeed = [guid]::NewGuid().ToString('N'); BurstOnceConsumed = $false
        Log = (New-Object System.Collections.Generic.List[string])
    }
    return $st
}

function Get-FakeBeat($St) {
    if (-not $St.AgentAlive) { return $St.FrozenBeat }
    $t = Get-Cp3Now
    return [Math]::Floor($t - (($t - $St.AgentStart) % 2.0))
}

# exit code of a PEP that dies in the model: the scratch terminate handler's 99, or (mutant) an access-violation code
function Get-FakeCrashCode($St) { if ($St.Mut.ContainsKey('pepOddExit')) { return -1073741819 } ; return 99 }

function Stop-FakeAgent($St) { $St.FrozenBeat = Get-FakeBeat $St; $St.AgentAlive = $false }
function Start-FakeAgent($St) { $St.AgentAlive = $true; $St.AgentStart = Get-Cp3Now }

function Get-FakeStaleLimit($St) { if ($St.Mut.ContainsKey('slowStale')) { return 60 } ; return 5 }

function ConvertTo-FakeBytes([int]$Status, [string]$ContentType, [string]$Body) {
    $text = if ($Status -eq 200) { 'OK' } elseif ($Status -eq 204) { 'No Content' } elseif ($Status -eq 401) { 'Unauthorized' } else { 'Forbidden' }
    $b = $script:Cp3Utf8.GetBytes($Body)
    $head = "HTTP/1.1 $Status $text`r`nContent-Type: $ContentType`r`nContent-Length: $($b.Length)`r`nConnection: close`r`n`r`n"
    $hb = $script:Cp3Latin1.GetBytes($head)
    $all = New-Object byte[] ($hb.Length + $b.Length)
    [Array]::Copy($hb, 0, $all, 0, $hb.Length)
    [Array]::Copy($b, 0, $all, $hb.Length, $b.Length)
    return $all
}

function New-FakeJsonReply([int]$Status, $Object) { return (ConvertTo-FakeBytes $Status 'application/json' (ConvertTo-Json -InputObject $Object -Compress -Depth 5)) }
function New-FakeDenied([int]$Status, [string]$Reason) { return (New-FakeJsonReply $Status ([ordered]@{ error = 'denied'; reason = $Reason })) }

function ConvertTo-FakeBase64Url([string]$Text) { return ([Convert]::ToBase64String($script:Cp3Utf8.GetBytes($Text))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-FakeSig($St, [string]$Payload) { return (Get-Cp3TextSha256 ($Payload + '|' + $St.ModelSeed)) }

function New-FakeToken($St, [string]$Sid, [string]$Uid, [string]$Dev, [string]$Origin) {
    $now = [long][Math]::Floor((Get-Cp3Now))
    $payload = ($Sid, $Uid, $Dev, $Origin, [string]$now, [string]($now + 20)) -join '|'
    return ((ConvertTo-FakeBase64Url $payload) + '.' + (Get-FakeSig $St $payload))
}

# returns @{ Ok; Reason; Sid; Uid }
function Test-FakeToken($St, [string]$Token, [string]$Device) {
    if ([string]::IsNullOrEmpty($Token)) { return @{ Ok = $false; Reason = 'missing token' } }
    $dot = $Token.IndexOf('.')
    if ($dot -lt 0) { return @{ Ok = $false; Reason = 'malformed token' } }
    $enc = $Token.Substring(0, $dot)
    $sig = $Token.Substring($dot + 1)
    $b64 = $enc.Replace('-', '+').Replace('_', '/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $payload = $null
    try { $payload = $script:Cp3Utf8.GetString([Convert]::FromBase64String($b64)) } catch { return @{ Ok = $false; Reason = 'malformed token encoding' } }
    if ($sig -cne (Get-FakeSig $St $payload)) { return @{ Ok = $false; Reason = 'signature mismatch' } }
    $p = $payload.Split('|')
    if ($p.Count -ne 6) { return @{ Ok = $false; Reason = 'malformed payload' } }
    $now = [long][Math]::Floor((Get-Cp3Now))
    if ($now -gt [long]$p[5]) { return @{ Ok = $false; Reason = 'token expired' } }
    if ($p[2] -cne $Device) { return @{ Ok = $false; Reason = 'device mismatch - possible token replay' } }
    return @{ Ok = $true; Reason = ''; Sid = $p[0]; Uid = $p[1] }
}

function Add-FakeEvent($St, $Sid, $Dev, [string]$Method, [string]$Path, [int]$Risk, [string]$Decision, [string]$Reason) {
    $St.EventSeq++
    $St.Events.Add([pscustomobject]@{ event_id = $St.EventSeq; session_id = $Sid; device_id = $Dev; method = $Method; path = $Path; risk_score = $Risk; decision = $Decision; reason = $Reason; ts = [long][Math]::Floor((Get-Cp3Now)) })
}

function Get-FakeBehavior($St, [string]$Sid) {
    if ($St.Mut.ContainsKey('behaviorBurstOnce') -and -not $St.BurstOnceConsumed) { $St.BurstOnceConsumed = $true; return 25 }
    $ts = @($St.Events | Where-Object { $_.session_id -ceq $Sid } | Sort-Object -Property event_id -Descending | Select-Object -First 10 | ForEach-Object { $_.ts })
    if ($ts.Count -lt 3) { return 0 }
    $now = [long][Math]::Floor((Get-Cp3Now))
    $current = $now - $ts[0]
    $total = 0
    for ($i = 0; $i -lt $ts.Count - 1; $i++) { $total += ($ts[$i] - $ts[$i + 1]) }
    $avg = [double]$total / ($ts.Count - 1)
    if ($avg -le 0) { return 0 }
    if (($current / $avg) -lt 0.3) { return 25 }
    return 0
}

function Get-FakeSession($St, [string]$Sid) { return @($St.Sessions | Where-Object { $_.Id -ceq $Sid } | Select-Object -First 1)[0] }

function Invoke-FakeLogin($St, $In, [string]$ClientIp) {
    $u = [string]$In.username
    $pw = [string]$In.password
    $dev = [string]$In.device_id
    if (-not $St.Users.ContainsKey($u) -or $St.Creds[$u].Password -cne $pw) { return (New-FakeJsonReply 401 ([ordered]@{ status = 'denied'; reason = 'invalid username or password' })) }
    $beat = Get-FakeBeat $St
    $age = [Math]::Floor((Get-Cp3Now)) - $beat
    if ($dev -cne $St.Device -or $age -gt (Get-FakeStaleLimit $St)) { return (New-FakeJsonReply 403 ([ordered]@{ status = 'denied'; reason = 'device posture unhealthy or agent not running - cannot start a session' })) }
    $sid = 'S-' + [guid]::NewGuid().ToString()
    $now = [long][Math]::Floor((Get-Cp3Now))
    $St.Sessions.Add([pscustomobject]@{ Id = $sid; User = $u; UserId = $St.Users[$u].Id; Role = $St.Users[$u].Role; Device = $dev; Origin = $ClientIp; Status = 'ACTIVE'; CreatedAt = $now; LastSeen = $now; Risk = 0; TerminatedBy = $null; TerminatedReason = $null })
    Add-FakeEvent $St $sid $dev 'LOGIN' '/pdp/auth/login' 0 'ALLOW' ('login granted for user ' + $u)
    return (New-FakeJsonReply 200 ([ordered]@{ status = 'ok'; token = (New-FakeToken $St $sid $St.Users[$u].Id $dev $ClientIp); session_id = $sid; role = $St.Users[$u].Role }))
}

function Invoke-FakeRenew($St, $In, [string]$ClientIp) {
    $v = Test-FakeToken $St ([string]$In.token) ([string]$In.device_id)
    if (-not $v.Ok) { return (New-FakeJsonReply 401 ([ordered]@{ status = 'denied'; reason = ('token rejected: ' + $v.Reason) })) }
    $s = Get-FakeSession $St $v.Sid
    if ($null -eq $s -or $s.Status -cne 'ACTIVE') { return (New-FakeJsonReply 403 ([ordered]@{ status = 'denied'; reason = 'session no longer active' })) }
    $age = [Math]::Floor((Get-Cp3Now)) - (Get-FakeBeat $St)
    if ($age -gt (Get-FakeStaleLimit $St)) { return (New-FakeJsonReply 403 ([ordered]@{ status = 'denied'; reason = 'device posture no longer healthy - renewal refused' })) }
    return (New-FakeJsonReply 200 ([ordered]@{ status = 'ok'; token = (New-FakeToken $St $v.Sid $v.Uid ([string]$In.device_id) $ClientIp) }))
}

function Invoke-FakeData($St, $Req, [string]$ClientIp) {
    $auth = ''
    if ($Req.Headers.ContainsKey('authorization')) { $auth = [string]$Req.Headers['authorization'] }
    $token = ''
    if ($auth.StartsWith('Bearer ')) { $token = $auth.Substring(7) }
    $dev = ''
    if ($Req.Headers.ContainsKey('x-device-id')) { $dev = [string]$Req.Headers['x-device-id'] }
    $pin = ''
    if ($Req.Headers.ContainsKey('x-stepup-pin')) { $pin = [string]$Req.Headers['x-stepup-pin'] }
    if (-not $token -or -not $dev) { return (New-FakeDenied 401 'missing Authorization bearer token or X-Device-Id header') }
    # the real PEP serializes the token into JSON for the PDP; an invalid UTF-8 byte makes that throw and the process terminates
    try { $strict = New-Object System.Text.UTF8Encoding($false, $true); [void]$strict.GetString($Req.AuthRawBytes) }
    catch {
        if ($St.Mut.ContainsKey('pepSurvives')) { return (New-FakeDenied 400 'bad header') }
        $St.PepAlive = $false; $St.PepExit = (Get-FakeCrashCode $St)
        return $null
    }
    $deny = { param($reason, $risk) return (New-FakeJsonReply 403 ([ordered]@{ error = 'denied'; risk_score = $risk; reason = $reason })) }
    $v = Test-FakeToken $St $token $dev
    if (-not $v.Ok) { $d = New-FakeJsonReply 403 ([ordered]@{ error = 'denied'; risk_score = 1000; reason = ('token rejected: ' + $v.Reason) }); Add-FakeEvent $St $null $dev $Req.Method $Req.Path 1000 'DENY' ('token rejected: ' + $v.Reason); return $d }
    $s = Get-FakeSession $St $v.Sid
    if ($null -eq $s -or $s.Status -cne 'ACTIVE') { Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path 1000 'DENY' 'session not active (expired, unknown, or terminated)'; return (& $deny 'session not active (expired, unknown, or terminated)' 1000) }
    $pattern = [regex]::Replace($Req.Path, '\d+', '*')
    $key = $Req.Method + '|' + $pattern
    if (-not $St.Sens.ContainsKey($key)) { Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path 1000 'DENY' ('unrecognized endpoint: ' + $Req.Method + ' ' + $Req.Path); return (& $deny ('unrecognized endpoint: ' + $Req.Method + ' ' + $Req.Path) 1000) }
    if ($St.Perms[$s.Role] -cnotcontains $key) { Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path 1000 'DENY' ("role '" + $s.Role + "' is not permitted on this endpoint"); return (& $deny ("role '" + $s.Role + "' is not permitted on this endpoint") 1000) }
    $age = [Math]::Floor((Get-Cp3Now)) - (Get-FakeBeat $St)
    $device = 0
    if ($dev -cne $St.Device -or $age -gt (Get-FakeStaleLimit $St)) { $device = 200 }
    $network = 0
    if ($ClientIp -cne $s.Origin) { $network = 40 }
    $assignment = 0
    if (($s.Role -eq 'doctor' -or $s.Role -eq 'nurse') -and $Req.Path -match '/api/patients/(\d+)/' -and -not $Req.Path.EndsWith('/list')) {
        if ($St.Assign -cnotcontains ($s.UserId + '|' + $Matches[1])) { $assignment = 25 }
    }
    $behavior = Get-FakeBehavior $St $v.Sid
    $data = [int]$St.Sens[$key]
    $total = $device + $network + $behavior + $data + $assignment
    $action = 'DENY'
    if ($total -lt 40) { $action = 'ALLOW' } elseif ($total -lt 70) { $action = 'STEP_UP' }
    $why = "risk=$total [device=$device, network=$network, behavior=$behavior, data=$data, assignment=$assignment] -> $action"
    $s.LastSeen = [long][Math]::Floor((Get-Cp3Now)); $s.Risk = $total
    if ($action -eq 'STEP_UP') {
        if (-not $pin) {
            Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path $total 'STEP_UP' ($why + ' (awaiting step-up PIN)')
            return (New-FakeJsonReply 401 ([ordered]@{ error = 'step_up_required'; risk_score = $total; reason = ($why + ' (awaiting step-up PIN)') }))
        }
        $ok = ($pin -ceq $St.Creds[$s.User].Pin)
        if ($St.Mut.ContainsKey('wrongPinAccepted')) { $ok = $true }
        if (-not $ok) {
            Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path $total 'DENY' ($why + ' (step-up PIN incorrect)')
            return (& $deny ($why + ' (step-up PIN incorrect)') $total)
        }
        Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path $total 'ALLOW' ($why + ' (step-up PIN verified)')
    } elseif ($action -eq 'DENY') {
        Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path $total 'DENY' $why
        return (& $deny $why $total)
    } else {
        Add-FakeEvent $St $v.Sid $dev $Req.Method $Req.Path $total 'ALLOW' $why
    }
    # the protected API's body (the real PEP forwards it unchanged)
    if ($key -eq 'GET|/api/public/info') { return (New-FakeJsonReply 200 ([ordered]@{ hospital = 'Zero Trust General Hospital'; hours = '24/7'; departments = 'General' })) }
    if ($key -eq 'GET|/api/patients/*/records') { return (New-FakeJsonReply 200 ([ordered]@{ patient_id = 101; name = 'Fake Patient'; dob = '1980-01-01'; diagnosis = 'fake'; medication = 'fake' })) }
    if ($key -eq 'POST|/api/patients/*/export-pdf') { return (New-FakeJsonReply 200 ([ordered]@{ patient_id = 101; name = 'Fake Patient'; dob = '1980-01-01'; diagnosis = 'fake'; medication = 'fake'; ssn = '987-65-4321'; billing = 'FAKE-BILLING-7777'; exported_at = 'now'; note = 'simulated' })) }
    return (New-FakeJsonReply 200 ([ordered]@{ ok = $true }))
}

function Invoke-FakeAdminTerminate($St, $In) {
    $sid = [string]$In.session_id
    $s = Get-FakeSession $St $sid
    if ($null -eq $s -or $s.Status -cne 'ACTIVE') { return (New-FakeJsonReply 404 ([ordered]@{ status = 'error'; reason = 'session not found or already terminated' })) }
    $by = 'SOC-operator'
    if (Test-Cp3HasProp $In 'terminated_by') { $by = [string]$In.terminated_by }
    $s.Status = 'TERMINATED'; $s.TerminatedBy = $by; $s.TerminatedReason = [string]$In.reason
    Add-FakeEvent $St $sid $s.Device 'ADMIN' '/pdp/admin/terminate-session' 100 'DENY' ('manually terminated by ' + $by)
    return (New-FakeJsonReply 200 ([ordered]@{ status = 'ok' }))
}

function ConvertFrom-FakeRequest([byte[]]$Bytes) {
    $end = Find-Cp3HeaderEnd $Bytes
    $r = [pscustomobject]@{ Valid = $false; Method = ''; Path = ''; Headers = @{}; AuthRawBytes = (New-Object byte[] 0); Body = (New-Object byte[] 0); BadLength = $false }
    if ($end -lt 0) { return $r }
    $head = $script:Cp3Latin1.GetString($Bytes, 0, $end)
    $lines = $head -split "`r`n"
    $parts = $lines[0].Split(' ')
    if ($parts.Count -lt 3) { return $r }
    $r.Method = $parts[0]; $r.Path = $parts[1]; $r.Valid = $true
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $c = $lines[$i].IndexOf(':')
        if ($c -le 0) { continue }
        $k = $lines[$i].Substring(0, $c).Trim().ToLowerInvariant()
        $val = $lines[$i].Substring($c + 1).Trim()
        $r.Headers[$k] = $val
        if ($k -eq 'authorization') { $r.AuthRawBytes = $script:Cp3Latin1.GetBytes($val) }
    }
    if ($r.Headers.ContainsKey('content-length') -and $r.Headers['content-length'] -notmatch '^\s*[+-]?\d') { $r.BadLength = $true }
    $start = $end + 4
    $len = $Bytes.Length - $start
    if ($len -gt 0) { $b = New-Object byte[] $len; [Array]::Copy($Bytes, $start, $b, 0, $len); $r.Body = $b }
    return $r
}

# The "socket": what the engine's $Ctx.Send scriptblock calls in a dry run.
function Invoke-FakeSend($St, [byte[]]$Bytes) {
    $res = [pscustomobject]@{ Connected = $false; Raw = (New-Object byte[] 0); ClosedBy = ''; Error = '' }
    if (-not $St.PepAlive) { $res.Error = 'connection refused (PEP not running)'; return $res }
    $res.Connected = $true
    $req = ConvertFrom-FakeRequest $Bytes
    $St.Log.Add($req.Method + ' ' + $req.Path)
    if ($St.Window -ne '') { $St.OpenWindowRequests.Add($St.Window + ' ' + $req.Method + ' ' + $req.Path) }
    if ($req.BadLength) {
        if ($St.Mut.ContainsKey('pepSurvives')) { $res.Raw = New-FakeDenied 400 'bad content-length'; $res.ClosedBy = 'fin'; return $res }
        $St.PepAlive = $false; $St.PepExit = (Get-FakeCrashCode $St); $res.ClosedBy = 'reset'; return $res
    }
    $text = ''
    if ($req.Body.Length -gt 0) { $text = $script:Cp3Utf8.GetString($req.Body) }
    $in = $null
    if ($text) { try { $in = ConvertFrom-Json -InputObject $text } catch { $in = $null } }
    $ip = '127.0.0.1'
    $reply = $null
    if ($req.Method -eq 'GET' -and ($req.Path -eq '/' -or $req.Path -eq '/index.html')) { $reply = ConvertTo-FakeBytes 200 'text/html; charset=utf-8' ('x' * 26800) }
    elseif ($req.Path -eq '/login') { if ($null -eq $in) { $reply = New-FakeDenied 400 'malformed json' } else { $reply = Invoke-FakeLogin $St $in $ip } }
    elseif ($req.Path -eq '/token/renew') { if ($null -eq $in) { $reply = New-FakeDenied 400 'malformed json' } else { $reply = Invoke-FakeRenew $St $in $ip } }
    elseif ($req.Path -eq '/admin/terminate-session') {
        if ($St.Mut.ContainsKey('protectAdmin')) { $reply = New-FakeDenied 401 'authentication required' }
        elseif ($null -eq $in) { $reply = New-FakeJsonReply 400 ([ordered]@{ status = 'error'; reason = 'malformed json' }) }
        else { $reply = Invoke-FakeAdminTerminate $St $in }
    }
    elseif ($req.Path -in @('/events/recent', '/devices', '/sessions')) {
        if ($St.Mut.ContainsKey('protectAdmin')) { $reply = New-FakeDenied 401 'authentication required' }
        elseif ($req.Path -eq '/sessions') {
            $rows = @($St.Sessions | Sort-Object -Property LastSeen -Descending | ForEach-Object { [ordered]@{ session_id = $_.Id; device_id = $_.Device; username = $_.User; role = $_.Role; origin_ip = $_.Origin; created_at = $_.CreatedAt; last_seen_ts = $_.LastSeen; current_risk_score = $_.Risk; status = $_.Status; terminated_by = $_.TerminatedBy; terminated_reason = $_.TerminatedReason } })
            $reply = ConvertTo-FakeBytes 200 'application/json' (ConvertTo-Json -InputObject $rows -Compress -Depth 4)
        } elseif ($req.Path -eq '/devices') {
            $age = [Math]::Floor((Get-Cp3Now)) - (Get-FakeBeat $St)
            $st2 = 'HEALTHY'
            if ($age -gt (Get-FakeStaleLimit $St)) { $st2 = 'STALE' }
            $rows = @([ordered]@{ device_id = $St.Device; hostname = 'fake'; os = 'Windows'; firewall_active = $true; antivirus_active = $true; signature_valid = $true; heartbeat_age_seconds = $age; status = $st2 })
            $reply = ConvertTo-FakeBytes 200 'application/json' (ConvertTo-Json -InputObject $rows -Compress -Depth 4)
        } else {
            $rows = @($St.Events | Sort-Object -Property event_id -Descending | Select-Object -First 50 | ForEach-Object { [ordered]@{ event_id = $_.event_id; session_id = $_.session_id; device_id = $_.device_id; method = $_.method; path = $_.path; risk_score = $_.risk_score; decision = $_.decision; reason = $_.reason; ts = $_.ts } })
            $reply = ConvertTo-FakeBytes 200 'application/json' (ConvertTo-Json -InputObject $rows -Compress -Depth 4)
        }
    }
    else {
        $reply = Invoke-FakeData $St $req $ip
        if ($null -eq $reply) { $res.ClosedBy = 'reset'; return $res }
    }
    $res.Raw = $reply
    $res.ClosedBy = 'fin'
    return $res
}

# The planned-exit controls follow the rules of the real ones (Enter-Cp3PlannedExit / Exit-Cp3PlannedExit): the same allowed (role, step) pairs and the same
# planned PEP exit code come from the same functions; a window must be closed by the step that opened it, and only with the role running again.
function New-Cp3FakeControl($St) {
    return @{
        StopAgent = { Stop-FakeAgent $St; return 'stopped (model)' }.GetNewClosure()
        StartAgentAndWait = { Start-FakeAgent $St; Wait-Cp3Seconds 2.0; return $true }.GetNewClosure()
        PepExitInfo = { return [pscustomobject]@{ Exited = (-not $St.PepAlive); ExitCode = $St.PepExit } }.GetNewClosure()
        RestartPep = {
            if ($St.Mut.ContainsKey('pepNotRestored')) { return $false }
            $St.PepAlive = $true; $St.PepExit = $null; return $true
        }.GetNewClosure()
        PortsListening = { return [pscustomobject]@{ Api = $St.ApiUp; Pdp = $St.PdpUp; Pep = $St.PepAlive } }.GetNewClosure()
        BeginPlannedExit = {
            param($role, $step)
            $St.Calls.Add('begin ' + $role + ' ' + $step)
            if (-not (Test-Cp3PlannedExitAllowed $role $step)) { throw ("RUN STATE VIOLATION: a planned exit of '$role' is not permitted at step '$step'") }
            if ($St.Window -ne '') { throw ("RUN STATE VIOLATION: the planned-exit window '" + $St.Window + "' is still open") }
            $St.Window = $role + '@' + $step
        }.GetNewClosure()
        EndPlannedExit = {
            param($role, $step, $exitInfo)
            $St.Calls.Add('end ' + $role + ' ' + $step)
            if ($St.Window -cne ($role + '@' + $step)) { throw ("RUN STATE VIOLATION: cannot close the planned-exit window '" + $role + '@' + $step + "' (open window: '" + $St.Window + "')") }
            if ($role -ceq 'pep' -and $null -ne $exitInfo -and [bool]$exitInfo.Exited) {
                if ($null -eq $exitInfo.ExitCode -or (Get-Cp3PepPlannedExitCodes) -notcontains [int]$exitInfo.ExitCode) { throw ('RUN STATE VIOLATION: unexplained exit of the PEP at ' + $step) }
            }
            if ($role -ceq 'pep' -and -not $St.PepAlive) { throw ('RUN STATE VIOLATION: the PEP is not running after the planned exit at ' + $step) }
            if ($role -ceq 'agent' -and -not $St.AgentAlive) { throw ('RUN STATE VIOLATION: the agent is not running after the planned exit at ' + $step) }
            $St.Window = ''
        }.GetNewClosure()
    }
}
