# cp3_engine.ps1 - the CP3 scenario engine (Phase B logic).  Dot-source it AFTER cp3_lib.ps1.
# Windows PowerShell 5.1, ASCII only.
# The engine only talks through $Ctx.Send (a scriptblock). In a real run that is Send-Cp3Raw (127.0.0.1:15000 only); in the harness
# dry run it is a model of the legacy stack that opens no socket and starts no process. Expected results come from the FROZEN file
# tests\baseline\cp3_expectations.json; a mismatch is reported as "prediction wrong" and never edited away.

# ---------------------------------------------------------------- generic helpers
function Test-Cp3IsNumber($x) { return ($x -is [int] -or $x -is [long] -or $x -is [double] -or $x -is [decimal] -or $x -is [single] -or $x -is [int16] -or $x -is [byte]) }

function Test-Cp3Equal($a, $b) {
    if ($null -eq $a -or $null -eq $b) { return ($null -eq $a -and $null -eq $b) }
    if ($a -is [bool] -or $b -is [bool]) { return ([bool]$a -eq [bool]$b) }
    if ((Test-Cp3IsNumber $a) -and (Test-Cp3IsNumber $b)) { return ([double]$a -eq [double]$b) }
    return ([string]$a -ceq [string]$b)
}

function Get-Cp3Path($Obj, [string]$Path) {
    $cur = $Obj
    foreach ($seg in $Path.Split('.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null }
        } else {
            $p = $cur.PSObject.Properties[$seg]
            if ($null -eq $p) { return $null }
            $cur = $p.Value
        }
    }
    return $cur
}

function Test-Cp3HasProp($Obj, [string]$Name) { return ($null -ne $Obj -and $null -ne $Obj.PSObject.Properties[$Name]) }

# One check: { path, op, value }. Returns $null when it holds, otherwise a short description of the failure.
function Test-Cp3OneCheck($Actual, $Check) {
    $path = [string]$Check.path
    $op = [string]$Check.op
    $v = Get-Cp3Path $Actual $path
    $arr = @()
    if ($null -ne $v) { $arr = @($v) }
    $want = $null
    if (Test-Cp3HasProp $Check 'value') { $want = $Check.value }
    $ok = $false
    switch ($op) {
        'eq' { $ok = Test-Cp3Equal $v $want }
        'ne' { $ok = -not (Test-Cp3Equal $v $want) }
        'in' { foreach ($w in @($want)) { if (Test-Cp3Equal $v $w) { $ok = $true } } }
        'between' { $w = @($want); $ok = ($null -ne $v) -and (Test-Cp3IsNumber $v) -and ([double]$v -ge [double]$w[0]) -and ([double]$v -le [double]$w[1]) }
        'lte' { $ok = ($null -ne $v) -and (Test-Cp3IsNumber $v) -and ([double]$v -le [double]$want) }
        'gte' { $ok = ($null -ne $v) -and (Test-Cp3IsNumber $v) -and ([double]$v -ge [double]$want) }
        'contains' { if ($v -is [string]) { $ok = $v.Contains([string]$want) } else { foreach ($e in $arr) { if (Test-Cp3Equal $e $want) { $ok = $true } } } }
        'startsWith' { $ok = ($v -is [string]) -and $v.StartsWith([string]$want, [System.StringComparison]::Ordinal) }
        'exists' { $ok = (($null -ne $v) -eq [bool]$want) }
        'hasAll' { $ok = $true; foreach ($w in @($want)) { $found = $false; foreach ($e in $arr) { if (Test-Cp3Equal $e $w) { $found = $true } } ; if (-not $found) { $ok = $false } } }
        'lacksAll' { $ok = $true; foreach ($w in @($want)) { foreach ($e in $arr) { if (Test-Cp3Equal $e $w) { $ok = $false } } } }
        default { return "unknown operator '$op' for $path" }
    }
    if ($ok) { return $null }
    $shown = 'null'
    if ($null -ne $v) { $shown = ((@($v) | ForEach-Object { [string]$_ }) -join ',') }
    if ($shown.Length -gt 80) { $shown = $shown.Substring(0, 80) + '...' }
    return ('{0} {1} {2} (actual: {3})' -f $path, $op, (ConvertTo-Json -InputObject $want -Compress), $shown)
}

function Test-Cp3Checks($Actual, $Checks) {
    $failed = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Checks)) {
        $r = Test-Cp3OneCheck $Actual $c
        if ($null -ne $r) { $failed.Add($r) }
    }
    return [pscustomobject]@{ Met = ($failed.Count -eq 0); Failed = $failed.ToArray() }
}

function Read-Cp3Expectations([string]$Path) {
    $doc = [System.IO.File]::ReadAllText($Path, $script:Cp3Utf8) | ConvertFrom-Json
    $map = @{}
    foreach ($s in @($doc.steps)) {
        if ($map.ContainsKey([string]$s.id)) { throw "duplicate step id $($s.id) in the expectations" }
        $map[[string]$s.id] = $s
    }
    return [pscustomobject]@{ Doc = $doc; Steps = $map }
}

# ---------------------------------------------------------------- response -> flat, safe "actual"
function ConvertFrom-Cp3Breakdown([string]$Reason) {
    $h = @{}
    if ($Reason -and $Reason -match '\[([^\]]*)\]') {
        foreach ($pair in ($Matches[1] -split ',\s*')) {
            if ($pair -match '^([a-z_]+)=(-?\d+)$') { $h[$Matches[1]] = [int]$Matches[2] }
        }
    }
    return $h
}

function ConvertTo-Cp3Actual($Send, $Resp, $Redactor) {
    $a = [ordered]@{
        received = $false; status = 0; contentType = ''; bodyLength = 0; closedBy = [string]$Send.ClosedBy; transportError = [string]$Send.Error
        isJson = $false; isArray = $false; itemCount = 0; fieldNames = @(); error = $null; jsonStatus = $null; reason = $null
        riskScore = $null; role = $null; breakdown = @{}; hasToken = $false; hasSessionId = $false
    }
    $a['_json'] = $null
    if ($Resp.Received) {
        $a['received'] = $true
        $a['status'] = [int]$Resp.Status
        $a['bodyLength'] = [int]$Resp.Body.Length
        if ($Resp.Headers.ContainsKey('content-type')) { $a['contentType'] = [string]$Resp.Headers['content-type'] }
    }
    $text = ''
    if ($Resp.Received) { $text = [string]$Resp.BodyText }
    $t = $text.TrimStart()
    if ($t.StartsWith('[')) {
        $a['isJson'] = $true
        $a['isArray'] = $true
        $items = @()
        try { $parsed = ConvertFrom-Json -InputObject $text; if ($null -ne $parsed) { $items = @($parsed) } } catch { $a['isJson'] = $false }
        $a['itemCount'] = $items.Count
        if ($items.Count -gt 0 -and $null -ne $items[0].PSObject) { $a['fieldNames'] = @($items[0].PSObject.Properties | ForEach-Object { $_.Name }) }
        $a['_json'] = $items
    } elseif ($t.StartsWith('{')) {
        $obj = $null
        try { $obj = ConvertFrom-Json -InputObject $text } catch { $obj = $null }
        if ($null -ne $obj) {
            $a['isJson'] = $true
            $a['fieldNames'] = @($obj.PSObject.Properties | ForEach-Object { $_.Name })
            if (Test-Cp3HasProp $obj 'error') { $a['error'] = [string]$obj.error }
            if (Test-Cp3HasProp $obj 'status') { $a['jsonStatus'] = [string]$obj.status }
            if (Test-Cp3HasProp $obj 'reason') { $a['reason'] = Protect-Cp3Text $Redactor ([string]$obj.reason) }
            if (Test-Cp3HasProp $obj 'risk_score') { $a['riskScore'] = [int]$obj.risk_score }
            if (Test-Cp3HasProp $obj 'role') { $a['role'] = [string]$obj.role }
            $a['hasToken'] = (Test-Cp3HasProp $obj 'token')
            $a['hasSessionId'] = (Test-Cp3HasProp $obj 'session_id')
            if ($a['reason']) { $a['breakdown'] = ConvertFrom-Cp3Breakdown ([string]$a['reason']) }
            $a['_json'] = $obj
        }
    }
    return $a
}

function Get-Cp3SafeActual($Actual) {
    $o = [ordered]@{}
    foreach ($k in $Actual.Keys) { if (-not ([string]$k).StartsWith('_')) { $o[$k] = $Actual[$k] } }
    return $o
}

# ---------------------------------------------------------------- context
function New-Cp3Context {
    param($Expectations, [scriptblock]$Send, [scriptblock]$Guard, [hashtable]$Control, [string]$Device, [hashtable]$Creds, $Redactor)
    foreach ($u in $Creds.Keys) {
        Add-Cp3Secret $Redactor $Creds[$u].Password 'pw'
        Add-Cp3Secret $Redactor $Creds[$u].Pin 'pin'
    }
    return [pscustomobject]@{
        Exp = $Expectations.Steps; Send = $Send; Guard = $Guard; Control = $Control; Device = $Device; Creds = $Creds; Redactor = $Redactor
        Results = (New-Object System.Collections.Generic.List[object]); Retried = (New-Object System.Collections.Generic.List[object])
        Transcript = (New-Object System.Collections.Generic.List[string]); Notes = (New-Object System.Collections.Generic.List[string])
        Perturbed = $false; T0 = (Get-Cp3Now)
    }
}

function Add-Cp3Transcript($Ctx, [string]$Text) {
    $Ctx.Transcript.Add(('{0,7:0.0}s  {1}' -f ((Get-Cp3Now) - $Ctx.T0), (Protect-Cp3Text $Ctx.Redactor $Text)))
}

# ---------------------------------------------------------------- HTTP through the context
function Invoke-Cp3Http {
    param($Ctx, [string]$Method, [string]$Path, [hashtable]$Headers, [string]$BodyText, [string]$Label)
    & $Ctx.Guard
    $h = @{}
    if ($null -ne $Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
    $body = $null
    if ($BodyText) { $body = $script:Cp3Utf8.GetBytes($BodyText); $h['Content-Type'] = 'application/json' }
    $bytes = New-Cp3RequestBytes -Method $Method -Path $Path -Headers $h -Body $body
    $send = & $Ctx.Send $bytes
    $resp = ConvertFrom-Cp3RawResponse $send.Raw
    $a = ConvertTo-Cp3Actual $send $resp $Ctx.Redactor
    $why = ''
    if ($a['reason']) { $why = ' ' + [string]$a['reason'] }
    if ($a['transportError']) { $why += ' [transport: ' + $a['transportError'] + ']' }
    Add-Cp3Transcript $Ctx ("{0}: {1} {2} -> {3}{4}" -f $Label, $Method, $Path, $a['status'], $why)
    return $a
}

function Get-Cp3TokenInfo([string]$Token) {
    $info = @{ ok = $false; ttl = $null; device = $null; origin = $null }
    try {
        $enc = $Token.Split('.')[0]
        $b64 = $enc.Replace('-', '+').Replace('_', '/')
        switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
        $payload = $script:Cp3Utf8.GetString([Convert]::FromBase64String($b64))
        $p = $payload.Split('|')
        if ($p.Count -eq 6) { $info.ok = $true; $info.ttl = [long]$p[5] - [long]$p[4]; $info.device = $p[2]; $info.origin = $p[3] }
    } catch { }
    return $info
}

function Invoke-Cp3Login {
    param($Ctx, [string]$User, [string]$Label)
    $c = $Ctx.Creds[$User]
    $json = ConvertTo-Json -Compress -InputObject ([ordered]@{ username = $User; password = $c.Password; device_id = $Ctx.Device })
    $a = Invoke-Cp3Http $Ctx 'POST' '/login' @{} $json $Label
    $sess = $null
    if ($a['status'] -eq 200 -and $null -ne $a['_json'] -and (Test-Cp3HasProp $a['_json'] 'token')) {
        $tok = [string]$a['_json'].token
        $sid = [string]$a['_json'].session_id
        Add-Cp3Secret $Ctx.Redactor $tok 'token'
        Add-Cp3Secret $Ctx.Redactor $sid 'session'
        $sess = [pscustomobject]@{ User = $User; Token = $tok; SessionId = $sid; LoginAt = (Get-Cp3Now); LastEvalAt = $null }
        $info = Get-Cp3TokenInfo $tok
        $a['tokenTtlSeconds'] = $info.ttl
        $a['tokenDeviceMatches'] = ($info.device -ceq $Ctx.Device)
        $a['tokenOriginIp'] = $info.origin
    }
    return [pscustomobject]@{ Actual = $a; Session = $sess }
}

function Wait-Cp3Cadence($Sess, [double]$MinGap = 3.0) {
    $ref = $Sess.LastEvalAt
    if ($null -eq $ref) { $ref = $Sess.LoginAt }
    $gap = (Get-Cp3Now) - $ref
    if ($gap -lt $MinGap) { Wait-Cp3Seconds ($MinGap - $gap) }
}

function Invoke-Cp3Authed {
    param($Ctx, $Sess, [string]$Method, [string]$Path, [string]$Pin, [string]$Label, [switch]$NoCadence, [string]$DeviceOverride, [string]$TokenOverride)
    if (-not $NoCadence) { Wait-Cp3Cadence $Sess }
    $dev = $Ctx.Device
    if ($DeviceOverride) { $dev = $DeviceOverride }
    $tok = $Sess.Token
    if ($TokenOverride) { $tok = $TokenOverride }
    $h = @{ 'Authorization' = ('Bearer ' + $tok); 'X-Device-Id' = $dev }
    if ($Pin) { $h['X-StepUp-Pin'] = $Pin }
    $a = Invoke-Cp3Http $Ctx $Method $Path $h $null $Label
    $Sess.LastEvalAt = (Get-Cp3Now)
    $bd = $a['breakdown']
    if ($bd.ContainsKey('behavior') -and [int]$bd['behavior'] -gt 0) {
        $Ctx.Perturbed = $true
        $Ctx.Notes.Add("behavior vector fired during '$Label'")
    }
    return $a
}

# ---------------------------------------------------------------- recording
function Add-Cp3StepResult {
    param($Ctx, [string]$Id, $Actual, [string]$Notes = '', [int]$Attempt = 1)
    if (-not $Ctx.Exp.ContainsKey($Id)) { throw "no expectation for step $Id" }
    $spec = $Ctx.Exp[$Id]
    $pred = Test-Cp3Checks $Actual @($spec.prediction.all)
    $met = $null
    $verdict = 'OBSERVATION'
    $reqFailed = @()
    if (-not (Test-Cp3HasProp $spec.requirement 'observation')) {
        $req = Test-Cp3Checks $Actual @($spec.requirement.all)
        $met = $req.Met
        $reqFailed = $req.Failed
        if ($met) { $verdict = 'PASS' } else { $verdict = 'FAIL' }
    }
    $rec = [pscustomobject]@{
        Id = $Id; Scenario = [string]$spec.scenario; Title = [string]$spec.title; Request = [string]$spec.request
        RequirementText = [string]$spec.requirementText; PredictionText = [string]$spec.predictionText
        PredictedBaseline = [string]$spec.predictedBaseline; BaselineVerdict = $verdict; RequirementMet = $met; RequirementFailures = $reqFailed
        PredictionHeld = $pred.Met; PredictionFailures = $pred.Failed; BaselineMatchesPrediction = ($verdict -eq [string]$spec.predictedBaseline)
        Actual = (Get-Cp3SafeActual $Actual); Notes = $Notes; Attempt = $Attempt
    }
    $Ctx.Results.Add($rec)
    Add-Cp3Transcript $Ctx ("RESULT {0}: baseline {1} (predicted {2}); prediction {3}" -f $Id, $verdict, $spec.predictedBaseline, $(if ($pred.Met) { 'held' } else { 'WRONG' }))
}

function Add-Cp3SetupFailure($Ctx, [string[]]$Ids, $LoginActual, [int]$Attempt) {
    foreach ($id in $Ids) {
        $a = [ordered]@{ setupFailed = $true; status = [int]$LoginActual['status']; reason = $LoginActual['reason']; transportError = $LoginActual['transportError'] }
        Add-Cp3StepResult $Ctx $id $a 'setup failed: the login for this scenario did not succeed' $Attempt
    }
}

# A scenario that re-runs ONCE in a fresh session when the legacy behaviour vector (+25 for bursts) fired and could have changed a risk number.
function Invoke-Cp3WithRetry($Ctx, [string]$Name, [scriptblock]$Body) {
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $Ctx.Perturbed = $false
        $startCount = $Ctx.Results.Count
        & $Body $attempt
        if (-not $Ctx.Perturbed) { return }
        if ($attempt -eq 1) {
            $Ctx.Notes.Add("$Name repeated once in a fresh session because the behaviour vector fired")
            $moved = $Ctx.Results.GetRange($startCount, $Ctx.Results.Count - $startCount).ToArray()
            $Ctx.Results.RemoveRange($startCount, $Ctx.Results.Count - $startCount)
            foreach ($m in $moved) { $Ctx.Retried.Add($m) }
        }
    }
}

function Get-Cp3Pins($Ctx, [string]$User) {
    $real = $Ctx.Creds[$User].Pin
    do { $wrong = New-Cp3Pin } while ($wrong -ceq $real)
    return [pscustomobject]@{ Real = $real; Wrong = $wrong }
}

# ---------------------------------------------------------------- scenarios
function Invoke-Cp3S0($Ctx) {
    $a1 = Invoke-Cp3Http $Ctx 'GET' '/' @{} $null 'S0 dashboard'
    $a2 = Invoke-Cp3Http $Ctx 'GET' '/api/public/info' @{ 'X-Device-Id' = $Ctx.Device } $null 'S0 data call without a token'
    $a = [ordered]@{
        dashboardStatus = $a1['status']; dashboardContentType = $a1['contentType']; dashboardBytes = $a1['bodyLength']
        unauthStatus = $a2['status']; unauthReason = $a2['reason']
    }
    Add-Cp3StepResult $Ctx 'S0' $a
}

function Get-Cp3ActiveSessions($Ctx, [string]$User) {
    $a = Invoke-Cp3Http $Ctx 'GET' '/sessions' @{} $null "read: sessions of $User"
    if ($a['status'] -ne 200 -or -not $a['isArray']) { return -1 }
    return @(@($a['_json']) | Where-Object { $_.username -ceq $User -and $_.status -ceq 'ACTIVE' }).Count
}

function Invoke-Cp3T01($Ctx) {
    $before = Get-Cp3ActiveSessions $Ctx 'dr_alice'
    $l = Invoke-Cp3Login $Ctx 'dr_alice' 'T01.1 login'
    $a = $l.Actual
    Add-Cp3StepResult $Ctx 'T01.1' $a
    $after = Get-Cp3ActiveSessions $Ctx 'dr_alice'
    $ev = Invoke-Cp3Http $Ctx 'GET' '/events/recent' @{} $null 'read: recent events'
    $listed = $false
    if ($null -ne $l.Session -and $ev['status'] -eq 200 -and $ev['isArray']) {
        $listed = (@(@($ev['_json']) | Where-Object { $_.session_id -ceq $l.Session.SessionId -and $_.method -ceq 'LOGIN' }).Count -ge 1)
    }
    $delta = $null
    if ($before -ge 0 -and $after -ge 0) { $delta = $after - $before }
    Add-Cp3StepResult $Ctx 'T01.2' ([ordered]@{ activeSessionsDelta = $delta; loginEventListed = $listed })
}

function Invoke-Cp3T03($Ctx, [int]$Attempt) {
    $l = Invoke-Cp3Login $Ctx 'dr_alice' 'T03 setup login'
    if ($null -eq $l.Session) { Add-Cp3SetupFailure $Ctx @('T03.1', 'T03.2', 'T03.3') $l.Actual $Attempt; return }
    $s = $l.Session
    $pin = (Get-Cp3Pins $Ctx 'dr_alice').Real
    Add-Cp3StepResult $Ctx 'T03.1' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/101/records' '' 'T03.1 assigned patient 101, no PIN') '' $Attempt
    Add-Cp3StepResult $Ctx 'T03.2' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/101/records' $pin 'T03.2 assigned patient 101, correct PIN') '' $Attempt
    $a3 = Invoke-Cp3Authed $Ctx $s 'POST' '/api/patients/101/export-pdf' $pin 'T03.3 export of 101, correct PIN'
    $a3['hasSsn'] = (@($a3['fieldNames']) -contains 'ssn')
    $a3['hasBilling'] = (@($a3['fieldNames']) -contains 'billing')
    Add-Cp3StepResult $Ctx 'T03.3' $a3 '' $Attempt
}

function Invoke-Cp3T04($Ctx, [int]$Attempt) {
    $l = Invoke-Cp3Login $Ctx 'dr_alice' 'T04 setup login'
    if ($null -eq $l.Session) { Add-Cp3SetupFailure $Ctx @('T04.1', 'T04.2', 'T04.3', 'T04.4') $l.Actual $Attempt; return }
    $s = $l.Session
    $pin = (Get-Cp3Pins $Ctx 'dr_alice').Real
    Add-Cp3StepResult $Ctx 'T04.1' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/103/records' '' 'T04.1 unassigned patient 103, no PIN') '' $Attempt
    Add-Cp3StepResult $Ctx 'T04.2' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/103/records' $pin 'T04.2 unassigned patient 103, correct PIN') '' $Attempt
    Add-Cp3StepResult $Ctx 'T04.3' (Invoke-Cp3Authed $Ctx $s 'POST' '/api/patients/103/export-pdf' $pin 'T04.3 export of 103, correct PIN') '' $Attempt
    Add-Cp3StepResult $Ctx 'T04.4' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/104/records' $pin 'T04.4 patient 104 (nobody assigned), correct PIN') '' $Attempt
}

function Invoke-Cp3T15($Ctx, [int]$Attempt) {
    $l = Invoke-Cp3Login $Ctx 'dr_alice' 'T15 setup login'
    if ($null -eq $l.Session) { Add-Cp3SetupFailure $Ctx @('T15.1', 'T15.2', 'T15.3', 'T15.4') $l.Actual $Attempt; return }
    $s = $l.Session
    $pins = Get-Cp3Pins $Ctx 'dr_alice'
    Add-Cp3StepResult $Ctx 'T15.1' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/101/records' '' 'T15.1 no PIN') '' $Attempt
    Add-Cp3StepResult $Ctx 'T15.2' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/101/records' $pins.Wrong 'T15.2 wrong PIN') '' $Attempt
    Add-Cp3StepResult $Ctx 'T15.3' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/patients/101/records' $pins.Real 'T15.3 correct PIN') '' $Attempt
    $ev = Invoke-Cp3Http $Ctx 'GET' '/events/recent' @{} $null 'read: recent events for the audit check'
    $rows = @()
    if ($ev['status'] -eq 200 -and $ev['isArray']) { $rows = @(@($ev['_json']) | Where-Object { $_.session_id -ceq $s.SessionId }) }
    $reasons = @($rows | ForEach-Object { [string]$_.reason })
    $a4 = [ordered]@{
        auditRows = $rows.Count
        hasAwaitingRow = (@($reasons | Where-Object { $_.Contains('awaiting step-up PIN') }).Count -ge 1)
        hasPinIncorrectRow = (@($reasons | Where-Object { $_.Contains('step-up PIN incorrect') }).Count -ge 1)
        hasPinVerifiedRow = (@($reasons | Where-Object { $_.Contains('step-up PIN verified') }).Count -ge 1)
    }
    Add-Cp3StepResult $Ctx 'T15.4' $a4 '' $Attempt
}

function Invoke-Cp3T10($Ctx) {
    # T10.1 missing token
    Add-Cp3StepResult $Ctx 'T10.1' (Invoke-Cp3Http $Ctx 'GET' '/api/public/info' @{ 'X-Device-Id' = $Ctx.Device } $null 'T10.1 no Authorization header')
    # T10.2 / T10.3 / T10.4 share one login (the token must be used inside 20 s for T10.2 and T10.3, then it expires for T10.4)
    $l = Invoke-Cp3Login $Ctx 'dr_alice' 'T10 setup login'
    if ($null -eq $l.Session) { Add-Cp3SetupFailure $Ctx @('T10.2', 'T10.3', 'T10.4') $l.Actual 1 }
    else {
        $s = $l.Session
        $dot = $s.Token.IndexOf('.')
        $last = $s.Token.Substring($s.Token.Length - 1)
        $swap = 'a'
        if ($last -ceq 'a') { $swap = 'b' }
        $tampered = $s.Token.Substring(0, $s.Token.Length - 1) + $swap
        $a1 = Invoke-Cp3Authed $Ctx $s 'GET' '/api/public/info' '' 'T10.2 token with a changed signature character' -NoCadence -TokenOverride $tampered
        $a2 = Invoke-Cp3Authed $Ctx $s 'GET' '/api/public/info' '' 'T10.2 malformed token' -NoCadence -TokenOverride 'abc'
        Add-Cp3StepResult $Ctx 'T10.2' ([ordered]@{ tamperedStatus = $a1['status']; tamperedReason = $a1['reason']; malformedStatus = $a2['status']; malformedReason = $a2['reason'] })
        Add-Cp3StepResult $Ctx 'T10.3' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/public/info' '' 'T10.3 valid token, other X-Device-Id' -NoCadence -DeviceOverride 'DEV-other-device')
        $age = (Get-Cp3Now) - $s.LoginAt
        if ($age -lt 22) { Wait-Cp3Seconds (22 - $age) }
        Add-Cp3StepResult $Ctx 'T10.4' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/public/info' '' 'T10.4 token 22 s after login' -NoCadence)
    }
    # T10.5 revoked session (the legacy way to revoke is the admin route, which is itself unauthenticated - see T18)
    $l2 = Invoke-Cp3Login $Ctx 'dr_alice' 'T10.5 setup login'
    if ($null -eq $l2.Session) { Add-Cp3SetupFailure $Ctx @('T10.5') $l2.Actual 1; return }
    $s2 = $l2.Session
    $term = ConvertTo-Json -Compress -InputObject ([ordered]@{ session_id = $s2.SessionId; terminated_by = 'cp3-t10'; reason = 'T10 revoke' })
    $t = Invoke-Cp3Http $Ctx 'POST' '/admin/terminate-session' @{} $term 'T10.5 terminate own session (legacy admin route)'
    $r1 = Invoke-Cp3Authed $Ctx $s2 'GET' '/api/public/info' '' 'T10.5 same token after termination' -NoCadence
    $renewBody = ConvertTo-Json -Compress -InputObject ([ordered]@{ token = $s2.Token; device_id = $Ctx.Device })
    $r2 = Invoke-Cp3Http $Ctx 'POST' '/token/renew' @{} $renewBody 'T10.5 renew after termination'
    Add-Cp3StepResult $Ctx 'T10.5' ([ordered]@{ terminateStatus = $t['status']; revokedStatus = $r1['status']; revokedReason = $r1['reason']; renewStatus = $r2['status']; renewReason = $r2['reason'] })
}

function Invoke-Cp3T18($Ctx) {
    $vl = Invoke-Cp3Login $Ctx 'front_carol' 'T18 setup: victim login'
    if ($null -eq $vl.Session) { Add-Cp3SetupFailure $Ctx @('T18.1', 'T18.2', 'T18.3', 'T18.4') $vl.Actual 1; return }
    $victim = $vl.Session
    $vb = Invoke-Cp3Authed $Ctx $victim 'GET' '/api/public/info' '' 'T18 setup: victim request before the attack'
    # the "attacker" below sends no credentials at all
    $a1 = Invoke-Cp3Http $Ctx 'GET' '/sessions' @{} $null 'T18.1 GET /sessions without credentials'
    $listed = $false
    $victimId = $null
    if ($a1['status'] -eq 200 -and $a1['isArray']) {
        $row = @(@($a1['_json']) | Where-Object { $_.session_id -ceq $victim.SessionId })
        if ($row.Count -ge 1) { $listed = $true; $victimId = [string]$row[0].session_id }
    }
    $a1['victimListed'] = $listed
    Add-Cp3StepResult $Ctx 'T18.1' $a1
    Add-Cp3StepResult $Ctx 'T18.2' (Invoke-Cp3Http $Ctx 'GET' '/devices' @{} $null 'T18.2 GET /devices without credentials')
    Add-Cp3StepResult $Ctx 'T18.3' (Invoke-Cp3Http $Ctx 'GET' '/events/recent' @{} $null 'T18.3 GET /events/recent without credentials')
    $target = $victimId
    if ($null -eq $target) { $target = $victim.SessionId }
    $forged = 'cp3-forged-operator'
    $body = ConvertTo-Json -Compress -InputObject ([ordered]@{ session_id = $target; terminated_by = $forged; reason = 'T18 unauthenticated termination' })
    $t = Invoke-Cp3Http $Ctx 'POST' '/admin/terminate-session' @{} $body 'T18.4 POST /admin/terminate-session without credentials, forged terminated_by'
    $va = Invoke-Cp3Authed $Ctx $victim 'GET' '/api/public/info' '' 'T18.4 victim request after the attack'
    $after = Invoke-Cp3Http $Ctx 'GET' '/sessions' @{} $null 'T18.4 read: sessions after the attack'
    $stored = $false
    if ($after['status'] -eq 200 -and $after['isArray']) {
        $row2 = @(@($after['_json']) | Where-Object { $_.session_id -ceq $victim.SessionId })
        if ($row2.Count -ge 1 -and [string]$row2[0].terminated_by -ceq $forged) { $stored = $true }
    }
    Add-Cp3StepResult $Ctx 'T18.4' ([ordered]@{
        terminateStatus = $t['status']; victimBeforeStatus = $vb['status']; victimAfterStatus = $va['status']
        victimAfterReason = $va['reason']; forgedAttributionStored = $stored
    })
}

function Invoke-Cp3T13($Ctx) {
    $l = Invoke-Cp3Login $Ctx 'dr_alice' 'T13 setup login'
    if ($null -eq $l.Session) { Add-Cp3SetupFailure $Ctx @('T13.1', 'T13.2', 'T13.3', 'T13.4', 'T13.5') $l.Actual 1; return }
    $s = $l.Session
    Add-Cp3StepResult $Ctx 'T13.1' (Invoke-Cp3Authed $Ctx $s 'GET' '/api/public/info' '' 'T13.1 request with the agent alive')
    # C1: the agent is allowed to be down from here until it has been restarted, and only in this scenario
    & $Ctx.Control.BeginPlannedExit 'agent' 'T13'
    $stop = & $Ctx.Control.StopAgent
    Add-Cp3Transcript $Ctx ("agent stop: " + [string]$stop)
    $tKill = Get-Cp3Now
    $polls = 0
    $allowed = 0
    $first = $null
    $devScore = $null
    for ($i = 0; $i -lt 15; $i++) {
        Wait-Cp3Seconds 1.0
        $a = Invoke-Cp3Authed $Ctx $s 'GET' '/api/public/info' '' ('T13.2 poll ' + ($i + 1)) -NoCadence
        $polls++
        if ($a['status'] -eq 200) { $allowed++; continue }
        $first = [Math]::Round(((Get-Cp3Now) - $tKill), 1)
        if ($a['breakdown'].ContainsKey('device')) { $devScore = [int]$a['breakdown']['device'] }
        break
    }
    Add-Cp3StepResult $Ctx 'T13.2' ([ordered]@{ firstDenySeconds = $first; allowedBeforeDeny = $allowed; polls = $polls; denyDeviceScore = $devScore })
    $renewBody = ConvertTo-Json -Compress -InputObject ([ordered]@{ token = $s.Token; device_id = $Ctx.Device })
    Add-Cp3StepResult $Ctx 'T13.3' (Invoke-Cp3Http $Ctx 'POST' '/token/renew' @{} $renewBody 'T13.3 renew while the heartbeat is stale')
    $l4 = Invoke-Cp3Login $Ctx 'dr_alice' 'T13.4 login while the agent is stopped'
    Add-Cp3StepResult $Ctx 'T13.4' $l4.Actual
    $up = & $Ctx.Control.StartAgentAndWait
    Add-Cp3Transcript $Ctx ("agent restart and first heartbeat: " + [string]$up)
    # the window closes only if the agent process is running again (a restart that died stops the run here)
    & $Ctx.Control.EndPlannedExit 'agent' 'T13' $null
    $l5 = Invoke-Cp3Login $Ctx 'dr_alice' 'T13.5 login after the agent restarted'
    $rs = 0
    if ($null -ne $l5.Session) { $rq = Invoke-Cp3Authed $Ctx $l5.Session 'GET' '/api/public/info' '' 'T13.5 request after recovery'; $rs = $rq['status'] }
    Add-Cp3StepResult $Ctx 'T13.5' ([ordered]@{ agentRestarted = [bool]$up; loginStatus = $l5.Actual['status']; requestStatus = $rs })
}

function Invoke-Cp3Probe($Ctx, [string]$Id, [string]$Which) {
    & $Ctx.Guard
    # C1: the PEP is allowed to exit from here on, and only in this probe
    & $Ctx.Control.BeginPlannedExit 'pep' $Id
    $send = & $Ctx.Send (New-Cp3ProbeBytes $Which)
    $resp = ConvertFrom-Cp3RawResponse $send.Raw
    Add-Cp3Transcript $Ctx ("{0}: one raw request sent; response received: {1}; connection closed by: {2}" -f $Id, $resp.Received, $send.ClosedBy)
    $exit = $null
    for ($i = 0; $i -lt 10; $i++) {
        $exit = & $Ctx.Control.PepExitInfo
        if ($exit.Exited) { break }
        Wait-Cp3Seconds 0.5
    }
    $ports = & $Ctx.Control.PortsListening
    $restarted = $false
    if ($exit.Exited) { $restarted = [bool](& $Ctx.Control.RestartPep) }
    $dash = 0
    if ((-not $exit.Exited) -or $restarted) {
        $d = Invoke-Cp3Http $Ctx 'GET' '/' @{} $null "$Id dashboard after the probe"
        $dash = $d['status']
    }
    $code = $null
    if ($exit.Exited) { $code = $exit.ExitCode }
    Add-Cp3StepResult $Ctx $Id ([ordered]@{
        responseReceived = $resp.Received; responseStatus = $resp.Status; closedBy = $send.ClosedBy
        pepExited = [bool]$exit.Exited; pepExitCode = $code; apiStillListening = [bool]$ports.Api; pdpStillListening = [bool]$ports.Pdp
        restartedOk = $restarted; dashboardAfterStatus = $dash
    })
    # the result is recorded first; then the window closes only if the PEP is running again and any exit carried the planned exit code
    & $Ctx.Control.EndPlannedExit 'pep' $Id $exit
}

function Invoke-Cp3AllScenarios($Ctx) {
    Invoke-Cp3S0 $Ctx
    Invoke-Cp3T01 $Ctx
    Invoke-Cp3WithRetry $Ctx 'T03' { param($n) Invoke-Cp3T03 $Ctx $n }
    Invoke-Cp3WithRetry $Ctx 'T04' { param($n) Invoke-Cp3T04 $Ctx $n }
    Invoke-Cp3WithRetry $Ctx 'T15' { param($n) Invoke-Cp3T15 $Ctx $n }
    Invoke-Cp3T10 $Ctx
    Invoke-Cp3T18 $Ctx
    Invoke-Cp3T13 $Ctx
    Invoke-Cp3Probe $Ctx 'P1' 'P1'
    Invoke-Cp3Probe $Ctx 'P2' 'P2'
    # coverage: every frozen step must have exactly one final result
    $final = $Ctx.Results.ToArray()
    $missing = @($Ctx.Exp.Keys | Where-Object { $id = $_; @($final | Where-Object { $_.Id -ceq $id }).Count -ne 1 })
    if ($missing.Count -gt 0) { throw ('steps without exactly one result: ' + ($missing -join ', ')) }
}

# ---------------------------------------------------------------- summary and reports
function Get-Cp3Summary($Ctx) {
    $r = $Ctx.Results.ToArray()
    return [pscustomobject]@{
        Steps = $r.Count
        BaselinePass = @($r | Where-Object { $_.BaselineVerdict -eq 'PASS' }).Count
        BaselineFail = @($r | Where-Object { $_.BaselineVerdict -eq 'FAIL' }).Count
        Observation = @($r | Where-Object { $_.BaselineVerdict -eq 'OBSERVATION' }).Count
        PredictionHeld = @($r | Where-Object { $_.PredictionHeld }).Count
        PredictionWrong = @($r | Where-Object { -not $_.PredictionHeld } | ForEach-Object { $_.Id })
        VerdictDiffersFromPrediction = @($r | Where-Object { -not $_.BaselineMatchesPrediction } | ForEach-Object { $_.Id })
        Retried = $Ctx.Retried.Count
        Notes = $Ctx.Notes.ToArray()
    }
}

function Format-Cp3ActualBrief($Actual) {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Actual.Keys) {
        $v = $Actual[$k]
        if ($k -in @('contentType', 'closedBy', 'transportError', 'isJson', 'received', 'bodyLength', 'hasToken', 'hasSessionId')) { continue }
        if ($null -eq $v -or ($v -is [string] -and $v -eq '')) { continue }
        if ($k -eq 'isArray' -and $v -eq $false) { continue }
        if ($k -eq 'itemCount' -and $v -eq 0) { continue }
        if ($v -is [System.Collections.IDictionary]) { if ($v.Count -eq 0) { continue } ; $v = ((@($v.Keys | Sort-Object) | ForEach-Object { $_ + '=' + $v[$_] }) -join ' ') }
        elseif ($v -is [array]) { if ($v.Count -eq 0) { continue } ; $v = '[' + ((@($v) | ForEach-Object { [string]$_ }) -join ',') + ']' }
        $s = [string]$v
        if ($s.Length -gt 70) { $s = $s.Substring(0, 70) + '...' }
        $parts.Add("$k=$s")
    }
    return ($parts -join '; ')
}

function Format-Cp3ResultsMarkdown($Ctx, $Summary) {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('# CP3 baseline results (redacted)')
    $out.Add('')
    $out.Add(('Steps: {0}. Baseline PASS {1}, baseline FAIL {2}, observation {3}. Predictions held {4} of {0}.' -f $Summary.Steps, $Summary.BaselinePass, $Summary.BaselineFail, $Summary.Observation, $Summary.PredictionHeld))
    if ($Summary.PredictionWrong.Count -gt 0) { $out.Add('Predictions that did NOT hold: ' + ($Summary.PredictionWrong -join ', ')) }
    if ($Summary.VerdictDiffersFromPrediction.Count -gt 0) { $out.Add('Baseline verdict differs from the predicted one: ' + ($Summary.VerdictDiffersFromPrediction -join ', ')) }
    $out.Add('')
    $out.Add('| ID | Baseline verdict | Predicted | Prediction held | What was observed |')
    $out.Add('|---|---|---|---|---|')
    foreach ($r in $Ctx.Results) {
        $held = 'yes'
        if (-not $r.PredictionHeld) { $held = 'NO' }
        $out.Add(('| {0} | {1} | {2} | {3} | {4} |' -f $r.Id, $r.BaselineVerdict, $r.PredictedBaseline, $held, (Format-Cp3ActualBrief $r.Actual).Replace('|', '/')))
    }
    return $out.ToArray()
}
