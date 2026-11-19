<#
.SYNOPSIS
  CP3 Phase A self-checks of the harness itself. It starts NO listener and NO legacy program.
.DESCRIPTION
  Every check ends in PASS or FAIL (a check that cannot run is reported as NOT RUN, never as PASS). Exit code 0 only if there is no FAIL.
  The only processes this script starts are harmless "powershell Start-Sleep" children (H1, H10, H13, H14, H16-H21), the console hosts Windows
  creates for them, and in H15 one own probe class (a Java program that prints its pid and sleeps). Everything else is pure code, temporary
  fixture files, read-only queries of this machine's TCP table, and a dry run of the scenario engine against a MODEL of the legacy stack
  (no socket of its own, no legacy program).
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cp3\Test-Cp3Harness.ps1 -OutDir <evidence>\phaseA\harness
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$WorkRoot,
    [string]$ExpectationsPath,
    [string]$Only    # development aid: comma-separated check ids; Run-Cp3.ps1 never passes it, and a subset run says so in its summary
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\cp3_lib.ps1"
. "$PSScriptRoot\cp3_proc.ps1"
. "$PSScriptRoot\cp3_engine.ps1"
. "$PSScriptRoot\cp3_fake_stack.ps1"
$repo = Get-RepoRoot
if (-not $ExpectationsPath) { $ExpectationsPath = Join-Path $repo 'tests\baseline\cp3_expectations.json' }
$work = Get-WorkRoot $WorkRoot
Assert-WorkRootSafe $work
$fixRoot = Join-Path $work ('cp3-harness-' + (New-RunId))
New-Item -ItemType Directory -Force -Path $fixRoot, $OutDir | Out-Null

$script:checks = New-Object System.Collections.Generic.List[object]
$script:leakCanaries = New-Object System.Collections.Generic.List[string]

function Add-Check([string]$Id, [string]$Name, [string]$Status, [string]$Detail) {
    if ($Status -notin @('PASS', 'FAIL', 'NOT RUN')) { throw "invalid verdict '$Status'" }
    $script:checks.Add([pscustomobject]@{ Id = $Id; Name = $Name; Status = $Status; Detail = $Detail })
    Write-Host ('{0,-8} {1,-4} {2}  {3}' -f $Status, $Id, $Name, $Detail)
}
$script:onlySet = @()
if ($Only) { $script:onlySet = @($Only -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function Run-Check([string]$Id, [string]$Name, [scriptblock]$Body) {
    if ($script:onlySet.Count -gt 0 -and $script:onlySet -notcontains $Id) { return }
    try {
        $r = & $Body
        if ($r -is [string] -and $r.StartsWith('NOT RUN:')) { Add-Check $Id $Name 'NOT RUN' $r.Substring(8).Trim(); return }
        if ($r -is [string] -and $r.StartsWith('FAIL:')) { Add-Check $Id $Name 'FAIL' $r.Substring(5).Trim(); return }
        Add-Check $Id $Name 'PASS' ([string]$r)
    } catch {
        $where = ''
        if ($null -ne $_.InvocationInfo) { $where = ' [at ' + (Split-Path -Leaf $_.InvocationInfo.ScriptName) + ':' + $_.InvocationInfo.ScriptLineNumber + ': ' + $_.InvocationInfo.Line.Trim() + ']' }
        Add-Check $Id $Name 'FAIL' ('exception: ' + $_.Exception.Message + $where)
    }
}

# ================================================================ H0 environment
Run-Check 'H0' 'Windows PowerShell 5.1 and strict mode' {
    if ($PSVersionTable.PSVersion.Major -ne 5) { return 'FAIL: not Windows PowerShell 5.x' }
    $threw = $false
    try { $undefinedVariableForTest = $noSuchVariable } catch { $threw = $true }
    if (-not $threw) { return 'FAIL: strict mode is not active' }
    return ('PowerShell ' + $PSVersionTable.PSVersion + ', strict mode active')
}

# ================================================================ H1 Job Object kill-on-close
Run-Check 'H1' 'Job Object kills its children when it is closed' {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args1 = @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120')
    Assert-Cp3LaunchAllowed -Kind 'harmless' -File $ps -Arguments $args1 -TreeRoot $fixRoot
    $job = New-Cp3Job
    Add-Cp3LaunchLog 'harmless' $ps $args1
    $p = Start-Process -FilePath $ps -ArgumentList (ConvertTo-ArgString $args1) -WindowStyle Hidden -PassThru
    try {
        Add-Cp3JobProcess $job $p
        Start-Sleep -Milliseconds 300
        if ($p.HasExited) { return 'FAIL: the sleeper exited before the job was closed' }
        Close-Cp3Job $job
        $gone = $p.WaitForExit(5000)
        if (-not $gone) { return 'FAIL: the child was still running 5 s after the job handle was closed' }
        return 'the child was alive before and gone within 5 s after the job handle was closed'
    } finally {
        if (-not $p.HasExited) { try { $p.Kill() } catch { } }
    }
}

# ================================================================ H1b launch guard
Run-Check 'H1b' 'Launch guard: legacy programs and anything outside the scratch tree are refused' {
    $tree = Join-Path $fixRoot 'guardtree'
    $problems = New-Object System.Collections.Generic.List[string]
    $mustThrow = {
        param($label, $kind, $file, $arguments)
        $threw = $false
        try { Assert-Cp3LaunchAllowed -Kind $kind -File $file -Arguments $arguments -TreeRoot $tree } catch { $threw = $true }
        if (-not $threw) { $problems.Add("accepted: $label") }
    }
    $mustPass = {
        param($label, $kind, $file, $arguments)
        try { Assert-Cp3LaunchAllowed -Kind $kind -File $file -Arguments $arguments -TreeRoot $tree } catch { $problems.Add("refused although allowed: $label ($($_.Exception.Message))") }
    }
    $script:Cp3AllowLegacyLaunch = $false
    $java = Get-Cp3RealJavaExe
    $shim = Find-Tool 'java'
    $cpp = Join-Path $tree 'build\cpp\pep_proxy.exe'
    & $mustThrow 'cpp program while legacy launching is disabled' 'cpp' $cpp @()
    & $mustThrow 'java program while legacy launching is disabled' 'java' $java @('-cp', (Join-Path $tree 'build\java\pdp'), 'pdp.Main')
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $mustThrow 'harmless kind with a different command' 'harmless' $ps @('-NoProfile', '-Command', 'Get-Process')
    & $mustThrow 'harmless kind with another executable' 'harmless' (Join-Path $env:SystemRoot 'System32\cmd.exe') @('-NoProfile', '-Command', 'Start-Sleep -Seconds 5')
    & $mustPass 'harmless sleeper' 'harmless' $ps @('-NoProfile', '-Command', 'Start-Sleep -Seconds 5')
    try {
        # the guard function alone is tested here with legacy launching switched on; nothing is ever started by this check
        $script:Cp3AllowLegacyLaunch = $true
        & $mustPass 'pep_proxy.exe inside the tree' 'cpp' $cpp @()
        & $mustPass 'agent.exe inside the tree' 'cpp' (Join-Path $tree 'build\cpp\agent.exe') @()
        & $mustThrow 'executable outside the tree' 'cpp' 'C:\Windows\System32\notepad.exe' @()
        & $mustThrow 'another file inside the tree' 'cpp' (Join-Path $tree 'build\cpp\other.exe') @()
        & $mustThrow 'scratch executable with arguments' 'cpp' $cpp @('--fake-av-off')
        if ($java) {
            $cp = (Join-Path $tree 'build\java\pdp') + ';' + (Join-Path $tree 'lib\gson-2.11.0.jar')
            & $mustPass 'pdp.Main with a classpath inside the tree' 'java' $java @('-cp', $cp, 'pdp.Main')
            & $mustPass 'app.Main with the native-access flag' 'java' $java @('--enable-native-access=ALL-UNNAMED', '-cp', $cp, 'app.Main')
            & $mustThrow 'classpath entry outside the tree' 'java' $java @('-cp', ($cp + ';C:\evil\x.jar'), 'pdp.Main')
            & $mustThrow 'classes folder outside the tree' 'java' $java @('-cp', 'C:\somewhere\classes', 'pdp.Main')
            & $mustThrow 'other main class' 'java' $java @('-cp', $cp, 'DbTool')
            & $mustThrow 'extra JVM flag' 'java' $java @('-Xmx1g', '-cp', $cp, 'pdp.Main')
            & $mustThrow 'java.exe that is not the real JVM' 'java' 'C:\other\java.exe' @('-cp', $cp, 'pdp.Main')
            if ($shim -and ($shim -ine $java)) { & $mustThrow 'the PATH launcher shim instead of the real JVM' 'java' $shim @('-cp', $cp, 'pdp.Main') }
        }
    } finally { $script:Cp3AllowLegacyLaunch = $false }
    # dry-check mode validates a command line without enabling anything
    try { Assert-Cp3LaunchAllowed -Kind 'cpp' -File $cpp -Arguments @() -TreeRoot $tree -DryCheck } catch { $problems.Add('the dry check refused a good scratch-tree line') }
    $threw = $false
    try { Assert-Cp3LaunchAllowed -Kind 'cpp' -File 'C:\Windows\System32\notepad.exe' -Arguments @() -TreeRoot $tree -DryCheck } catch { $threw = $true }
    if (-not $threw) { $problems.Add('the dry check accepted another executable') }
    $threw = $false
    try { Assert-Cp3LaunchAllowed -Kind 'cpp' -File $cpp -Arguments @() -TreeRoot $tree } catch { $threw = $true }
    if (-not $threw) { $problems.Add('the real check accepted a program after a dry check (the dry check must not enable anything)') }
    # the launch plan: four entries, each accepted by the dry check, and a tampered entry is refused
    $libDir = Join-Path $tree 'lib'
    New-Item -ItemType Directory -Force -Path $libDir | Out-Null
    foreach ($j in @('gson-2.11.0.jar', 'sqlite-jdbc-3.46.1.3.jar')) { if (-not (Test-Path -LiteralPath (Join-Path $libDir $j))) { [System.IO.File]::WriteAllBytes((Join-Path $libDir $j), (New-Object byte[] 4)) } }
    if ($java) {
        $plan = @(Get-Cp3LaunchPlan -Tree $tree -JavaExe $java -JavaFlags @('--enable-native-access=ALL-UNNAMED'))
        if ($plan.Count -ne 4 -or (($plan | ForEach-Object { $_.Role }) -join ',') -ne 'api,pdp,pep,agent') { $problems.Add('the launch plan does not list api, pdp, pep, agent') }
        foreach ($e in $plan) { try { Assert-Cp3LaunchAllowed -Kind $e.Kind -File $e.File -Arguments $e.Arguments -TreeRoot $tree -DryCheck } catch { $problems.Add("plan entry '$($e.Role)' refused: $($_.Exception.Message)") } }
        $threw = $false
        try { Assert-Cp3LaunchAllowed -Kind 'java' -File $plan[0].File -Arguments @($plan[0].Arguments[0], $plan[0].Arguments[1], ($plan[0].Arguments[2] + ';C:\elsewhere\x.jar'), $plan[0].Arguments[3]) -TreeRoot $tree -DryCheck } catch { $threw = $true }
        if (-not $threw) { $problems.Add('a plan entry with an extra classpath element was accepted') }
    }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join '; ')) }
    if ($script:Cp3AllowLegacyLaunch) { return 'FAIL: the legacy-launch switch was left on' }
    return 'refused: cpp/java while disabled, other executables, other arguments, other classpaths, other main classes, the PATH launcher shim; accepted only the exact allowed forms; the four-entry launch plan passes the dry check, which enables nothing; the switch is off again'
}

# ================================================================ H2 loopback classifier on synthetic records
Run-Check 'H2' 'Listener classifier on synthetic records (no real socket is opened)' {
    $L = @(
        [pscustomobject]@{ Pid = 100; Address = '127.0.0.1'; Port = 15000 },
        [pscustomobject]@{ Pid = 100; Address = '0.0.0.0'; Port = 15001 },
        [pscustomobject]@{ Pid = 101; Address = '::'; Port = 18443 },
        [pscustomobject]@{ Pid = 102; Address = '::1'; Port = 19000 },
        [pscustomobject]@{ Pid = 103; Address = '192.168.1.5'; Port = 19001 },
        [pscustomobject]@{ Pid = 104; Address = '169.254.10.20'; Port = 19002 },
        [pscustomobject]@{ Pid = 999; Address = '0.0.0.0'; Port = 5000 },
        [pscustomobject]@{ Pid = 100; Address = '127.0.0.1'; Port = 40000 }
    )
    $C = @(
        [pscustomobject]@{ Pid = 100; LocalAddress = '127.0.0.1'; LocalPort = 50000; RemoteAddress = '127.0.0.1'; RemotePort = 18443; State = 'Established' },
        [pscustomobject]@{ Pid = 100; LocalAddress = '192.168.1.9'; LocalPort = 50001; RemoteAddress = '20.50.1.1'; RemotePort = 443; State = 'Established' },
        [pscustomobject]@{ Pid = 100; LocalAddress = '0.0.0.0'; LocalPort = 15000; RemoteAddress = '0.0.0.0'; RemotePort = 0; State = 'Listen' },
        [pscustomobject]@{ Pid = 101; LocalAddress = '::1'; LocalPort = 50002; RemoteAddress = '::1'; RemotePort = 18443; State = 'Established' },
        [pscustomobject]@{ Pid = 999; LocalAddress = '10.0.0.1'; LocalPort = 50003; RemoteAddress = '8.8.8.8'; RemotePort = 53; State = 'Established' }
    )
    $f = Get-Cp3AuditFindings -Listeners $L -Connections $C -Pids @(100, 101, 102, 103, 104) -ExpectedPorts @(15000, 18443, 19000)
    $v = @($f.Violations)
    $w = @($f.Warnings)
    $expectV = 7   # 0.0.0.0:15001, ::, ::1, 192.168.1.5, 169.254.10.20 (5 listeners) + 2 non-loopback connections (20.50.1.1 and ::1)
    if ($v.Count -ne $expectV) { return ("FAIL: expected $expectV violations, got $($v.Count): " + ($v -join ' | ')) }
    if (@($v | Where-Object { $_ -match '127\.0\.0\.1:15000' }).Count -ne 0) { return 'FAIL: the good listener was reported' }
    if (@($v | Where-Object { $_ -match 'pid 999' }).Count -ne 0) { return 'FAIL: a process outside the recorded set was reported' }
    if ($w.Count -ne 1 -or $w[0] -notmatch '40000') { return ('FAIL: expected exactly one warning for the unexpected loopback port 40000, got: ' + ($w -join ' | ')) }
    $clean = Get-Cp3AuditFindings -Listeners @($L[0]) -Connections @($C[0]) -Pids @(100) -ExpectedPorts @(15000)
    if (@($clean.Violations).Count -ne 0 -or @($clean.Warnings).Count -ne 0) { return 'FAIL: a clean set produced findings' }
    return '5 non-loopback listeners and 2 non-loopback connections flagged; the 127.0.0.1 listener, other pids and Listen rows are not; one warning for an unexpected loopback port'
}

Run-Check 'H2b' 'Read-only audit plumbing works on this machine (integer pids, no violations for a process with no sockets)' {
    $all = @(Get-Cp3Listeners)
    foreach ($l in $all) { if ($l.Pid -isnot [int] -or $l.Port -isnot [int]) { return 'FAIL: listener fields are not integers' } }
    $me = @($PID)
    $conns = @(Get-Cp3Connections $me)
    $f = Get-Cp3AuditFindings -Listeners $all -Connections $conns -Pids $me -ExpectedPorts @(15000, 18443, 19000)
    if (@($f.Violations).Count -ne 0) { return ('FAIL: ' + (@($f.Violations) -join '; ')) }
    return ('read ' + $all.Count + ' listeners system-wide (none of them touched); this PowerShell process has no listener and no outbound connection')
}

# ================================================================ H3 redaction
Run-Check 'H3' 'Redaction never lets a planted secret through' {
    $red = New-Cp3Redactor
    $alnum = -join ((48..57 + 65..90 + 97..122) | ForEach-Object { [char]$_ })
    $tok = (New-Cp3RandomString 22 $alnum) + '.' + (New-Cp3RandomString 64 '0123456789abcdef')
    $pw = New-Cp3Password
    $pin = New-Cp3Pin
    $ssn = '321-54-9876'
    $sess = 'S-' + [guid]::NewGuid().ToString()
    Add-Cp3Secret $red $tok 'token'
    Add-Cp3Secret $red $pw 'pw'
    Add-Cp3Secret $red $pin 'pin'
    Add-Cp3Secret $red $sess 'session'
    $shapes = @(
        ('{"token":"' + $tok + '","session_id":"' + $sess + '"}'),
        ('Authorization: Bearer ' + $tok),
        ('X-StepUp-Pin: ' + $pin),
        ('GET /x?pw=' + $pw + '&pin=' + $pin),
        ('error while handling ' + $tok + ' for ' + $sess),
        ('{"nested":{"password":"' + $pw + '","step_up_pin":"' + $pin + '","ssn":"' + $ssn + '"}}'),
        ('plain text with ' + $ssn + ' and ' + $pw)
    )
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($s in $shapes) {
        $o = Protect-Cp3Text $red $s
        foreach ($secret in @($tok, $pw, $pin, $sess, $ssn)) { if ($o.Contains($secret)) { $bad.Add('leaked in: ' + $s.Substring(0, [Math]::Min(30, $s.Length))) } }
    }
    # an unregistered token-shaped string and an unregistered 64-hex value are still caught by the generic rules
    $generic = Protect-Cp3Text $red ('seen ' + (New-Cp3RandomString 20 $alnum) + '.' + (New-Cp3RandomString 64 '0123456789abcdef') + ' and ' + (New-Cp3RandomString 64 '0123456789abcdef'))
    if ($generic -match '[0-9a-f]{64}') { $bad.Add('a 64-hex value survived the generic rule') }
    # fingerprints are keyed: two redactors give different fingerprints for the same value
    $red2 = New-Cp3Redactor
    if ((Get-Cp3Fingerprint $red $pin) -ceq (Get-Cp3Fingerprint $red2 $pin)) { $bad.Add('fingerprints are not keyed per run') }
    if ($bad.Count -gt 0) { return ('FAIL: ' + ($bad -join '; ')) }
    return '7 shapes with 5 planted secrets: none survived; generic token/hex rules work; fingerprints differ per run'
}

# ================================================================ H4 patch tool on fixtures
Run-Check 'H4' 'Exact-line patch tool: applies, refuses mismatches, and the three checks agree' {
    $dir = Join-Path $fixRoot 'patchfx'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $orig = Join-Path $dir 'orig.txt'
    $dst = Join-Path $dir 'dst.txt'
    $content = "alpha`nPORT = 1;`n`tTAB line`nPATH = `"C:/Ap project/x`";`nint main() {`n    body`n}`nlast`n"
    [System.IO.File]::WriteAllBytes($orig, $script:Cp3Utf8.GetBytes($content))
    Copy-Item -LiteralPath $orig -Destination $dst
    $edits = @(
        [pscustomobject]@{ id = 1; kind = 'P1'; op = 'replace'; line = 2; original = 'PORT = 1;'; replacement = 'PORT = 2;' },
        [pscustomobject]@{ id = 2; kind = 'P1'; op = 'replace'; line = 4; original = 'PATH = "C:/Ap project/x";'; replacement = 'PATH = "{RUN}/x";' },
        [pscustomobject]@{ id = 3; kind = 'P3'; op = 'insert-after'; line = 5; anchor = 'int main() {'; text = '    hook();' },
        [pscustomobject]@{ id = 4; kind = 'P3'; op = 'insert-after'; line = 1; anchor = 'alpha'; text = '#include <exception>' }
    )
    Invoke-Cp3PatchFile -SourcePath $orig -DestPath $dst -Edits $edits -RunFwd 'C:/run/one' -RunPlaceholder '{RUN}'
    $o = Split-Cp3Lines (Read-Cp3Utf8File $orig)
    $n = Split-Cp3Lines (Read-Cp3Utf8File $dst)
    $exp = Get-Cp3ExpectedPatched -OrigLines $o.Lines -Edits $edits -RunFwd 'C:/run/one' -RunPlaceholder '{RUN}'
    if ($n.Lines.Count -ne $exp.Lines.Count) { return 'FAIL: line count differs from the independent expectation' }
    for ($i = 0; $i -lt $exp.Lines.Count; $i++) { if ($n.Lines[$i] -cne $exp.Lines[$i]) { return "FAIL: line $($i + 1) differs from the independent expectation" } }
    if ((Get-Sha256Hex $dst) -ne (Get-Cp3TextSha256 (Join-Cp3Lines $exp.Lines $o.EndsWithNewline))) { return 'FAIL: hash differs from the independent expectation' }
    $ops = Get-Cp3LineDiff $o.Lines $n.Lines
    $probs = @(Compare-Cp3DiffToSpec $ops $exp.Changes)
    if ($probs.Count -gt 0) { return ('FAIL: diff vs spec: ' + ($probs -join '; ')) }
    if (-not (@($ops | Where-Object { $_.Op -eq '+' -and $_.Text -ceq '    hook();' }).Count -eq 1)) { return 'FAIL: the inserted hook line is not in the diff' }
    # refusals
    $refused = 0
    $cases = @(
        @{ name = 'wrong original text'; edits = @([pscustomobject]@{ id = 9; kind = 'P1'; op = 'replace'; line = 2; original = 'PORT = 9;'; replacement = 'x' }) },
        @{ name = 'shifted line'; edits = @([pscustomobject]@{ id = 9; kind = 'P1'; op = 'replace'; line = 3; original = 'PORT = 1;'; replacement = 'x' }) },
        @{ name = 'line beyond the end'; edits = @([pscustomobject]@{ id = 9; kind = 'P1'; op = 'replace'; line = 99; original = 'x'; replacement = 'y' }) },
        @{ name = 'wrong anchor'; edits = @([pscustomobject]@{ id = 9; kind = 'P3'; op = 'insert-after'; line = 5; anchor = 'int main(){'; text = 'x' }) },
        @{ name = 'unknown operation'; edits = @([pscustomobject]@{ id = 9; kind = 'P3'; op = 'delete'; line = 2; original = 'PORT = 1;' }) }
    )
    foreach ($c in $cases) {
        $d2 = Join-Path $dir ('refuse-' + $refused + '.txt')
        Copy-Item -LiteralPath $orig -Destination $d2
        $threw = $false
        try { Invoke-Cp3PatchFile -SourcePath $orig -DestPath $d2 -Edits $c.edits -RunFwd 'C:/run/one' -RunPlaceholder '{RUN}' } catch { $threw = $true }
        if (-not $threw) { return ('FAIL: not refused: ' + $c.name) }
        if ((Get-Sha256Hex $d2) -ne (Get-Sha256Hex $orig)) { return ('FAIL: the destination was modified by a refused patch: ' + $c.name) }
        $refused++
    }
    # applying the same spec to the already patched file is refused (the originals no longer match)
    $threw = $false
    try { Invoke-Cp3PatchFile -SourcePath $dst -DestPath (Join-Path $dir 'twice.txt') -Edits $edits -RunFwd 'C:/run/one' -RunPlaceholder '{RUN}' } catch { $threw = $true }
    if (-not $threw) { return 'FAIL: a second application was not refused' }
    # CRLF and BOM files are refused
    $crlf = Join-Path $dir 'crlf.txt'
    [System.IO.File]::WriteAllBytes($crlf, $script:Cp3Utf8.GetBytes("a`r`nb`r`n"))
    $threw = $false
    try { Invoke-Cp3PatchFile -SourcePath $crlf -DestPath (Join-Path $dir 'crlf2.txt') -Edits @([pscustomobject]@{ id = 1; kind = 'P1'; op = 'replace'; line = 1; original = 'a'; replacement = 'b' }) -RunFwd 'x' -RunPlaceholder '{RUN}' } catch { $threw = $true }
    if (-not $threw) { return 'FAIL: a CRLF file was not refused' }
    # a deliberately wrong "after" file must be caught by the independent diff comparison
    $wrongLines = @($n.Lines)
    $wrongLines[1] = 'PORT = 3;'
    $badOps = Get-Cp3LineDiff $o.Lines $wrongLines
    if (@(Compare-Cp3DiffToSpec $badOps $exp.Changes).Count -eq 0) { return 'FAIL: the diff-vs-spec comparison missed a wrong replacement' }
    return '4 edits applied; line-by-line, diff-vs-spec and hash checks agree; 5 bad specs, a second application, a CRLF file refused with the destination untouched; a wrong result is caught'
}

# ================================================================ H5 static gates on fixtures
Run-Check 'H5' 'Static gates catch planted violations and list the harmless placeholder' {
    $dir = Join-Path $fixRoot 'gatefx'
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'src') | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dir 'src\a.java'), "class A { void f() { x = new InetSocketAddress(port); } }`n", $script:Cp3Utf8)
    [System.IO.File]::WriteAllText((Join-Path $dir 'src\b.cpp'), "int g() { s.s_addr = INADDR_ANY; return bind(s, a, n); }`nconst char* p = `"0.0.0.0`";`n", $script:Cp3Utf8)
    [System.IO.File]::WriteAllText((Join-Path $dir 'src\c.h'), "// path C:/Ap project/db is in a comment`n", $script:Cp3Utf8)
    [System.IO.File]::WriteAllBytes((Join-Path $dir 'src\d.bin'), $script:Cp3Latin1.GetBytes('xx' + 'Ap_project_backup' + 'yy'))
    [System.IO.File]::WriteAllBytes((Join-Path $dir 'src\e.bin'), [System.Text.Encoding]::Unicode.GetBytes('Ap project'))
    $needleHits = @(Find-Cp3Needles -Root $dir -Needles @('Ap project', 'Ap_project'))
    $files = @($needleHits | ForEach-Object { $_.File + ':' + $_.Form } | Sort-Object)
    $wantFiles = @('src/c.h:ascii', 'src/d.bin:ascii', 'src/e.bin:utf-16le')
    if (($files -join '|') -ne ($wantFiles -join '|')) { return ('FAIL: needle search found ' + ($files -join ', ')) }
    $forb = @(Test-Cp3ForbiddenPatterns -Root $dir -Patterns @('INADDR_ANY', 'new\s+InetSocketAddress\s*\(\s*port\s*\)'))
    if ($forb.Count -ne 2) { return ('FAIL: expected 2 forbidden-pattern hits, got ' + $forb.Count) }
    $regex = 'bind\s*\(|InetSocketAddress\s*\(|INADDR_[A-Z]+|0\.0\.0\.0'
    $hits = @(Get-Cp3SourceHits -Root $dir -Regex $regex)
    $expected = @(
        [pscustomobject]@{ file = 'src/a.java'; text = 'class A { void f() { x = new InetSocketAddress(port); } }' },
        [pscustomobject]@{ file = 'src/b.cpp'; text = 'int g() { s.s_addr = INADDR_ANY; return bind(s, a, n); }' },
        [pscustomobject]@{ file = 'src/b.cpp'; text = 'const char* p = "0.0.0.0";' }
    )
    if (@(Compare-Cp3BindSites -Hits $hits -Expected $expected).Count -ne 0) { return 'FAIL: the exact list was reported as different' }
    $short = @($expected[0], $expected[1])
    if (@(Compare-Cp3BindSites -Hits $hits -Expected $short).Count -eq 0) { return 'FAIL: a binding site missing from the expected list was not reported' }
    $extra = $expected + @([pscustomobject]@{ file = 'src/z.cpp'; text = 'listen(s, 5);' })
    if (@(Compare-Cp3BindSites -Hits $hits -Expected $extra).Count -eq 0) { return 'FAIL: an expected site that is absent was not reported' }
    return 'ASCII and UTF-16 path strings found; INADDR_ANY and "new InetSocketAddress(port)" found; exact bind-site comparison works in both directions; the placeholder is listed, not failed'
}

# ================================================================ H6 raw HTTP bytes and the host lock
Run-Check 'H6' 'Raw request/probe bytes are exact; the target is locked to 127.0.0.1:15000' {
    $get = $script:Cp3Latin1.GetString((New-Cp3RequestBytes -Method 'GET' -Path '/x' -Headers @{ 'X-Device-Id' = 'D' } -Body $null))
    if ($get -ne "GET /x HTTP/1.1`r`nHost: 127.0.0.1:15000`r`nConnection: close`r`nX-Device-Id: D`r`n`r`n") { return 'FAIL: GET request bytes differ' }
    $body = $script:Cp3Utf8.GetBytes('{"a":1}')
    $post = $script:Cp3Latin1.GetString((New-Cp3RequestBytes -Method 'POST' -Path '/login' -Headers @{} -Body $body))
    if ($post -ne "POST /login HTTP/1.1`r`nHost: 127.0.0.1:15000`r`nConnection: close`r`nContent-Length: 7`r`n`r`n{`"a`":1}") { return 'FAIL: POST request bytes differ' }
    $p1 = $script:Cp3Latin1.GetString((New-Cp3ProbeBytes 'P1'))
    if ($p1 -ne "POST /login HTTP/1.1`r`nHost: 127.0.0.1:15000`r`nContent-Length: abc`r`nConnection: close`r`n`r`n") { return 'FAIL: probe P1 bytes differ' }
    $p2 = New-Cp3ProbeBytes 'P2'
    $idx = -1
    for ($i = 0; $i -lt $p2.Length - 1; $i++) { if ($p2[$i] -eq 0xFF -and $p2[$i + 1] -eq 0xFE) { $idx = $i; break } }
    if ($idx -lt 0) { return 'FAIL: probe P2 does not contain the bytes FF FE' }
    $pre = $script:Cp3Latin1.GetString($p2, 0, $idx)
    $post2 = $script:Cp3Latin1.GetString($p2, $idx + 2, $p2.Length - $idx - 2)
    if ($pre -ne "GET /api/public/info HTTP/1.1`r`nHost: 127.0.0.1:15000`r`nAuthorization: Bearer ") { return 'FAIL: probe P2 prefix differs' }
    if ($post2 -ne "`r`nX-Device-Id: probe`r`nConnection: close`r`n`r`n") { return 'FAIL: probe P2 suffix differs' }
    $strictThrew = $false
    try { [void](New-Object System.Text.UTF8Encoding($false, $true)).GetString([byte[]](0xFF, 0xFE)) } catch { $strictThrew = $true }
    if (-not $strictThrew) { return 'FAIL: bytes FF FE are valid UTF-8 (the probe would prove nothing)' }
    $threwUnknown = $false
    try { [void](New-Cp3ProbeBytes 'P3') } catch { $threwUnknown = $true }
    if (-not $threwUnknown) { return 'FAIL: an unknown probe name was accepted' }
    # response parsing
    $raw = $script:Cp3Latin1.GetBytes("HTTP/1.1 401 Unauthorized`r`nContent-Type: application/json`r`nContent-Length: 11`r`nConnection: close`r`n`r`n{`"error`":1}EXTRA")
    $r = ConvertFrom-Cp3RawResponse $raw
    if (-not $r.Received -or $r.Status -ne 401 -or $r.BodyText -ne '{"error":1}' -or $r.Headers['content-type'] -ne 'application/json') { return 'FAIL: response parsing differs' }
    if ((ConvertFrom-Cp3RawResponse (New-Object byte[] 0)).Received) { return 'FAIL: an empty response was reported as received' }
    # the only socket function has no host or port parameter
    $names = @((Get-Command Send-Cp3Raw).Parameters.Keys | Where-Object { $_ -notin @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable') })
    if (($names | Sort-Object) -join ',' -ne 'RequestBytes,TimeoutMs') { return ('FAIL: Send-Cp3Raw parameters are ' + ($names -join ',')) }
    if ($script:Cp3PepHost -ne '127.0.0.1' -or $script:Cp3PepPort -ne 15000) { return 'FAIL: the locked target changed' }
    return 'GET/POST/P1/P2 bytes are exactly as specified (FF FE is invalid UTF-8); responses parse; Send-Cp3Raw takes only bytes and a timeout and targets 127.0.0.1:15000'
}

# ================================================================ H7 tripwire
Run-Check 'H7' 'File tripwire detects a size change and a modification-time change on a fixture' {
    $dir = Join-Path $fixRoot 'tripfx'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $a = Join-Path $dir 'a.db'
    $b = Join-Path $dir 'b.db-wal'
    [System.IO.File]::WriteAllBytes($a, (New-Object byte[] 100))
    [System.IO.File]::WriteAllBytes($b, (New-Object byte[] 50))
    $s0 = Get-Cp3FileStamps @($a, $b, (Join-Path $dir 'missing.db'))
    if (@(Compare-Cp3FileStamps $s0 (Get-Cp3FileStamps @($a, $b, (Join-Path $dir 'missing.db')))).Count -ne 0) { return 'FAIL: false alarm on unchanged files' }
    $fs = [System.IO.File]::Open($a, 'Append'); $fs.WriteByte(1); $fs.Close()
    $c1 = @(Compare-Cp3FileStamps $s0 (Get-Cp3FileStamps @($a, $b, (Join-Path $dir 'missing.db'))))
    if ($c1.Count -ne 1 -or $c1[0] -ne $a) { return 'FAIL: the size change was not detected' }
    (Get-Item -LiteralPath $b).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddMinutes(-7)
    $c2 = @(Compare-Cp3FileStamps $s0 (Get-Cp3FileStamps @($a, $b, (Join-Path $dir 'missing.db'))))
    if ($c2.Count -ne 2) { return 'FAIL: the modification-time change was not detected' }
    return 'unchanged -> no alarm; +1 byte -> detected; modification time only -> detected; (stamps use size and time, the file is not opened)'
}

# ================================================================ H8 expectations file
Run-Check 'H8' 'Frozen expectations: parse, completeness, counts, vocabulary' {
    $exp = Read-Cp3Expectations $ExpectationsPath
    $ids = @($exp.Steps.Keys | Sort-Object)
    if ($ids.Count -ne 30) { return "FAIL: $($ids.Count) steps, expected 30" }
    $ops = @('eq', 'ne', 'in', 'between', 'lte', 'gte', 'contains', 'startsWith', 'exists', 'hasAll', 'lacksAll')
    $c = @{ PASS = 0; FAIL = 0; OBSERVATION = 0 }
    foreach ($id in $ids) {
        $s = $exp.Steps[$id]
        foreach ($f in @('scenario', 'title', 'request', 'requirementText', 'requirement', 'predictionText', 'prediction', 'predictedBaseline')) { if (-not (Test-Cp3HasProp $s $f)) { return "FAIL: $id lacks $f" } }
        if ([string]$s.predictedBaseline -notin @('PASS', 'FAIL', 'OBSERVATION')) { return "FAIL: $id has an invalid predictedBaseline" }
        $c[[string]$s.predictedBaseline]++
        $isObs = Test-Cp3HasProp $s.requirement 'observation'
        if ($isObs -and [string]$s.predictedBaseline -ne 'OBSERVATION') { return "FAIL: $id is an observation but predicts $($s.predictedBaseline)" }
        if (-not $isObs -and [string]$s.predictedBaseline -eq 'OBSERVATION') { return "FAIL: $id has a requirement but predicts OBSERVATION" }
        $all = @($s.prediction.all)
        if (-not $isObs) { $all += @($s.requirement.all) }
        foreach ($chk in $all) { if ([string]$chk.op -notin $ops) { return "FAIL: $id uses the unknown operator '$($chk.op)'" } }
    }
    if ($c.PASS -ne 19 -or $c.FAIL -ne 8 -or $c.OBSERVATION -ne 3) { return ("FAIL: predicted counts PASS=$($c.PASS) FAIL=$($c.FAIL) OBSERVATION=$($c.OBSERVATION), expected 19/8/3") }
    $h = Get-Sha256Hex $ExpectationsPath
    Write-Cp3Text (Join-Path $OutDir 'expectations.sha256') @("$h  tests/baseline/cp3_expectations.json")
    return ("30 steps; predicted PASS 19, FAIL 8, OBSERVATION 3; every operator is in the vocabulary; sha256 $h")
}

# ================================================================ H9 random credentials
Run-Check 'H9' 'Generated credentials: shape, alphabet and uniqueness (values are never printed)' {
    $pws = New-Object System.Collections.Generic.HashSet[string]
    $pins = New-Object System.Collections.Generic.HashSet[string]
    for ($i = 0; $i -lt 200; $i++) {
        $p = New-Cp3Password
        $n = New-Cp3Pin
        if ($p.Length -ne 24 -or ($p -notmatch '^[a-zA-Z2-9]+$') -or ($p -cmatch '[lIO]')) { return 'FAIL: password shape' }
        if ($n.Length -ne 8 -or $n -notmatch '^\d{8}$') { return 'FAIL: PIN shape' }
        [void]$pws.Add($p)
        [void]$pins.Add($n)
    }
    if ($pws.Count -ne 200) { return 'FAIL: duplicate passwords in 200 draws' }
    if ($pins.Count -lt 199) { return 'FAIL: too many duplicate PINs in 200 draws' }
    # known-answer check of the hash helper used for fingerprints and manifests
    $kf = Join-Path $fixRoot 'abc.bin'
    [System.IO.File]::WriteAllBytes($kf, [System.Text.Encoding]::ASCII.GetBytes('abc'))
    if ((Get-Cp3TextSha256 'abc') -ne (Get-FileHash -LiteralPath $kf -Algorithm SHA256).Hash.ToLower()) { return 'FAIL: the SHA-256 helper disagrees with Get-FileHash' }
    return '200 passwords (24 chars) and 200 PINs (8 digits) drawn: all passwords distinct, shapes correct, no look-alike characters (l, I, O); the SHA-256 helper agrees with Get-FileHash'
}

# ================================================================ H10 stop-by-record safety (harmless sleeper only)
Run-Check 'H10' 'A recorded process is only stopped when pid, start time and image path all match' {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args1 = @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120')
    $runDir = Join-Path $fixRoot 'stopfx'
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $pidFile = Join-Path $runDir 'pids.tsv'
    $job = New-Cp3Job
    $rec = $null
    try {
        $rec = Start-Cp3Process -Role 'sleeper' -Kind 'harmless' -File $ps -Arguments $args1 -WorkingDirectory $runDir -StdOutPath (Join-Path $runDir 'o.log') -StdErrPath (Join-Path $runDir 'e.log') -Job $job -PidFile $pidFile -TreeRoot $runDir
        $fromFile = @(Read-Cp3PidFile $pidFile)
        if ($fromFile.Count -ne 1 -or [int]$fromFile[0].Pid -ne $rec.Pid) { return 'FAIL: the pid file does not hold the record' }
        $wrongTime = [pscustomobject]@{ Role = 'x'; Pid = $rec.Pid; StartUtcTicks = ($rec.StartUtcTicks + 10000000); ImagePath = $rec.ImagePath }
        $wrongPath = [pscustomobject]@{ Role = 'x'; Pid = $rec.Pid; StartUtcTicks = $rec.StartUtcTicks; ImagePath = 'C:\other\program.exe' }
        $r1 = Stop-Cp3Recorded $wrongTime
        $r2 = Stop-Cp3Recorded $wrongPath
        if (-not $r1.StartsWith('REFUSED') -or -not $r2.StartsWith('REFUSED')) { return "FAIL: a mismatching record was not refused ($r1 / $r2)" }
        if ((Get-Process -Id $rec.Pid -ErrorAction SilentlyContinue) -eq $null) { return 'FAIL: the process was stopped by a mismatching record' }
        $r3 = Stop-Cp3Recorded $fromFile[0]
        if ($r3 -ne 'stopped') { return "FAIL: the matching record was not stopped ($r3)" }
        $r4 = Stop-Cp3Recorded $fromFile[0]
        if ($r4 -ne 'already-gone') { return "FAIL: second stop returned $r4" }
        return 'wrong start time -> REFUSED and alive; wrong image path -> REFUSED and alive; the record read back from the pid file -> stopped; again -> already-gone'
    } finally {
        if ($null -ne $rec) { $p = Get-Process -Id $rec.Pid -ErrorAction SilentlyContinue; if ($p) { try { $p.Kill() } catch { } } }
        Close-Cp3Job $job
    }
}

# ================================================================ H13 Phase B control helpers through closures (harmless sleepers only)
Run-Check 'H13' 'Phase B control helpers (stop by role, exit info, latest record, port status, log wait) work through closures' {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $sleepArgs = @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120')
    $runDir = Join-Path $fixRoot 'ctlfx'
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $pidFile = Join-Path $runDir 'pids.tsv'
    $job = New-Cp3Job
    $recs = New-Object System.Collections.Generic.List[object]
    $startOne = {
        param([string]$role, [string]$tag)
        $r = Start-Cp3Process -Role $role -Kind 'harmless' -File $ps -Arguments $sleepArgs -WorkingDirectory $runDir -StdOutPath (Join-Path $runDir ($tag + '.out.log')) -StdErrPath (Join-Path $runDir ($tag + '.err.log')) -Job $job -PidFile $pidFile -TreeRoot $runDir
        $recs.Add($r)
        return $r
    }
    try {
        $agent = & $startOne 'agent' 'agent1'
        $pep1 = & $startOne 'pep' 'pep1'
        # closures shaped exactly like the ones Run-Cp3.ps1 builds for Phase B
        $ctl = @{
            StopAgent = { return (Stop-Cp3Role $pidFile 'agent') }.GetNewClosure()
            PepExitInfo = { return (Get-Cp3RoleExitInfo $pidFile 'pep') }.GetNewClosure()
            PortsListening = { return (Get-Cp3PortStatus) }
        }
        $e0 = & $ctl.PepExitInfo
        if ($e0.Exited) { return 'FAIL: a running process was reported as exited' }
        $s1 = & $ctl.StopAgent
        if ($s1 -ne 'stopped') { return "FAIL: the agent-role process was not stopped ($s1)" }
        if ($null -ne (Get-Process -Id $agent.Pid -ErrorAction SilentlyContinue)) { return 'FAIL: the agent-role process is still running' }
        if ((Get-Process -Id $pep1.Pid -ErrorAction SilentlyContinue) -eq $null) { return 'FAIL: stopping the agent role also stopped the pep-role process' }
        $s2 = & $ctl.StopAgent
        if ($s2 -ne 'already-gone') { return "FAIL: stopping again returned $s2" }
        $threw = $false
        try { [void](Stop-Cp3Role $pidFile 'api') } catch { $threw = $true }
        if (-not $threw) { return 'FAIL: stopping a role that was never recorded did not throw' }
        # a "crash": the pep-role process disappears without the helper being involved
        Stop-Process -Id $pep1.Pid -Force
        $deadline = (Get-Date).AddSeconds(5)
        $e1 = $null
        while ((Get-Date) -lt $deadline) { $e1 = & $ctl.PepExitInfo; if ($e1.Exited) { break }; Start-Sleep -Milliseconds 200 }
        if (-not $e1.Exited) { return 'FAIL: the exit of the pep-role process was not noticed' }
        if ($null -eq $e1.ExitCode -or $e1.ExitCode -isnot [int]) { return 'FAIL: no integer exit code for a process this script started' }
        # the most recent record of a role wins
        $pep2 = & $startOne 'pep' 'pep2'
        if ((Get-Cp3LatestRecord $pidFile 'pep').Pid -ne $pep2.Pid) { return 'FAIL: the latest record of a role was not selected' }
        $e2 = & $ctl.PepExitInfo
        if ($e2.Exited) { return 'FAIL: the restarted process was reported as exited' }
        $ps1 = & $ctl.PortsListening
        if ($ps1.Api -isnot [bool] -or $ps1.Pdp -isnot [bool] -or $ps1.Pep -isnot [bool]) { return 'FAIL: port status is not boolean' }
        # waiting for a line in a log file that is still open for writing by another handle
        $lf = Join-Path $runDir 'live.log'
        $fs = New-Object System.IO.FileStream($lf, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        try {
            $line = $script:Cp3Utf8.GetBytes("[Agent] heartbeat: firewall=true av=true -> HTTP 200 {}`r`n")
            $fs.Write($line, 0, $line.Length)
            $fs.Flush()
            if (-not (Wait-Cp3LogMatch $lf 'heartbeat:.*HTTP 200' 5)) { return 'FAIL: a line in a log that is still open for writing was not found' }
            if (Wait-Cp3LogMatch $lf 'this-text-is-not-in-the-log' 1) { return 'FAIL: a missing line was reported as found' }
        } finally { $fs.Dispose() }
        if (Wait-Cp3LogMatch (Join-Path $runDir 'no-such.log') 'x' 1) { return 'FAIL: a missing file was reported as matching' }
        return 'stop-by-role stops only that role and is idempotent; an unknown role throws; a vanished process is noticed with an integer exit code; the latest record wins; port status is boolean; a log still open for writing is readable. The closures call the named helpers correctly. (Wait-Cp3Listener and Start-Cp3Process with a legacy program need a real listener or program and are NOT exercised.)'
    } finally {
        foreach ($r in $recs) { $p = Get-Process -Id $r.Pid -ErrorAction SilentlyContinue; if ($p) { try { $p.Kill() } catch { } } }
        Close-Cp3Job $job
    }
}

# ================================================================ H15 Job Object process list and the real JVM
Run-Check 'H15' 'Job Object lists every process in the job; the real JVM (not the PATH launcher shim) is what gets recorded' {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $sleepArgs = @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120')
    $runDir = Join-Path $fixRoot 'jobfx'
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $pidFile = Join-Path $runDir 'pids.tsv'
    $job = New-Cp3Job
    $recs = New-Object System.Collections.Generic.List[object]
    $extra = New-Object System.Collections.Generic.List[object]
    try {
        if (@(Get-Cp3JobPids $job).Count -ne 0) { return 'FAIL: a new job is not empty' }
        foreach ($tag in @('s1', 's2')) {
            $recs.Add((Start-Cp3Process -Role $tag -Kind 'harmless' -File $ps -Arguments $sleepArgs -WorkingDirectory $runDir -StdOutPath (Join-Path $runDir ($tag + '.out.log')) -StdErrPath (Join-Path $runDir ($tag + '.err.log')) -Job $job -PidFile $pidFile -TreeRoot $runDir))
        }
        $ids = @(Get-Cp3JobPids $job)
        foreach ($r in $recs) { if ($ids -notcontains $r.Pid) { return "FAIL: pid $($r.Pid) is missing from the job list" } }
        $others = @($ids | Where-Object { $pid1 = $_; @($recs | Where-Object { $_.Pid -eq $pid1 }).Count -eq 0 })
        Stop-Process -Id $recs[0].Pid -Force
        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline -and (@(Get-Cp3JobPids $job) -contains $recs[0].Pid)) { Start-Sleep -Milliseconds 200 }
        if (@(Get-Cp3JobPids $job) -contains $recs[0].Pid) { return 'FAIL: a stopped process is still listed in the job' }
        if (@(Get-Cp3JobPids $job) -notcontains $recs[1].Pid) { return 'FAIL: the surviving process vanished from the job list' }
        # the real JVM: the shim that is first on PATH starts it as a child process
        $rj = Get-Cp3RealJavaExe
        if ((Split-Path -Leaf $rj) -ne 'java.exe' -or $rj -match 'Common Files\\Oracle\\Java\\javapath') { return "FAIL: the resolved java is not the real JVM ($rj)" }
        $javac = Find-Tool 'javac'
        $src = Join-Path $runDir 'SleepProbe.java'
        $cls = Join-Path $runDir 'cls'
        New-Item -ItemType Directory -Force -Path $cls | Out-Null
        [System.IO.File]::WriteAllText($src, "public class SleepProbe { public static void main(String[] a) throws Exception { System.out.println(`"pid=`" + ProcessHandle.current().pid()); Thread.sleep(20000); } }`n", $script:Cp3Utf8)
        $jc = Invoke-Native -File $javac -Arguments @('-d', $cls, $src) -WorkingDirectory $runDir -TimeoutSec 120
        if ($jc.ExitCode -ne 0) { return ('FAIL: the probe class did not compile: ' + $jc.StdErr.Trim()) }
        $shim = Find-Tool 'java'
        $viaShim = $null
        $direct = $null
        $shimNote = 'the PATH java.exe is already the real JVM'
        if ($shim -ine $rj) {
            Add-Cp3LaunchLog 'probe' $shim @('SleepProbe (own harmless class)')
            $viaShim = Start-Process -FilePath $shim -ArgumentList (ConvertTo-ArgString @('-cp', $cls, 'SleepProbe')) -RedirectStandardOutput (Join-Path $runDir 'shim.out') -RedirectStandardError (Join-Path $runDir 'shim.err') -WindowStyle Hidden -PassThru
            $extra.Add($viaShim)
            if (-not (Wait-Cp3LogMatch (Join-Path $runDir 'shim.out') 'pid=\d+' 20)) { return 'FAIL: the probe started through the shim printed nothing' }
            $printed = [int]([regex]::Match((Read-Cp3SharedText (Join-Path $runDir 'shim.out')), 'pid=(\d+)').Groups[1].Value)
            if ($printed -eq $viaShim.Id) { return 'FAIL: expected the shim to start the JVM as a child process, but the JVM runs in the shim process' }
            $kid = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $printed)
            if ($null -eq $kid -or $kid.ParentProcessId -ne $viaShim.Id -or $kid.ExecutablePath -ine $rj) { return 'FAIL: the JVM child of the shim is not the real java.exe' }
            $shimNote = "through the PATH shim the JVM is a CHILD process (shim pid $($viaShim.Id), JVM pid $printed), which is why the real java.exe is launched directly"
        }
        Add-Cp3LaunchLog 'probe' $rj @('SleepProbe (own harmless class)')
        $direct = Start-Process -FilePath $rj -ArgumentList (ConvertTo-ArgString @('-cp', $cls, 'SleepProbe')) -RedirectStandardOutput (Join-Path $runDir 'direct.out') -RedirectStandardError (Join-Path $runDir 'direct.err') -WindowStyle Hidden -PassThru
        $extra.Add($direct)
        if (-not (Wait-Cp3LogMatch (Join-Path $runDir 'direct.out') 'pid=\d+' 20)) { return 'FAIL: the probe started directly printed nothing' }
        $printed2 = [int]([regex]::Match((Read-Cp3SharedText (Join-Path $runDir 'direct.out')), 'pid=(\d+)').Groups[1].Value)
        if ($printed2 -ne $direct.Id) { return 'FAIL: started directly, the JVM pid differs from the process pid' }
        $img = Get-Cp3ImagePath $direct
        if ($img -ine $rj) { return 'FAIL: the image of the directly started JVM is not the resolved real java.exe' }
        return ("job list: both sleepers listed (" + $others.Count + " other pid(s) in the job), a stopped one disappears; real JVM = $rj; $shimNote; started directly, process pid = JVM pid and the recorded image is the real java.exe")
    } finally {
        foreach ($r in $recs) { $x = Get-Process -Id $r.Pid -ErrorAction SilentlyContinue; if ($x) { try { $x.Kill() } catch { } } }
        foreach ($pr in $extra) {
            $kids = @(Get-CimInstance -ClassName Win32_Process -Filter ('ParentProcessId=' + $pr.Id) -ErrorAction SilentlyContinue)
            foreach ($k in $kids) { $x = Get-Process -Id $k.ProcessId -ErrorAction SilentlyContinue; if ($x -and $x.ProcessName -eq 'java') { try { $x.Kill() } catch { } } }
            $x = Get-Process -Id $pr.Id -ErrorAction SilentlyContinue; if ($x) { try { $x.Kill() } catch { } }
        }
        Close-Cp3Job $job
    }
}

# ================================================================ H14 Stop-Cp3.ps1 end to end (harmless sleepers only)
Run-Check 'H14' 'Stop-Cp3.ps1 end to end: stops only the recorded process, refuses a tampered record, is idempotent' {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $sleepArgs = @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120')
    $runDir = Join-Path $fixRoot 'stopscript'
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $pidFile = Join-Path $runDir 'pids.tsv'
    $stopScript = Join-Path $PSScriptRoot 'Stop-Cp3.ps1'
    $job = New-Cp3Job
    $rec = $null
    $bystander = $null
    $runStop = { Invoke-Native -File $ps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stopScript, '-RunDir', $runDir) -WorkingDirectory $runDir -TimeoutSec 60 }
    try {
        $rec = Start-Cp3Process -Role 'agent' -Kind 'harmless' -File $ps -Arguments $sleepArgs -WorkingDirectory $runDir -StdOutPath (Join-Path $runDir 'a.out.log') -StdErrPath (Join-Path $runDir 'a.err.log') -Job $job -PidFile $pidFile -TreeRoot $runDir
        # a process that is NOT in the pid file and must never be touched
        $bystander = Start-Process -FilePath $ps -ArgumentList (ConvertTo-ArgString $sleepArgs) -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 300
        # 1. tampered start time -> REFUSED, exit code 1, both processes still alive
        $original = [System.IO.File]::ReadAllText($pidFile, $script:Cp3Utf8)
        $parts = $original.TrimEnd().Split([char]9)
        $parts[2] = [string]([long]$parts[2] + 10000000)
        [System.IO.File]::WriteAllText($pidFile, ([string]::Join([string][char]9, $parts) + "`r`n"), $script:Cp3Utf8)
        $r1 = & $runStop
        if ($r1.ExitCode -ne 1 -or $r1.StdOut -notmatch 'REFUSED') { return ("FAIL: a tampered record was not refused (exit code $($r1.ExitCode)): " + $r1.StdOut.Trim()) }
        if ($null -eq (Get-Process -Id $rec.Pid -ErrorAction SilentlyContinue)) { return 'FAIL: the recorded process was stopped although its record was tampered with' }
        # 2. correct record -> stopped, exit code 0, the bystander survives
        [System.IO.File]::WriteAllText($pidFile, $original, $script:Cp3Utf8)
        $r2 = & $runStop
        if ($r2.ExitCode -ne 0 -or $r2.StdOut -notmatch 'stopped') { return ("FAIL: the recorded process was not stopped (exit code $($r2.ExitCode)): " + $r2.StdOut.Trim() + ' ' + $r2.StdErr.Trim()) }
        if ($null -ne (Get-Process -Id $rec.Pid -ErrorAction SilentlyContinue)) { return 'FAIL: the recorded process is still running' }
        if ($null -eq (Get-Process -Id $bystander.Id -ErrorAction SilentlyContinue)) { return 'FAIL: a process that was not recorded was stopped' }
        # 3. again -> already-gone, exit code 0
        $r3 = & $runStop
        if ($r3.ExitCode -ne 0 -or $r3.StdOut -notmatch 'already-gone') { return ("FAIL: the second run was not idempotent (exit code $($r3.ExitCode)): " + $r3.StdOut.Trim()) }
        # 4. no pid file -> nothing happens
        $empty = Join-Path $fixRoot 'stopscript-empty'
        New-Item -ItemType Directory -Force -Path $empty | Out-Null
        $r4 = Invoke-Native -File $ps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stopScript, '-RunDir', $empty) -WorkingDirectory $empty -TimeoutSec 60
        if ($r4.ExitCode -ne 0 -or $r4.StdOut -notmatch 'nothing is stopped') { return 'FAIL: a run folder without a pid file was not handled' }
        return 'tampered start time -> REFUSED (exit 1, process alive); correct record -> stopped (exit 0); an unrecorded bystander process survives; second run -> already-gone (exit 0); no pid file -> nothing stopped'
    } finally {
        if ($null -ne $rec) { $x = Get-Process -Id $rec.Pid -ErrorAction SilentlyContinue; if ($x) { try { $x.Kill() } catch { } } }
        if ($null -ne $bystander) { $x = Get-Process -Id $bystander.Id -ErrorAction SilentlyContinue; if ($x) { try { $x.Kill() } catch { } } }
        Close-Cp3Job $job
    }
}

# ================================================================ C1-C5 checks: rig of harmless sleepers (no socket of ours, no legacy program)
$script:psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:sleepArgs = @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120')
$script:rigs = New-Object System.Collections.Generic.List[object]

function Get-ThrownMessage([scriptblock]$Body) {
    try { & $Body | Out-Null; return $null } catch { return $_.Exception.Message }
}

function Start-RigSleeper($Rig, [string]$Role) {
    $Rig.Seq++
    $tag = $Role + $Rig.Seq
    return (Start-Cp3Process -Role $Role -Kind 'harmless' -File $script:psExe -Arguments $script:sleepArgs -WorkingDirectory $Rig.Dir -StdOutPath (Join-Path $Rig.Dir ($tag + '.out.log')) -StdErrPath (Join-Path $Rig.Dir ($tag + '.err.log')) -Job $Rig.Job -PidFile $Rig.PidFile -TreeRoot $Rig.Dir)
}

# A "crash" from the monitor's point of view: the newest recorded process of the role is killed from outside.
function Stop-RigProcess($Rig, [string]$Role) {
    $rec = Get-Cp3LatestRecord $Rig.PidFile $Role
    Stop-Process -Id $rec.Pid -Force
    [void](Get-Cp3ProcObject ([int]$rec.Pid)).WaitForExit(5000)
}

function New-SleeperRig([string]$Name, [string[]]$Roles = @('api', 'pdp', 'pep', 'agent')) {
    $dir = Join-Path $fixRoot $Name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $db = @('stand-in.db', 'stand-in.db-wal', 'stand-in.db-shm' | ForEach-Object { Join-Path $dir $_ })
    foreach ($p in $db) { [System.IO.File]::WriteAllBytes($p, (New-Object byte[] 16)) }
    $rig = [pscustomobject]@{ Dir = $dir; PidFile = (Join-Path $dir 'pids.tsv'); Job = (New-Cp3Job); Expect = (New-Cp3Expect); Db = $db; Extra = (New-Object System.Collections.Generic.List[object]); Mon = $null; Seq = 0 }
    $rig.Mon = New-Cp3Monitor -PidFile $rig.PidFile -Job $rig.Job -Expect $rig.Expect -LivePaths $db -LiveStamps (Get-Cp3FileStamps $db) -AuditFile '' -Ports $script:Cp3TestPorts -ExpectedListeners @{} -WatchdogSec 600 -AuditEverySec 5
    $script:rigs.Add($rig)
    foreach ($r in $Roles) { [void](Start-RigSleeper $rig $r); Set-Cp3RoleStarted $rig.Expect $r }
    return $rig
}

function Remove-SleeperRig($Rig) {
    foreach ($r in @(Read-Cp3PidFile $Rig.PidFile)) { $x = Get-Process -Id $r.Pid -ErrorAction SilentlyContinue; if ($x) { try { $x.Kill() } catch { } } }
    foreach ($x in $Rig.Extra) { $y = Get-Process -Id $x.Id -ErrorAction SilentlyContinue; if ($y) { try { $y.Kill() } catch { } } }
    Close-Cp3Job $Rig.Job
}

# ================================================================ H16 run-state monitor (C1, C2)
Run-Check 'H16' 'Run-state monitor: unexpected exits, unexpected job members and planned-exit windows only at the exact steps (harmless sleepers)' {
    $problems = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $rig = New-SleeperRig 'mon1'
    try {
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { return "FAIL: a clean rig was reported: $m" }
        if (@(Get-Cp3RunStateProblems -PidFile $rig.PidFile -Job $rig.Job -Expect $rig.Expect).Count -ne 0) { return 'FAIL: a clean rig has run-state problems' }
        # job members that are not recorded must all be the console hosts that Windows creates for hidden console programs, and they are tolerated
        $recPids = @(Read-Cp3PidFile $rig.PidFile | ForEach-Object { [int]$_.Pid })
        $unrec = @(Get-Cp3JobPids $rig.Job | Where-Object { $recPids -notcontains $_ })
        foreach ($u in $unrec) { $pp = Get-Process -Id $u -ErrorAction SilentlyContinue; if ($pp -and $pp.ProcessName -ne 'conhost') { $problems.Add("an unrecorded job member that is not a console host: $($pp.ProcessName)") } }
        $notes.Add('console hosts tolerated in the job: ' + $unrec.Count)

        # 1. an unexpected exit of each role is reported with the role and the exit code
        foreach ($role in @('api', 'pdp', 'pep', 'agent')) {
            Stop-RigProcess $rig $role
            $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
            if (-not $m -or $m -notmatch 'RUN STATE VIOLATION' -or $m -notmatch ("the '" + $role + "' process") -or $m -notmatch 'exited unexpectedly') { $problems.Add("an unexpected exit of $role was not reported properly: $m") }
            if ($m -and $m -notmatch 'exit code -?\d+ \(0x') { $problems.Add("the exit code is missing in the report for $role") }
            [void](Start-RigSleeper $rig $role)
            $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
            if ($m) { $problems.Add("after replacing $role the monitor still reports: $m") }
        }

        # 2. a planned exit of the agent at T13: allowed down, restarted, closed; a later exit is a violation again
        Enter-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'agent' 'T13'
        Stop-RigProcess $rig 'agent'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { $problems.Add("an exit inside the open agent window was reported: $m") }
        [void](Start-RigSleeper $rig 'agent')
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { $problems.Add("the restarted agent inside the window was reported: $m") }
        $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'agent' 'T13' $null }
        if ($m) { $problems.Add("closing the agent window after a restart failed: $m") }
        if ([string]$rig.Expect['agent'] -ne 'ALIVE' -or [string]$rig.Expect['_window'] -ne '') { $problems.Add('the expectation table was not restored after the window') }
        Stop-RigProcess $rig 'agent'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch "the 'agent' process") { $problems.Add('an agent exit after the window was closed was not reported') }
        [void](Start-RigSleeper $rig 'agent')

        # 3. windows that are not allowed are refused and change nothing
        $refused = 0
        foreach ($case in @(@('agent', 'P1'), @('agent', 'P2'), @('pep', 'T13'), @('api', 'T13'), @('api', 'P1'), @('pdp', 'P1'), @('pdp', 'T13'), @('agent', 'T13 '), @('agent', 't13'), @('pep', 'p1'), @('pep', ''), @('router', 'P1'))) {
            $c0 = $case[0]; $c1 = $case[1]
            $m = Get-ThrownMessage { Enter-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job $c0 $c1 }
            if (-not $m -or $m -notmatch 'not permitted') { $problems.Add("a window was accepted for $c0 at '$c1'") } else { $refused++ }
            if ([string]$rig.Expect['_window'] -ne '') { $problems.Add("a refused window changed the table: $c0 at '$c1'") }
        }
        foreach ($role in @('api', 'pdp', 'pep', 'agent')) { if ([string]$rig.Expect[$role] -ne 'ALIVE') { $problems.Add("a refused window changed the state of $role") } }
        $notes.Add("$refused wrong (role, step) pairs refused")

        # 4. only one window at a time; a window is closed by the step that opened it, with the same role
        Enter-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P1'
        $m = Get-ThrownMessage { Enter-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'agent' 'T13' }
        if (-not $m -or $m -notmatch 'still open') { $problems.Add('a second window was accepted while one is open') }
        if ([string]$rig.Expect['agent'] -ne 'ALIVE') { $problems.Add('the refused nested window changed the agent state') }
        foreach ($case in @(@('pep', 'P2'), @('agent', 'T13'), @('pep', 'T13'))) {
            $c0 = $case[0]; $c1 = $case[1]
            $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job $c0 $c1 $null }
            if (-not $m -or $m -notmatch 'cannot close') { $problems.Add("the window pep@P1 was closed as $c0@$c1") }
        }
        if ([string]$rig.Expect['_window'] -ne 'pep@P1') { $problems.Add('the open window was changed by refused closes') }

        # 5. the other roles stay monitored while a window is open
        Stop-RigProcess $rig 'pdp'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch "the 'pdp' process") { $problems.Add('an exit of another role inside a window was not reported') }
        [void](Start-RigSleeper $rig 'pdp')

        # 6. closing a window without a restart is refused (the run-state check after the close fails)
        Stop-RigProcess $rig 'pep'
        $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P1' ([pscustomobject]@{ Exited = $true; ExitCode = 99 }) }
        if (-not $m -or $m -notmatch "the 'pep' process") { $problems.Add('closing the PEP window without a restart was accepted') }
        [void](Start-RigSleeper $rig 'pep')
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { $problems.Add("the rig is not clean after the repair: $m") }

        # 7. PEP exit codes: only the planned one (99) is accepted; a window around a PEP that did not exit closes fine
        Enter-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P2'
        Stop-RigProcess $rig 'pep'
        [void](Start-RigSleeper $rig 'pep')
        foreach ($code in @(1, 0, 3, -1073741819, 100)) {
            $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P2' ([pscustomobject]@{ Exited = $true; ExitCode = $code }) }
            if (-not $m -or $m -notmatch 'unexplained exit of the PEP') { $problems.Add("the PEP exit code $code was accepted") }
        }
        $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P2' ([pscustomobject]@{ Exited = $true; ExitCode = $null }) }
        if (-not $m -or $m -notmatch 'unexplained exit') { $problems.Add('a PEP exit without a known exit code was accepted') }
        if ([string]$rig.Expect['_window'] -ne 'pep@P2') { $problems.Add('the window was closed by a refused exit') }
        $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P2' ([pscustomobject]@{ Exited = $true; ExitCode = 99 }) }
        if ($m) { $problems.Add("exit code 99 with a restarted PEP was refused: $m") }
        Enter-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P1'
        $m = Get-ThrownMessage { Exit-Cp3PlannedExit $rig.Expect $rig.PidFile $rig.Job 'pep' 'P1' ([pscustomobject]@{ Exited = $false; ExitCode = $null }) }
        if ($m) { $problems.Add("a window around a PEP that did not exit was refused: $m") }

        # 8. a process in the job that this run did not record
        $stray = Start-Process -FilePath $script:psExe -ArgumentList (ConvertTo-ArgString $script:sleepArgs) -WindowStyle Hidden -PassThru
        $rig.Extra.Add($stray)
        Add-Cp3JobProcess $rig.Job $stray
        Start-Sleep -Milliseconds 300
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch 'unexpected process in the Job Object' -or $m -notmatch ('pid ' + $stray.Id + ' ')) { $problems.Add("an unrecorded job member was not reported: $m") }
        $stray.Kill()
        [void]$stray.WaitForExit(5000)
        $deadline = (Get-Date).AddSeconds(8)
        $m = 'x'
        while ((Get-Date) -lt $deadline) { $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }; if (-not $m) { break }; Start-Sleep -Milliseconds 250 }
        if ($m) { $problems.Add("the monitor still reports after the stray process ended: $m") }

        # 9. a recorded, running process that is not in the job (and an older process of the same role that is still running)
        $outside = Start-Process -FilePath $script:psExe -ArgumentList (ConvertTo-ArgString $script:sleepArgs) -WindowStyle Hidden -PassThru
        $rig.Extra.Add($outside)
        $img = Get-Cp3ImagePath $outside
        Add-Cp3PidRecord $rig.PidFile ([pscustomobject]@{ Role = 'agent'; Pid = [int]$outside.Id; StartUtcTicks = [long]$outside.StartTime.ToUniversalTime().Ticks; ImagePath = $img; StdOut = 'x'; StdErr = 'x' })
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch 'is running but is not in the Job Object') { $problems.Add("a recorded process outside the job was not reported: $m") }
        if (-not $m -or $m -notmatch "an older 'agent' process") { $problems.Add('the older agent process of the same role was not reported') }

        if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
        return ('exits of api/pdp/pep/agent reported with the exit code; agent window only at T13 and PEP windows only at P1/P2; 12 wrong (role, step) pairs refused; nested window, wrong closer, close without restart and every PEP exit code except 99 refused; other roles stay monitored inside a window; an unrecorded job member, a recorded process outside the job and a second live process of a role are reported; ' + ($notes -join '; '))
    } finally { Remove-SleeperRig $rig }
}

Run-Check 'H16b' 'Run-state monitor: expectation table rules, watchdog, live-database tripwire, conhost rule, quick socket classifier (harmless sleepers)' {
    $problems = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $rig = New-SleeperRig 'mon2' @('api', 'pdp', 'pep')
    try {
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { return "FAIL: the rig without an agent was reported: $m" }
        # an ALIVE role without a record, a NOT_STARTED role with a record, a role started twice
        $rig.Expect['agent'] = 'ALIVE'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch "'agent' is expected to be started but no process is recorded") { $problems.Add("ALIVE without a record: $m") }
        $rig.Expect['agent'] = 'NOT_STARTED'
        [void](Start-RigSleeper $rig 'agent')
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch "'agent' has a recorded process although it was not supposed to be started yet") { $problems.Add("NOT_STARTED with a record: $m") }
        Set-Cp3RoleStarted $rig.Expect 'agent'
        $m = Get-ThrownMessage { Set-Cp3RoleStarted $rig.Expect 'agent' }
        if (-not $m -or $m -notmatch 'second time') { $problems.Add('a role could be marked as started twice') }
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { $problems.Add("the rig is not clean after the agent was marked as started: $m") }
        # a second live process of one role: the older one must not still run
        $second = Start-RigSleeper $rig 'agent'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch "an older 'agent' process \(pid \d+\) is still running") { $problems.Add("an older live process of the role was not reported: $m") }

        # watchdog: replaced and restarted by Set-Cp3WatchdogLimit
        Set-Cp3WatchdogLimit $rig.Mon 1
        Start-Sleep -Milliseconds 1300
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch 'WATCHDOG') { $problems.Add("the watchdog did not fire: $m") }
        Set-Cp3WatchdogLimit $rig.Mon 600

        # (test-only) take the agent out of the picture, so that the tripwire is the only thing the next ticks can report
        foreach ($r in @(Read-Cp3PidFile $rig.PidFile | Where-Object { $_.Role -eq 'agent' })) { [void](Stop-Cp3Recorded $r) }
        $rig.Expect['agent'] = 'PLANNED_DOWN'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { $problems.Add("the rig is not clean before the tripwire test: $m") }
        # live-database tripwire: size change, then a modification-time change only
        $fs = [System.IO.File]::Open($rig.Db[0], 'Append'); $fs.WriteByte(1); $fs.Close()
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch 'LIVE DATABASE TRIPWIRE') { $problems.Add("a size change of a database file was not reported: $m") }
        $rig.Mon.LiveStamps = Get-Cp3FileStamps $rig.Db
        (Get-Item -LiteralPath $rig.Db[1]).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddMinutes(-9)
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if (-not $m -or $m -notmatch 'LIVE DATABASE TRIPWIRE') { $problems.Add("a modification-time change of a database file was not reported: $m") }
        $rig.Mon.LiveStamps = Get-Cp3FileStamps $rig.Db

        # the console-host rule applies to the system conhost.exe with a recorded parent and to nothing else
        $cand = $null
        foreach ($pc in @(Get-Process -Name conhost -ErrorAction SilentlyContinue)) {
            if (@(Get-Cp3JobPids $rig.Job) -contains $pc.Id) { continue }
            try { $null = $pc.StartTime; $null = $pc.MainModule.FileName; $cand = $pc; break } catch { }
        }
        if ($null -ne $cand) {
            $why = Get-Cp3UnrecordedMemberProblem ([int]$cand.Id) @()
            if (-not $why -or $why -notmatch 'is not a recorded process') { $problems.Add("a conhost with an unrecorded parent was tolerated: '$why'") }
        } else { $notes.Add('no readable conhost.exe outside the rig: the unrecorded-parent case was NOT RUN') }
        $why = Get-Cp3UnrecordedMemberProblem $PID @()
        if (-not $why -or $why -notmatch 'not started and recorded') { $problems.Add("an ordinary process was tolerated as a job member: '$why'") }

        # quick socket classifier on synthetic records
        $synL = @([pscustomobject]@{ Address = '127.0.0.1'; Port = 15000 }, [pscustomobject]@{ Address = '0.0.0.0'; Port = 18443 }, [pscustomobject]@{ Address = '::'; Port = 19000 }, [pscustomobject]@{ Address = '0.0.0.0'; Port = 445 })
        $synC = @(
            [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 15000; RemoteAddress = '127.0.0.1'; RemotePort = 50001 },
            [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 18443; RemoteAddress = '10.1.2.3'; RemotePort = 50002 },
            [pscustomobject]@{ LocalAddress = '192.168.1.5'; LocalPort = 19000; RemoteAddress = '127.0.0.1'; RemotePort = 50003 },
            [pscustomobject]@{ LocalAddress = '192.168.1.5'; LocalPort = 50004; RemoteAddress = '8.8.8.8'; RemotePort = 15000 })
        $qf = @(Get-Cp3QuickSocketFindings -Listeners $synL -Connections $synC -Ports @(15000, 18443, 19000))
        if ($qf.Count -ne 4) { $problems.Add("the quick classifier produced $($qf.Count) findings for 2 bad listeners and 2 bad connections: " + ($qf -join ' | ')) }
        if (@(Get-Cp3QuickSocketFindings -Listeners @($synL[0]) -Connections @($synC[0]) -Ports @(15000)).Count -ne 0) { $problems.Add('the quick classifier flagged a clean loopback listener and connection') }

        # the request guard: a tick every time, a full audit when due and in any case before every 10th request (the rule of the first version)
        $rig.Mon.AuditEverySec = 100000
        $rig.Mon.LastAudit = [System.Diagnostics.Stopwatch]::StartNew()
        $aud0 = $rig.Mon.Audits
        $tick0 = $rig.Mon.Ticks
        $rq0 = $rig.Mon.Requests
        for ($k = 0; $k -lt 25; $k++) { Invoke-Cp3MonitorGuard $rig.Mon }
        if ($rig.Mon.Requests - $rq0 -ne 25) { $problems.Add('the guard did not count its 25 calls') }
        if ($rig.Mon.Ticks - $tick0 -lt 25) { $problems.Add('the guard did not tick on every call') }
        if ($rig.Mon.Audits - $aud0 -ne 2) { $problems.Add('the guard ran ' + ($rig.Mon.Audits - $aud0) + ' full audits in 25 calls although none was due by time; expected 2 (before requests 10 and 20)') }
        $rig.Mon.AuditEverySec = 5

        # coverage check on synthetic records: an ALIVE server role must be SEEN listening on 127.0.0.1:<port> with the pid of its newest record
        $exp = New-Cp3Expect
        $exp['api'] = 'ALIVE'; $exp['pdp'] = 'ALIVE'; $exp['pep'] = 'PLANNED_DOWN'
        $recs = @([pscustomobject]@{ Role = 'api'; Pid = 100 }, [pscustomobject]@{ Role = 'pdp'; Pid = 101 }, [pscustomobject]@{ Role = 'pep'; Pid = 102 })
        $lst = @([pscustomobject]@{ Pid = 100; Address = '127.0.0.1'; Port = 19000 }, [pscustomobject]@{ Pid = 999; Address = '127.0.0.1'; Port = 18443 })
        $cov = @(Get-Cp3ListenerCoverageProblems -Listeners $lst -Records $recs -Expect $exp -ExpectedListeners @{ api = 19000; pdp = 18443; pep = 15000 })
        if ($cov.Count -ne 1 -or $cov[0] -notmatch "'pdp'") { $problems.Add('the coverage check should report exactly the pdp (listener owned by another pid) and skip the planned-down pep: ' + ($cov -join ' | ')) }
        $lst2 = @([pscustomobject]@{ Pid = 100; Address = '0.0.0.0'; Port = 19000 })
        if (@(Get-Cp3ListenerCoverageProblems -Listeners $lst2 -Records $recs -Expect $exp -ExpectedListeners @{ api = 19000 }).Count -ne 1) { $problems.Add('a wildcard listener counted as coverage for 127.0.0.1') }

        if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
        return ('ALIVE without a record, NOT_STARTED with a record, a role started twice and an older live process are reported; the watchdog fires and is reset; a size change and a modification-time change of a database stand-in file are reported; the console-host rule rejects an unrecorded parent and ordinary processes; the quick classifier flags 2 bad listeners and 2 bad connections and nothing else; the listener-coverage check reports a missing / foreign / wildcard listener. ' + ($notes -join '; '))
    } finally { Remove-SleeperRig $rig }
}

# ================================================================ H17 wait hook (C2)
Run-Check 'H17' 'Wait hook: runs at the start of every slice of at most one second, an exception stops the wait, a slow hook does not stretch it' {
    $problems = New-Object System.Collections.Generic.List[string]
    $script:hookCalls = 0
    $script:Cp3Virtual = $true
    $script:Cp3VirtualNow = 1000.0
    try {
        Set-Cp3WaitHook { $script:hookCalls++ }
        Wait-Cp3Seconds 5.5
        if ([Math]::Abs(($script:Cp3VirtualNow - 1000.0) - 5.5) -gt 0.000001) { $problems.Add('virtual clock: a wait of 5.5 s advanced the clock by ' + ($script:Cp3VirtualNow - 1000.0)) }
        if ($script:hookCalls -ne 6) { $problems.Add("virtual clock: the hook ran $($script:hookCalls) times in a 5.5 s wait, expected 6") }
        $script:hookCalls = 0; Wait-Cp3Seconds 0.4
        if ($script:hookCalls -ne 1) { $problems.Add("virtual clock: the hook ran $($script:hookCalls) times in a 0.4 s wait, expected 1") }
        $script:hookCalls = 0; Wait-Cp3Seconds 3.0
        if ($script:hookCalls -ne 3) { $problems.Add("virtual clock: the hook ran $($script:hookCalls) times in a 3 s wait, expected 3") }
        $script:hookCalls = 0; Wait-Cp3Seconds 0
        if ($script:hookCalls -ne 0) { $problems.Add('virtual clock: a zero wait ran the hook') }
        $script:hookCalls = 0
        Set-Cp3WaitHook { $script:hookCalls++; if ($script:hookCalls -eq 3) { throw 'HOOK-STOP' } }
        $before = $script:Cp3VirtualNow
        $m = Get-ThrownMessage { Wait-Cp3Seconds 10 }
        if ($m -ne 'HOOK-STOP') { $problems.Add("an exception thrown by the hook did not reach the caller (got '$m')") }
        if (($script:Cp3VirtualNow - $before) -gt 2.000001) { $problems.Add('the wait went on after the hook threw: advanced ' + ($script:Cp3VirtualNow - $before)) }
    } finally { Clear-Cp3WaitHook; $script:Cp3Virtual = $false }
    # real clock
    $script:hookCalls = 0
    Set-Cp3WaitHook { $script:hookCalls++ }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Wait-Cp3Seconds 2.3
    $el = $sw.Elapsed.TotalSeconds
    Clear-Cp3WaitHook
    if ($el -lt 2.25 -or $el -gt 3.2) { $problems.Add("real clock: a 2.3 s wait took $([Math]::Round($el, 2)) s") }
    if ($script:hookCalls -lt 3 -or $script:hookCalls -gt 4) { $problems.Add("real clock: the hook ran $($script:hookCalls) times in a 2.3 s wait, expected 3") }
    Set-Cp3WaitHook { Start-Sleep -Milliseconds 400 }
    $sw.Restart()
    Wait-Cp3Seconds 1.0
    $el2 = $sw.Elapsed.TotalSeconds
    Clear-Cp3WaitHook
    if ($el2 -lt 0.95 -or $el2 -gt 1.6) { $problems.Add("real clock: a hook that takes 0.4 s stretched a 1.0 s wait to $([Math]::Round($el2, 2)) s") }
    $sw.Restart()
    Wait-Cp3Seconds 0.5
    if ($sw.Elapsed.TotalSeconds -lt 0.45) { $problems.Add('real clock: a wait without a hook was too short') }
    if ($null -ne $script:Cp3WaitHook) { $problems.Add('the hook was not cleared') }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return ('virtual clock: 5.5 s -> 6 hook calls and exactly 5.5 s, 0.4 s -> 1, 3 s -> 3, 0 s -> 0, an exception from the hook ends the wait and reaches the caller; real clock: 2.3 s took ' + [Math]::Round($el, 2) + ' s with ' + $script:hookCalls + ' hook calls, a 0.4 s hook inside a 1.0 s wait gave ' + [Math]::Round($el2, 2) + ' s')
}

# ================================================================ H18 audit data path on this machine (C3)
Run-Check 'H18' 'Audit data path (C3) against this machine''s real TCP table, without opening a socket of ours' {
    $problems = New-Object System.Collections.Generic.List[string]
    $snap = Read-Cp3TcpSnapshot @()
    if ($snap.Rows -lt 1 -or @($snap.Listeners).Count -lt 1) { return 'FAIL: the TCP snapshot is empty' }
    foreach ($l in $snap.Listeners) { if ($l.Pid -isnot [int] -or $l.Port -isnot [int] -or $l.Address -isnot [string]) { return 'FAIL: listener fields have the wrong types' } }
    # two independent views of the same table: Get-NetTCPConnection (CIM) and .NET IPGlobalProperties. A dual-stack listener appears as :: in the first and also as 0.0.0.0 in the second.
    $agree = $false
    $detail = ''
    for ($try = 0; $try -lt 4 -and -not $agree; $try++) {
        $snap = Read-Cp3TcpSnapshot @()
        $netL = @([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners())
        $netPorts = @($netL | ForEach-Object { [int]$_.Port } | Sort-Object -Unique)
        $cimPorts = @($snap.Listeners | ForEach-Object { [int]$_.Port } | Sort-Object -Unique)
        $netLoop = @($netL | Where-Object { $_.Address.ToString() -eq '127.0.0.1' } | ForEach-Object { [int]$_.Port } | Sort-Object -Unique)
        $cimLoop = @($snap.Listeners | Where-Object { $_.Address -eq '127.0.0.1' } | ForEach-Object { [int]$_.Port } | Sort-Object -Unique)
        $d1 = @(Compare-Object $netPorts $cimPorts)
        $d2 = @(Compare-Object $netLoop $cimLoop)
        $detail = "ports only in one view: $($d1.Count); 127.0.0.1 ports only in one view: $($d2.Count)"
        if ($d1.Count -eq 0 -and $d2.Count -eq 0) { $agree = $true } else { Start-Sleep -Milliseconds 500 }
    }
    if (-not $agree) { $problems.Add("the two views of the listener table disagree ($detail)") }
    # real positive control: a listener of some other process that is not on 127.0.0.1 is a violation for the classifier
    $wild = @($snap.Listeners | Where-Object { $_.Address -ne '127.0.0.1' -and $_.Pid -gt 0 } | Select-Object -First 1)
    $posNote = 'no non-loopback listener on this machine: the real-data listener positive control was NOT RUN'
    if ($wild.Count -gt 0) {
        $f = Get-Cp3AuditFindings -Listeners $snap.Listeners -Connections @() -Pids @([int]$wild[0].Pid) -ExpectedPorts @()
        if (@($f.Violations).Count -lt 1) { $problems.Add('a real non-loopback listener of another process was not classified as a violation') }
        $qp = @(Get-Cp3QuickSocketProblems @([int]$wild[0].Port))
        if ($qp.Count -lt 1) { $problems.Add('the quick check did not see the real non-loopback listener on port ' + $wild[0].Port) }
        $posNote = 'a real non-loopback listener of another process is a violation for both the pid-attributed classifier and the quick check'
    }
    # negative control for the quick check: a port nobody uses
    $used = @($netPorts)
    $free = 0
    foreach ($cand in 61000..61100) { if ($used -notcontains $cand) { $free = $cand; break } }
    if ($free -eq 0 -or @(Get-Cp3QuickSocketProblems @($free)).Count -ne 0) { $problems.Add('the quick check reported something on an unused port') }
    # real connections: a remote connection of another process is a violation for the connection classifier
    $connNote = ''
    $all = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' -and $_.OwningProcess -gt 0 } | Select-Object -First 1)
    if ($all.Count -gt 0) {
        $pidX = [int]$all[0].OwningProcess
        $s2 = Read-Cp3TcpSnapshot @($pidX)
        if (@($s2.Connections).Count -lt 1) { $problems.Add('the snapshot lost the connections of a chosen pid') }
        $f2 = Get-Cp3AuditFindings -Listeners @() -Connections $s2.Connections -Pids @($pidX) -ExpectedPorts @()
        if (@($f2.Violations | Where-Object { $_ -match 'connection to' }).Count -lt 1) { $problems.Add('a real remote connection of another process was not classified as a violation') }
        $connNote = 'a real remote connection of another process is a violation for the connection classifier'
    } else { $connNote = 'no remote connection on this machine: the real-data connection positive control was NOT RUN' }
    # fail-closed behaviour of the snapshot cannot be provoked without breaking the machine; the code path is: an exception from the cmdlet or an empty table throws
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return ('snapshot of ' + $snap.Rows + ' TCP rows (' + @($snap.Listeners).Count + ' listeners); CIM and .NET views agree on the listening ports and on the 127.0.0.1 listeners; ' + $posNote + '; ' + $connNote + '; the quick check is silent on an unused port')
}

# ================================================================ H19 sensitive-data scan (C5)
Run-Check 'H19' 'Sensitive-data scan: right category and location, nothing exposed in the report, placeholders and manifests not flagged' {
    $problems = New-Object System.Collections.Generic.List[string]
    $seeder = Join-Path $repo 'protected_app\src\app\seed\PatientSeeder.java'
    $mk = @(Get-Cp3PatientMarkers $seeder)
    if ($mk.Count -ne 24) { return "FAIL: $($mk.Count) patient markers, expected 24 (4 patients x 6 fields)" }
    $cats = @($mk | Group-Object Category)
    if ($cats.Count -ne 6 -or @($cats | Where-Object { $_.Count -ne 4 }).Count -gt 0) { return 'FAIL: the patient markers do not fall into 6 categories of 4' }
    # a seeder with one patient less must be refused
    $badSeed = Join-Path $fixRoot 'seeder-three.java'
    $txt = [System.IO.File]::ReadAllText($seeder, $script:Cp3Utf8)
    $firstCall = [regex]::Match($txt, 'insertPatient\(db, cipher, 101,[^\r\n]*')
    [System.IO.File]::WriteAllText($badSeed, $txt.Replace($firstCall.Value, ''), $script:Cp3Utf8)
    $m = Get-ThrownMessage { Get-Cp3PatientMarkers $badSeed }
    if (-not $m -or $m -notmatch 'expected exactly 4') { $problems.Add('a seeder with 3 patient calls was not refused') }

    $alnum = -join ((48..57 + 65..90 + 97..122) | ForEach-Object { [char]$_ })
    $name = ($mk | Where-Object { $_.Category -eq 'patient-name' } | Select-Object -First 1).Value
    $diag = ($mk | Where-Object { $_.Category -eq 'patient-diagnosis' } | Select-Object -First 1).Value
    $ssnShaped = '{0}-{1}-{2}' -f '123', '45', '6789'
    $hex = New-Cp3RandomString 64 '0123456789abcdef'
    $tokenShaped = (New-Cp3RandomString 22 $alnum) + '.' + (New-Cp3RandomString 64 '0123456789abcdef')
    $pw = New-Cp3Password
    $pw2 = New-Cp3Password
    $pin = New-Cp3Pin
    $bearerVal = 'abcdEFGH' + '1234' + 'ijklMNOPqrst'
    $fx = Join-Path $fixRoot 'scanfx'
    $ev1 = Join-Path $fx 'evidence'
    New-Item -ItemType Directory -Force -Path (Join-Path $ev1 'logs') | Out-Null
    $w = { param($rel, $lines) [System.IO.File]::WriteAllText((Join-Path $ev1 $rel), (($lines -join "`n") + "`n"), $script:Cp3Utf8) }
    & $w 'notes.txt' @('plain line', ('visit for patient ' + $name + ' today'), ('ref ' + $ssnShaped), ('diagnosis ' + $diag.ToUpperInvariant()), ('twice: ' + $name + ' and ' + $name))
    & $w 'results.json' @('{', ('"hash": "' + $hex + '",'), ('"password": "' + $pw + '",'), '"token": "<redacted>",', '"note": "clean"', '}')
    & $w 'notes2.txt' @(('Authorization: Bearer ' + $bearerVal), 'Authorization: Bearer <redacted>', 'Bearer authentication scheme is used', ('X-StepUp-Pin: ' + $pin), 'X-StepUp-Pin: <redacted>', ('token ' + $tokenShaped), ('sha256 ' + $hex))
    & $w 'logs\api.out.log' @('started', ('user logged in pw=' + $pw), ('checksum ' + $hex))
    & $w 'transcript_x.txt' @(('sig ' + $hex))
    & $w 'clean.txt' @('Bearer <redacted>', '<token>', '<ssn-shaped>', '<hex64>', 'hasToken: true', 'date 2026-10-11 and id 00000000-1111-2222-3333-444444444444', '"fieldNames": ["token","session_id","ssn","billing"]')
    [System.IO.File]::WriteAllBytes((Join-Path $ev1 'utf16.txt'), [System.Text.Encoding]::Unicode.GetBytes('secret=' + $pw2))
    $issued = @([pscustomobject]@{ Category = 'issued-password'; Value = $pw }, [pscustomobject]@{ Category = 'issued-password'; Value = $pw2 })
    $lits = @(Get-Cp3SensitiveLiterals $seeder $issued)
    $res = Find-Cp3SensitiveMatches -Targets @([pscustomobject]@{ Label = 'evidence'; Path = $ev1 }) -Literals $lits
    $got = @($res.Findings | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Category, $_.Location, $_.Line, $_.Occurrences } | Sort-Object)
    $want = @(
        'patient-name|evidence\notes.txt|2|1', 'ssn-shaped (nnn-nn-nnnn)|evidence\notes.txt|3|1', 'patient-diagnosis|evidence\notes.txt|4|1', 'patient-name|evidence\notes.txt|5|2',
        'hex64 (hash or signature shaped)|evidence\results.json|2|1', 'credential-field-value (json)|evidence\results.json|3|1', 'issued-password|evidence\results.json|3|1',
        'bearer-credential|evidence\notes2.txt|1|1', 'step-up-pin-header-value|evidence\notes2.txt|4|1', 'token-shaped (payload.signature)|evidence\notes2.txt|6|1',
        'issued-password|evidence\logs\api.out.log|2|1', 'hex64 (hash or signature shaped)|evidence\logs\api.out.log|3|1',
        'hex64 (hash or signature shaped)|evidence\transcript_x.txt|1|1', 'issued-password|evidence\utf16.txt|1|1'
    ) | Sort-Object
    $missingW = @($want | Where-Object { $got -notcontains $_ })
    $extraG = @($got | Where-Object { $want -notcontains $_ })
    if ($missingW.Count -gt 0) { $problems.Add('expected findings missing: ' + ($missingW -join ' ; ')) }
    if ($extraG.Count -gt 0) { $problems.Add('unexpected findings: ' + ($extraG -join ' ; ')) }
    if (@($res.Targets)[0].Files -ne 7) { $problems.Add('the scan covered ' + @($res.Targets)[0].Files + ' files, expected 7') }
    # the report and the problem list never contain a planted value, a patient marker or part of one
    $report = (Format-Cp3SensitiveReport $res $lits 'T') -join "`n"
    $json = ConvertTo-Json -InputObject $res -Depth 6
    $probText = (Get-Cp3SensitiveScanProblems $res) -join "`n"
    $exposed = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($name, $diag, $ssnShaped, $hex, $tokenShaped, $tokenShaped.Split('.')[0], $pw, $pw2, $pin, $bearerVal) + @($mk | ForEach-Object { $_.Value })) {
        foreach ($t in @($report, $json, $probText)) { if ($t.IndexOf([string]$s, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $exposed.Add('a value is exposed (length ' + ([string]$s).Length + ')') } }
    }
    if ($exposed.Count -gt 0) { $problems.Add(($exposed | Select-Object -Unique) -join ', ') }
    if ($report -notmatch 'MATCH  category=patient-name  location=evidence\\notes\.txt  line=2  occurrences=1') { $problems.Add('the report does not name category, location and line of a match') }
    # missing and empty targets are problems, not silence
    $emptyDir = Join-Path $fx 'empty'
    New-Item -ItemType Directory -Force -Path $emptyDir | Out-Null
    $res2 = Find-Cp3SensitiveMatches -Targets @([pscustomobject]@{ Label = 'gone'; Path = (Join-Path $fx 'no-such-folder') }, [pscustomobject]@{ Label = 'empty'; Path = $emptyDir }) -Literals $lits
    $p2 = @(Get-Cp3SensitiveScanProblems $res2)
    if (@($p2 | Where-Object { $_ -match 'target missing: gone' }).Count -ne 1 -or @($p2 | Where-Object { $_ -match 'target without files: empty' }).Count -ne 1) { $problems.Add('a missing target or an empty target was not reported: ' + ($p2 -join ' | ')) }
    # a clean folder gives no problem
    $cleanDir = Join-Path $fx 'cleanonly'
    New-Item -ItemType Directory -Force -Path $cleanDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $ev1 'clean.txt') -Destination (Join-Path $cleanDir 'clean.txt')
    $res3 = Find-Cp3SensitiveMatches -Targets @([pscustomobject]@{ Label = 'clean'; Path = $cleanDir }) -Literals $lits
    if (@(Get-Cp3SensitiveScanProblems $res3).Count -ne 0) { $problems.Add('placeholders, a date, a GUID and field names were flagged: ' + ((Get-Cp3SensitiveScanProblems $res3) -join ' | ')) }
    # which files count as result files (the 64-hex rule applies to them only)
    $classCases = @{ 'cp3_results.json' = $true; 'cp3_results.md' = $true; 'results.json' = $true; 'partial_results.json' = $true; 'CP3A_RESULTS.txt' = $false; 'harness\dryrun_baseline\x.txt' = $true; '05_transcript_redacted.txt' = $true; 'logs\api.out.log' = $true; 'phaseA_manifest.json' = $false; '04_postflight.txt' = $false; '08_tree_manifest_after_build.txt' = $false }
    foreach ($k in $classCases.Keys) { if ((Test-Cp3ResultClassPath $k) -ne $classCases[$k]) { $problems.Add("result-class decision wrong for $k") } }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return ('24 patient markers in 6 categories read from the seeder (a seeder with 3 patients is refused); 14 planted matches reported with the exact category, file, line and count and nothing else (incl. a UTF-16 file, case-insensitive markers, two occurrences on one line); report, JSON and problem list expose none of ' + ($mk.Count + 10) + ' values; placeholders, manifests, a date, a GUID and field names are not flagged; a missing or empty target is a problem')
}

# ================================================================ H20 shutdown verification and integrity helpers (C4)
Run-Check 'H20' 'Shutdown verification (C4): REFUSED is a failure, every record is shown to have exited, job leftovers and survivors, integrity comparisons that only read' {
    $problems = New-Object System.Collections.Generic.List[string]
    if (@(Get-Cp3CleanupProblems @('agent pid 5: stopped', 'pep pid 6: already-gone') @()).Count -ne 0) { $problems.Add('successful stop results were treated as problems') }
    if (@(Get-Cp3CleanupProblems @('agent pid 5: REFUSED (start time differs from the record: the pid was reused)') @()).Count -ne 1) { $problems.Add('a REFUSED stop result was not a problem') }
    if (@(Get-Cp3CleanupProblems @('agent pid 5: stopped') @('stop loop: boom')).Count -ne 1) { $problems.Add('a shutdown error was not a problem') }
    if (@(Get-Cp3CleanupProblems @('agent pid 5: something odd') @()).Count -ne 1) { $problems.Add('an unknown stop result was accepted') }
    $rig = New-SleeperRig 'shut' @('api', 'agent')
    try {
        $t0 = @(Get-Cp3RecordExitTable $rig.PidFile)
        if ($t0.Count -ne 2 -or @($t0 | Where-Object { $_.Exited }).Count -ne 0) { $problems.Add('running records were reported as exited') }
        $lo = @(Get-Cp3JobLeftovers $rig.Job $rig.PidFile)
        if (@($lo | Where-Object { $_ -match 'recorded process pid \d+ is still a member' }).Count -ne 2) { $problems.Add('the job leftovers did not list the two recorded members: ' + ($lo -join ' | ')) }
        $recApi = Get-Cp3LatestRecord $rig.PidFile 'api'
        $recAgent = Get-Cp3LatestRecord $rig.PidFile 'agent'
        # a record whose start time does not match is never stopped; for the verification it counts as "the recorded process is not there"
        $tampered = [pscustomobject]@{ Role = 'agent'; Pid = $recAgent.Pid; StartUtcTicks = ($recAgent.StartUtcTicks + 10000000); ImagePath = $recAgent.ImagePath; StdOut = ''; StdErr = '' }
        if (-not (Stop-Cp3Recorded $tampered).StartsWith('REFUSED')) { $problems.Add('a tampered record was not refused') }
        if ($null -eq (Get-Process -Id $recAgent.Pid -ErrorAction SilentlyContinue)) { $problems.Add('a tampered record stopped a process') }
        $r1 = Stop-Cp3Recorded $recApi
        if ($r1 -ne 'stopped') { $problems.Add("stopping the api record returned $r1") }
        $t1 = @(Get-Cp3RecordExitTable $rig.PidFile)
        $a = @($t1 | Where-Object { $_.Role -eq 'api' })[0]
        $b = @($t1 | Where-Object { $_.Role -eq 'agent' })[0]
        if (-not $a.Exited -or $a.ExitCode -isnot [int]) { $problems.Add('a stopped record was not shown as exited with an integer exit code') }
        if ($b.Exited) { $problems.Add('a running record was shown as exited') }
        $r2 = Stop-Cp3Recorded $recAgent
        if ($r2 -ne 'stopped') { $problems.Add("stopping the agent record returned $r2") }
        if (@(Get-Cp3RecordExitTable $rig.PidFile | Where-Object { -not $_.Exited }).Count -ne 0) { $problems.Add('after stopping both records one is still shown as running') }
        $deadline = (Get-Date).AddSeconds(8)
        $lo2 = @('x')
        while ((Get-Date) -lt $deadline) { $lo2 = @(Get-Cp3JobLeftovers $rig.Job $rig.PidFile); if ($lo2.Count -eq 0) { break }; Start-Sleep -Milliseconds 300 }
        if ($lo2.Count -ne 0) { $problems.Add('job leftovers remain after both processes were stopped: ' + ($lo2 -join ' | ')) }
        # survivors of a snapshot: one process is left running in the job, the snapshot lists it, closing the job removes it
        $third = Start-RigSleeper $rig 'agent'
        $snapJ = @(Get-Cp3JobSnapshot $rig.Job)
        if (@($snapJ | Where-Object { $_.Pid -eq $third.Pid }).Count -ne 1) { $problems.Add('the job snapshot misses a member') }
        if (@(Get-Cp3SnapshotSurvivors $snapJ).Count -lt 1) { $problems.Add('a running former member was not listed as a survivor before the job was closed') }
        Close-Cp3Job $rig.Job
        $deadline = (Get-Date).AddSeconds(8)
        $sv = @('x')
        while ((Get-Date) -lt $deadline) { $sv = @(Get-Cp3SnapshotSurvivors $snapJ); if ($sv.Count -eq 0) { break }; Start-Sleep -Milliseconds 300 }
        if ($sv.Count -ne 0) { $problems.Add('former members survived the closing of the job: ' + ($sv -join ' | ')) }
        $rig.Job = [IntPtr]::Zero
    } finally { try { Remove-SleeperRig $rig } catch { } }
    # integrity helpers: read-only, they report and never repair
    $ifx = Join-Path $fixRoot 'intfx'
    New-Item -ItemType Directory -Force -Path (Join-Path $ifx 'sub') | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $ifx 'a.txt'), 'alpha', $script:Cp3Utf8)
    [System.IO.File]::WriteAllText((Join-Path $ifx 'b.txt'), 'beta', $script:Cp3Utf8)
    [System.IO.File]::WriteAllText((Join-Path $ifx 'sub\c.txt'), 'gamma', $script:Cp3Utf8)
    $man = @{}
    foreach ($rel in @('a.txt', 'b.txt', 'sub/c.txt')) { $man[$rel] = [pscustomobject]@{ Hash = (Get-Sha256Hex (Join-Path $ifx ($rel -replace '/', '\'))); Size = 1 } }
    if (@(Get-Cp3ManifestMismatches $ifx $man).Count -ne 0) { $problems.Add('an unchanged folder was reported') }
    $linesBefore = @(Get-Cp3TreeManifest $ifx | ForEach-Object { $_.Hash + ' ' + $_.Path })
    [System.IO.File]::WriteAllText((Join-Path $ifx 'b.txt'), 'beta!', $script:Cp3Utf8)
    Remove-Item -LiteralPath (Join-Path $ifx 'sub\c.txt')
    [System.IO.File]::WriteAllText((Join-Path $ifx 'new.txt'), 'extra', $script:Cp3Utf8)
    $mm = @(Get-Cp3ManifestMismatches $ifx $man)
    if ($mm.Count -ne 2 -or @($mm | Where-Object { $_ -eq 'differs: b.txt' }).Count -ne 1 -or @($mm | Where-Object { $_ -eq 'missing: sub/c.txt' }).Count -ne 1) { $problems.Add('changed / missing files were not reported exactly: ' + ($mm -join ' | ')) }
    $linesAfter = @(Get-Cp3TreeManifest $ifx | ForEach-Object { $_.Hash + ' ' + $_.Path })
    $cmp = @(Compare-Cp3Lines $linesBefore $linesAfter)
    if (@($cmp | Where-Object { $_ -like 'only before: *' }).Count -ne 2 -or @($cmp | Where-Object { $_ -like 'only after : *' }).Count -ne 2) { $problems.Add('the line comparison did not find 2 lines only before and 2 only after: ' + ($cmp -join ' | ')) }
    $h1 = Get-Sha256Hex (Join-Path $ifx 'b.txt'); $h2 = Get-Sha256Hex (Join-Path $ifx 'new.txt')
    [void](Get-Cp3ManifestMismatches $ifx $man); [void](Compare-Cp3Lines $linesBefore $linesAfter)
    if ((Get-Sha256Hex (Join-Path $ifx 'b.txt')) -ne $h1 -or (Get-Sha256Hex (Join-Path $ifx 'new.txt')) -ne $h2 -or (Test-Path -LiteralPath (Join-Path $ifx 'sub\c.txt'))) { $problems.Add('an integrity helper modified, restored or deleted a file') }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return 'stop results: only stopped / already-gone count, REFUSED, unknown results and shutdown errors are problems; the exit table shows running records as running and stopped ones as exited with an integer exit code; a tampered record is refused and never stops a process; job leftovers and survivors are listed and disappear; the manifest and line comparisons report a changed, a missing and an added file exactly and leave every file as it was'
}

# ================================================================ H24 completeness rule of the orchestrator's harness step
Run-Check 'H24' 'Harness completeness rule (step A6): every expected check needs a PASS line; a missing, extra, duplicate, failed or subset result is refused' {
    $problems = New-Object System.Collections.Generic.List[string]
    $ids = @('H0', 'H1', 'H1b', 'H2')
    $line = { param($s, $id) ($s + '     ' + $id + '   some name  some detail') }
    $good = ($ids | ForEach-Object { & $line 'PASS' $_ }) -join "`r`n"
    if (@(Get-Cp3HarnessCompletenessProblems $good $ids).Count -ne 0) { $problems.Add('a complete output was refused') }
    $oneMissing = (@('H0', 'H1', 'H2') | ForEach-Object { & $line 'PASS' $_ }) -join "`n"
    if (@(Get-Cp3HarnessCompletenessProblems $oneMissing $ids).Count -ne 1) { $problems.Add('a missing check was not refused') }
    $failed = ((@('H0', 'H1', 'H2') | ForEach-Object { & $line 'PASS' $_ }) + @(& $line 'FAIL' 'H1b')) -join "`n"
    if (@(Get-Cp3HarnessCompletenessProblems $failed $ids).Count -ne 1) { $problems.Add('a failed check was counted as passed') }
    $notRun = ((@('H0', 'H1', 'H2') | ForEach-Object { & $line 'PASS' $_ }) + @(& $line 'NOT RUN' 'H1b')) -join "`n"
    if (@(Get-Cp3HarnessCompletenessProblems $notRun $ids).Count -ne 1) { $problems.Add('a check that did not run was counted as passed') }
    $extra = (($ids + @('H99')) | ForEach-Object { & $line 'PASS' $_ }) -join "`n"
    if (@(Get-Cp3HarnessCompletenessProblems $extra $ids).Count -ne 1) { $problems.Add('an unexpected extra check was accepted') }
    $dup = (($ids + @('H1')) | ForEach-Object { & $line 'PASS' $_ }) -join "`n"
    if (@(Get-Cp3HarnessCompletenessProblems $dup $ids).Count -ne 1) { $problems.Add('a duplicated check was accepted') }
    $subset = $good + "`nSUBSET RESULT (H0,H1): PASS  - not a complete harness run"
    if (@(Get-Cp3HarnessCompletenessProblems $subset $ids).Count -ne 1) { $problems.Add('a subset run was accepted') }
    # the word "subset" inside the description of a check (as in this very check) is not a subset run
    $wordInside = ($ids | ForEach-Object { & $line 'PASS' $_ }) -join "`n"
    $wordInside = $wordInside.Replace('some detail', 'a refused subset result and a SUBSET word in the middle of a line')
    if (@(Get-Cp3HarnessCompletenessProblems $wordInside $ids).Count -ne 0) { $problems.Add('the word subset inside a check description was taken for a subset run') }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return 'complete output accepted; missing, failed, not-run, extra, duplicated and subset results are each refused with exactly one problem; the word in a description is not a subset run'
}

# ================================================================ H21 controls glue (C1, C2, C3) with harmless sleepers
Run-Check 'H21' 'Controls used by the scenario engine: stop agent / restart / planned windows / audits after each restart / final check (harmless sleepers)' {
    $problems = New-Object System.Collections.Generic.List[string]
    $rig = New-SleeperRig 'ctl'
    try {
        $startAgent = { [void](Start-RigSleeper $rig 'agent'); return $true }.GetNewClosure()
        $startPep = { [void](Start-RigSleeper $rig 'pep'); return $true }.GetNewClosure()
        $c = New-Cp3Controls -Mon $rig.Mon -StartAgent $startAgent -StartPep $startPep
        foreach ($k in @('StopAgent', 'StartAgentAndWait', 'PepExitInfo', 'RestartPep', 'PortsListening', 'BeginPlannedExit', 'EndPlannedExit')) { if (-not $c.ContainsKey($k)) { return "FAIL: the control '$k' is missing" } }
        # T13 order: begin, stop, (monitor ticks), restart + audit, end
        & $c.BeginPlannedExit 'agent' 'T13'
        $s = & $c.StopAgent
        if ($s -ne 'stopped') { $problems.Add("StopAgent returned $s") }
        $m = Get-ThrownMessage { Invoke-Cp3MonitorTick $rig.Mon }
        if ($m) { $problems.Add("the monitor objected inside the agent window: $m") }
        $a0 = $rig.Mon.Audits
        $ok = & $c.StartAgentAndWait
        if ($ok -ne $true) { $problems.Add('StartAgentAndWait did not return the starter result') }
        if ($rig.Mon.Audits -ne $a0 + 1 -or $rig.Mon.StageAudits[$rig.Mon.StageAudits.Count - 1] -ne 'after the agent restarted: clean') { $problems.Add('no clean full audit followed the agent restart: ' + ($rig.Mon.StageAudits -join ' / ')) }
        $m = Get-ThrownMessage { & $c.EndPlannedExit 'agent' 'T13' $null }
        if ($m) { $problems.Add("closing the agent window failed: $m") }
        # P1 order: begin, crash, exit info, restart + audit, end with the exit info
        & $c.BeginPlannedExit 'pep' 'P1'
        Stop-RigProcess $rig 'pep'
        $e1 = & $c.PepExitInfo
        if (-not $e1.Exited -or $e1.ExitCode -isnot [int]) { $problems.Add('PepExitInfo did not report the crash with an integer exit code') }
        $a1 = $rig.Mon.Audits
        $ok2 = & $c.RestartPep
        if ($ok2 -ne $true -or $rig.Mon.Audits -ne $a1 + 1 -or $rig.Mon.StageAudits[$rig.Mon.StageAudits.Count - 1] -ne 'after the PEP restarted: clean') { $problems.Add('no clean full audit followed the PEP restart') }
        # the real exit info of a process killed from outside carries code 1, which is not the planned 99: the run must stop
        $m = Get-ThrownMessage { & $c.EndPlannedExit 'pep' 'P1' $e1 }
        if (-not $m -or $m -notmatch 'unexplained exit of the PEP') { $problems.Add("an unplanned PEP exit code was accepted: $m") }
        # the same window closes with the planned code
        $m = Get-ThrownMessage { & $c.EndPlannedExit 'pep' 'P1' ([pscustomobject]@{ Exited = $true; ExitCode = 99 }) }
        if ($m) { $problems.Add("closing the PEP window with exit code 99 failed: $m") }
        $ps0 = & $c.PortsListening
        if ($ps0.Api -isnot [bool] -or $ps0.Pdp -isnot [bool] -or $ps0.Pep -isnot [bool]) { $problems.Add('PortsListening is not boolean') }
        # final check: a window left open and a role not ALIVE stop the run; otherwise one more full audit
        & $c.BeginPlannedExit 'agent' 'T13'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorFinal $rig.Mon }
        if (-not $m -or $m -notmatch 'still open') { $problems.Add("the final check accepted an open window: $m") }
        & $c.EndPlannedExit 'agent' 'T13' $null
        $a2 = $rig.Mon.Audits
        $m = Get-ThrownMessage { Invoke-Cp3MonitorFinal $rig.Mon }
        if ($m) { $problems.Add("the final check failed on a clean rig: $m") }
        if ($rig.Mon.Audits -ne $a2 + 1 -or $rig.Mon.StageAudits[$rig.Mon.StageAudits.Count - 1] -ne 'before shutdown: clean') { $problems.Add('the final check did not run the audit before shutdown') }
        $rig.Expect['pdp'] = 'PLANNED_DOWN'
        $m = Get-ThrownMessage { Invoke-Cp3MonitorFinal $rig.Mon }
        if (-not $m -or $m -notmatch 'not ALIVE') { $problems.Add("the final check accepted a role that is not ALIVE: $m") }
        if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
        return ('begin / stop / restart / end in the order of T13 and P1 work through the closures; a full audit follows each restart; the real exit info of a killed process (code 1) is rejected as unexplained and 99 is accepted; the final check refuses an open window and a role that is not ALIVE and otherwise runs the audit before shutdown (' + $rig.Mon.Audits + ' full audits in this check)')
    } finally { Remove-SleeperRig $rig }
}

# ================================================================ H11 / H12 dry runs against the model (no socket, no process)
function New-DryRun([hashtable]$Mutations) {
    $script:Cp3Virtual = $true
    $script:Cp3VirtualNow = 1760000000.25
    $device = 'DEV-DRYRUN'
    $creds = @{}
    foreach ($u in @('dr_alice', 'nurse_bob', 'front_carol', 'audit_dan')) { $creds[$u] = @{ Password = (New-Cp3Password); Pin = (New-Cp3Pin) } }
    $red = New-Cp3Redactor
    $st = New-Cp3FakeStack -Creds $creds -Device $device -Mutations $Mutations
    $exp = Read-Cp3Expectations $ExpectationsPath
    $send = { param($bytes) Invoke-FakeSend $st $bytes }.GetNewClosure()
    $script:GuardCalls = 0
    $guard = { $script:GuardCalls++ }
    $ctx = New-Cp3Context -Expectations $exp -Send $send -Guard $guard -Control (New-Cp3FakeControl $st) -Device $device -Creds $creds -Redactor $red
    return [pscustomobject]@{ Ctx = $ctx; Stack = $st; Creds = $creds }
}

function Invoke-DryRun([hashtable]$Mutations) {
    # any use of the real socket function during a dry run is an error
    function Send-Cp3Raw { throw 'the real socket function was called during a dry run' }
    try {
        $d = New-DryRun $Mutations
        $script:LastDry = $d     # kept so that a check can look at what was recorded before a dry run was stopped by an exception
        Invoke-Cp3AllScenarios $d.Ctx
        return $d
    } finally {
        $script:Cp3Virtual = $false
    }
}

$script:baseline = $null
Run-Check 'H11' 'Dry run of all 30 steps against the model: every prediction holds, no socket, no leaks' {
    $d = Invoke-DryRun @{}
    $script:baseline = $d
    $sum = Get-Cp3Summary $d.Ctx
    $problems = New-Object System.Collections.Generic.List[string]
    if ($sum.Steps -ne 30) { $problems.Add("$($sum.Steps) results") }
    if ($sum.PredictionHeld -ne 30) { $problems.Add('predictions that did not hold against the model: ' + ($sum.PredictionWrong -join ',')) }
    if ($sum.BaselinePass -ne 19 -or $sum.BaselineFail -ne 8 -or $sum.Observation -ne 3) { $problems.Add("verdict counts PASS=$($sum.BaselinePass) FAIL=$($sum.BaselineFail) OBS=$($sum.Observation)") }
    if ($sum.VerdictDiffersFromPrediction.Count -gt 0) { $problems.Add('verdict differs from prediction: ' + ($sum.VerdictDiffersFromPrediction -join ',')) }
    if ($sum.Retried -ne 0) { $problems.Add('unexpected retries: ' + ($sum.Notes -join '; ')) }
    # exact invariant: every request that reached the model passed the guard first, and the guard was never skipped
    if ($script:GuardCalls -ne $d.Stack.Log.Count) { $problems.Add("the guard ran $($script:GuardCalls) times for $($d.Stack.Log.Count) requests") }
    if ($d.Stack.Log.Count -lt 40) { $problems.Add("only $($d.Stack.Log.Count) requests reached the model") }
    $onlyPep = @($d.Stack.Log | Where-Object { $_ -notmatch '^(GET|POST|OPTIONS) /' })
    if ($onlyPep.Count -ne 0) { $problems.Add('malformed request lines reached the model') }
    # write the redacted artefacts and look for planted values in them
    $dir = Join-Path $OutDir 'dryrun_baseline'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dir 'results.json'), (ConvertTo-Json -InputObject $d.Ctx.Results.ToArray() -Depth 8), $script:Cp3Utf8)
    Write-Cp3Text (Join-Path $dir 'results.md') (Format-Cp3ResultsMarkdown $d.Ctx $sum)
    Write-Cp3Text (Join-Path $dir 'transcript.txt') $d.Ctx.Transcript.ToArray()
    foreach ($v in $d.Ctx.Redactor.Values) { $script:leakCanaries.Add([string]$v.Value) }
    $script:leakCanaries.Add('987-65-4321')
    $script:leakCanaries.Add('FAKE-BILLING-7777')
    $leaks = @(Find-Cp3Leaks -Directories @($dir) -Canaries $script:leakCanaries.ToArray())
    if ($leaks.Count -gt 0) { $problems.Add('planted values found in: ' + ($leaks -join ', ')) }
    # C5: the same artefacts through the sensitive-data scan (patient markers read from the seeder, the model's credentials, tokens and session ids, credential shapes)
    $issuedDry = New-Object System.Collections.Generic.List[object]
    foreach ($rv in $d.Ctx.Redactor.Values) { $issuedDry.Add([pscustomobject]@{ Category = ('issued-' + [string]$rv.Label); Value = [string]$rv.Value }) }
    $issuedDry.Add([pscustomobject]@{ Category = 'model-ssn'; Value = '987-65-4321' })
    $issuedDry.Add([pscustomobject]@{ Category = 'model-billing'; Value = 'FAKE-BILLING-7777' })
    $litDry = @(Get-Cp3SensitiveLiterals (Join-Path $repo 'protected_app\src\app\seed\PatientSeeder.java') $issuedDry.ToArray())
    $scanDry = Find-Cp3SensitiveMatches -Targets @([pscustomobject]@{ Label = 'dry run'; Path = $dir }) -Literals $litDry
    $spDry = @(Get-Cp3SensitiveScanProblems $scanDry)
    if ($spDry.Count -gt 0) { $problems.Add('the sensitive-data scan of the dry-run artefacts found: ' + ($spDry -join ' | ')) }
    $scanNote = 'sensitive-data scan of the 3 dry-run artefacts: ' + $litDry.Count + ' literal values + 6 shape rules, ' + @($scanDry.Findings).Count + ' findings in ' + @($scanDry.Targets)[0].Files + ' files'
    # positive control: the leak scanner must see a planted value
    $ctl = Join-Path $fixRoot 'leakctl'
    New-Item -ItemType Directory -Force -Path $ctl | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $ctl 'x.txt'), ('prefix ' + $script:leakCanaries[0] + ' suffix'), $script:Cp3Utf8)
    if (@(Find-Cp3Leaks -Directories @($ctl) -Canaries @($script:leakCanaries[0])).Count -ne 1) { $problems.Add('the leak scanner missed a planted value (positive control)') }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join '; ')) }
    return ('30 results; 30 of 30 predictions hold against the model; PASS 19 / FAIL 8 / OBSERVATION 3; the guard ran before each of the ' + $script:GuardCalls + ' requests; ' + $script:leakCanaries.Count + ' planted values (passwords, PINs, tokens, session ids, an SSN-shaped value, a billing value) not found in results, report or transcript; positive control detects a planted value; ' + $scanNote)
}

Run-Check 'H12' 'Mutant models: the verdict logic notices when the system behaves differently' {
    $problems = New-Object System.Collections.Generic.List[string]
    $get = { param($d, $id) @($d.Ctx.Results.ToArray() | Where-Object { $_.Id -ceq $id })[0] }

    $d1 = Invoke-DryRun @{ protectAdmin = $true }
    foreach ($id in @('T18.1', 'T18.2', 'T18.3', 'T18.4')) {
        $r = & $get $d1 $id
        if ($r.BaselineVerdict -ne 'PASS') { $problems.Add("protectAdmin: $id verdict $($r.BaselineVerdict), expected PASS") }
        if ($r.PredictionHeld) { $problems.Add("protectAdmin: $id prediction still held") }
        if ($r.BaselineMatchesPrediction) { $problems.Add("protectAdmin: $id verdict still matches the prediction") }
    }
    $d2 = Invoke-DryRun @{ pepSurvives = $true }
    foreach ($id in @('P1', 'P2')) {
        $r = & $get $d2 $id
        if ($r.BaselineVerdict -ne 'PASS') { $problems.Add("pepSurvives: $id verdict $($r.BaselineVerdict), expected PASS") }
        if ($r.PredictionHeld) { $problems.Add("pepSurvives: $id prediction still held") }
    }
    $d3 = Invoke-DryRun @{ wrongPinAccepted = $true }
    $r = & $get $d3 'T15.2'
    if ($r.BaselineVerdict -ne 'FAIL') { $problems.Add("wrongPinAccepted: T15.2 verdict $($r.BaselineVerdict), expected FAIL") }
    if ($r.BaselineMatchesPrediction) { $problems.Add('wrongPinAccepted: T15.2 verdict still matches the prediction') }
    $d4 = Invoke-DryRun @{ slowStale = $true }
    $r = & $get $d4 'T13.2'
    if ($r.BaselineVerdict -ne 'FAIL') { $problems.Add("slowStale: T13.2 verdict $($r.BaselineVerdict), expected FAIL") }
    $d5 = Invoke-DryRun @{ behaviorBurstOnce = $true }
    $sum5 = Get-Cp3Summary $d5.Ctx
    if ($sum5.Retried -lt 1) { $problems.Add('behaviorBurstOnce: no scenario was repeated') }
    if ($sum5.Steps -ne 30) { $problems.Add("behaviorBurstOnce: $($sum5.Steps) final results") }
    if ($sum5.PredictionHeld -ne 30) { $problems.Add('behaviorBurstOnce: after the repeat the predictions should hold, wrong: ' + ($sum5.PredictionWrong -join ',')) }
    if (@($d5.Ctx.Notes.ToArray() | Where-Object { $_ -like '*repeated once*' }).Count -lt 1) { $problems.Add('behaviorBurstOnce: the repeat was not noted') }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join '; ')) }
    return 'protected admin routes -> T18.1-4 turn PASS and the prediction is reported wrong; surviving PEP -> P1/P2 PASS; wrong PIN accepted -> T15.2 FAIL; slow stale detection -> T13.2 FAIL; a behaviour burst -> the scenario is repeated once and noted'
}

# ================================================================ H22 planned exits in the engine (C1)
function Get-AstCommands($Ast, [string[]]$Names) {
    return @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and ($n.GetCommandName() -in $Names) }, $true))
}
function Get-AstFunction($Ast, [string]$Name) {
    return @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))[0]
}
function Get-ScriptAst([string]$Path) {
    $tokens = $null
    $errs = $null
    return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
}

Run-Check 'H22' 'Planned exits: the engine opens a window only for the agent at T13 and the PEP at P1/P2; windows close in order; a PEP that is not restored or exits with another code stops the run' {
    $problems = New-Object System.Collections.Generic.List[string]
    # static: where the engine asks for a planned exit, with which arguments
    $ast = Get-ScriptAst (Join-Path $PSScriptRoot 'cp3_engine.ps1')
    $hits = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Member.Value -in @('BeginPlannedExit', 'EndPlannedExit') }, $true))
    $sites = New-Object System.Collections.Generic.List[string]
    foreach ($h in $hits) {
        $fn = $h.Parent
        while ($null -ne $fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
        $argText = ''
        if ($h.Parent -is [System.Management.Automation.Language.CommandAst]) { $argText = (@($h.Parent.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text }) -join ' ') }
        $sites.Add(($fn.Name + ' ' + $h.Member.Value + ' ' + $argText))
    }
    $wantSites = @('Invoke-Cp3T13 BeginPlannedExit ''agent'' ''T13''', 'Invoke-Cp3T13 EndPlannedExit ''agent'' ''T13'' $null', 'Invoke-Cp3Probe BeginPlannedExit ''pep'' $Id', 'Invoke-Cp3Probe EndPlannedExit ''pep'' $Id $exit')
    if (($sites -join '|') -ne ($wantSites -join '|')) { $problems.Add('the engine asks for planned exits at: ' + ($sites -join ' ; ')) }
    # static: nothing but the controls factory calls the window functions (outside the harness)
    $callers = New-Object System.Collections.Generic.List[string]
    foreach ($f in (Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Where-Object { $_.Name -ne 'Test-Cp3Harness.ps1' })) {
        $a = Get-ScriptAst $f.FullName
        foreach ($c in (Get-AstCommands $a @('Enter-Cp3PlannedExit', 'Exit-Cp3PlannedExit'))) {
            $fn = $c.Parent
            while ($null -ne $fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
            $callers.Add($f.Name + ':' + $fn.Name + ':' + $c.GetCommandName())
        }
    }
    $wantCallers = @('cp3_proc.ps1:New-Cp3Controls:Enter-Cp3PlannedExit', 'cp3_proc.ps1:New-Cp3Controls:Exit-Cp3PlannedExit')
    if ((@($callers | Sort-Object) -join '|') -ne (@($wantCallers | Sort-Object) -join '|')) { $problems.Add('the window functions are called from: ' + ($callers -join ' ; ')) }
    # dry run: the exact order of the calls, no window left open, and only the requests of the scenario inside each window
    $d = Invoke-DryRun @{}
    $wantCalls = @('begin agent T13', 'end agent T13', 'begin pep P1', 'end pep P1', 'begin pep P2', 'end pep P2')
    if ((@($d.Stack.Calls) -join '|') -ne ($wantCalls -join '|')) { $problems.Add('call order in the dry run: ' + (@($d.Stack.Calls) -join ' ; ')) }
    if ($d.Stack.Window -ne '') { $problems.Add('a window was left open at the end of the dry run') }
    $allowed = @{
        'agent@T13' = @('GET /api/public/info', 'POST /token/renew', 'POST /login')
        'pep@P1' = @('POST /login', 'GET /')
        'pep@P2' = @('GET /api/public/info', 'GET /')
    }
    $perWindow = @{ 'agent@T13' = 0; 'pep@P1' = 0; 'pep@P2' = 0 }
    foreach ($r in $d.Stack.OpenWindowRequests) {
        $sp = $r.Split(' ', 2)
        if (-not $allowed.ContainsKey($sp[0]) -or $allowed[$sp[0]] -notcontains $sp[1]) { $problems.Add('a request outside the scenario was made inside a window: ' + $r) } else { $perWindow[$sp[0]]++ }
    }
    foreach ($k in $perWindow.Keys) { if ($perWindow[$k] -lt 1) { $problems.Add("no request was made inside the window $k") } }
    # a PEP that survives the probe (no exit) still closes its window
    $dS = Invoke-DryRun @{ pepSurvives = $true }
    if (@($dS.Stack.Calls).Count -ne 6 -or $dS.Stack.Window -ne '') { $problems.Add('with a surviving PEP the windows were not opened and closed in pairs') }
    # mutants: a PEP that is not restored, a PEP that exits with another code -> the run stops after the P1 result is recorded
    foreach ($mut in @(@{ name = 'pepNotRestored'; pattern = 'not running after the planned exit at P1' }, @{ name = 'pepOddExit'; pattern = 'unexplained exit of the PEP at P1' })) {
        $script:LastDry = $null
        $hm = @{}
        $hm[$mut.name] = $true
        $mname = $mut.name; $mpat = $mut.pattern
        $m = Get-ThrownMessage { Invoke-DryRun $hm }
        if (-not $m -or $m -notmatch $mpat) { $problems.Add("mutant $mname did not stop the run with '$mpat': $m") }
        $ids = @()
        if ($null -ne $script:LastDry) { $ids = @($script:LastDry.Ctx.Results.ToArray() | ForEach-Object { $_.Id }) }
        if ($ids -notcontains 'P1') { $problems.Add("mutant ${mname}: the P1 result was not recorded before the run stopped") }
        if ($ids -contains 'P2') { $problems.Add("mutant ${mname}: P2 ran after the run should have stopped") }
    }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return ('the engine requests planned exits at exactly 4 places (agent T13 begin / end, PEP probe begin / end); only New-Cp3Controls calls the window functions; dry run: calls in the order ' + ($wantCalls -join ', ') + ', no window left open, ' + ($d.Stack.OpenWindowRequests.Count) + ' requests inside windows all from the scenarios; a surviving PEP closes its window; a PEP that is not restored, or that exits with another code, stops the run right after the P1 result is recorded')
}

# ================================================================ H23 static checks of Phase B and of Phase A (C1-C5, C4)
Run-Check 'H23' 'Static checks: Phase B never deletes / moves / overwrites files and wires the monitor in; Phase A and the library cannot start a program or open a listener' {
    $problems = New-Object System.Collections.Generic.List[string]
    $ast = Get-ScriptAst (Join-Path $PSScriptRoot 'Run-Cp3.ps1')
    $fnB = Get-AstFunction $ast 'Invoke-PhaseB'
    $fnR = Get-AstFunction $ast 'Get-Cp3PostRunReport'
    $fnA = Get-AstFunction $ast 'Invoke-PhaseA'
    if ($null -eq $fnB -or $null -eq $fnR -or $null -eq $fnA) { return 'FAIL: Invoke-PhaseA, Invoke-PhaseB or Get-Cp3PostRunReport was not found' }
    # C4: no cmdlet, .NET call or redirection in Phase B / the post-run report can delete, move, copy over or overwrite a file
    $forbiddenCmd = @('Remove-Item', 'Clear-Content', 'Set-Content', 'Add-Content', 'Out-File', 'Move-Item', 'Rename-Item', 'Copy-Item', 'Remove-ItemProperty', 'Set-ItemProperty', 'del', 'erase', 'rd', 'rmdir', 'ri', 'rm', 'mv', 'move', 'ren', 'rni', 'cp', 'copy', 'cpi', 'sc', 'ac', 'clc', 'Tee-Object', 'Expand-Archive', 'Compress-Archive')
    foreach ($fn in @($fnB, $fnR)) {
        foreach ($c in (Get-AstCommands $fn $forbiddenCmd)) { $problems.Add($fn.Name + ' calls ' + $c.GetCommandName()) }
        foreach ($mx in @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Member.Value -in @('Delete', 'Move', 'Copy', 'Replace', 'Create', 'CreateText', 'SetAttributes', 'SetLastWriteTime', 'SetLastWriteTimeUtc', 'MoveTo', 'CopyTo', 'Truncate') }, $true))) { $problems.Add($fn.Name + ' calls the .NET method ' + $mx.Member.Value) }
        foreach ($rd in @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true))) { $problems.Add($fn.Name + ' uses a file redirection: ' + $rd.Extent.Text) }
    }
    # Phase B wiring
    $cnt = { param($name) @(Get-AstCommands $fnB @($name)).Count }
    if ((& $cnt 'Start-Cp3Process') -ne 5) { $problems.Add('Invoke-PhaseB starts programs at ' + (& $cnt 'Start-Cp3Process') + ' places, expected 5 (api, pdp, pep, agent starter, pep restart starter)') }
    foreach ($c in (Get-AstCommands $fnB @('Start-Cp3Process'))) { if (@($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Job' }).Count -ne 1) { $problems.Add('a Start-Cp3Process call has no -Job: ' + $c.Extent.StartLineNumber) } }
    if ((& $cnt 'Set-Cp3RoleStarted') -ne 4) { $problems.Add('Set-Cp3RoleStarted is called ' + (& $cnt 'Set-Cp3RoleStarted') + ' times, expected 4') }
    if ((& $cnt 'Set-Cp3WaitHook') -ne 1) { $problems.Add('Set-Cp3WaitHook is called ' + (& $cnt 'Set-Cp3WaitHook') + ' times, expected 1') }
    if ((& $cnt 'Clear-Cp3WaitHook') -lt 2) { $problems.Add('Clear-Cp3WaitHook is called fewer than 2 times') }
    if ((& $cnt 'Invoke-Cp3MonitorFinal') -ne 1) { $problems.Add('Invoke-Cp3MonitorFinal is not called exactly once') }
    if ((& $cnt 'Invoke-Cp3MonitorAudit') -lt 5) { $problems.Add('Invoke-Cp3MonitorAudit is called fewer than 5 times in Invoke-PhaseB') }
    if ((& $cnt 'Set-Cp3WatchdogLimit') -ne 1) { $problems.Add('Set-Cp3WatchdogLimit is not called exactly once') }
    if ((& $cnt 'Invoke-Cp3SensitiveScan') -ne 2) { $problems.Add('Invoke-PhaseB runs the sensitive-data scan at ' + (& $cnt 'Invoke-Cp3SensitiveScan') + ' places, expected 2 (results gate B8 and the early-stop path)') }
    if ((& $cnt 'Get-Cp3IssuedLiterals') -ne 2) { $problems.Add('Get-Cp3IssuedLiterals is called ' + (& $cnt 'Get-Cp3IssuedLiterals') + ' times in Invoke-PhaseB, expected 2') }
    if ((& $cnt 'Get-Cp3PostRunReport') -ne 1) { $problems.Add('Get-Cp3PostRunReport is not called exactly once') }
    foreach ($nm in @('Wait-Cp3Listener', 'Wait-Cp3LogMatch')) {
        foreach ($c in (Get-AstCommands $fnB @($nm))) { if (@($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Tick' }).Count -ne 1) { $problems.Add("a $nm call without -Tick at line " + $c.Extent.StartLineNumber) } }
    }
    $ctl = @(Get-AstCommands $fnB @('New-Cp3Controls'))
    if ($ctl.Count -ne 1) { $problems.Add('Invoke-PhaseB does not build its controls with New-Cp3Controls exactly once') }
    # Phase A (and the library) cannot start a program, send a request or wait for a listener
    foreach ($c in (Get-AstCommands $fnA @('Start-Cp3Process', 'Send-Cp3Raw', 'Wait-Cp3Listener', 'Wait-Cp3LogMatch', 'Invoke-Cp3AllScenarios', 'Invoke-Cp3MonitorAudit', 'New-Cp3Controls', 'Stop-Cp3Role', 'Start-Process'))) { $problems.Add('Invoke-PhaseA calls ' + $c.GetCommandName()) }
    # no script in this folder (the harness aside) can create a listening socket; the only socket user is Send-Cp3Raw
    $sockUsers = New-Object System.Collections.Generic.List[string]
    foreach ($f in (Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Where-Object { $_.Name -ne 'Test-Cp3Harness.ps1' })) {
        $txt = [System.IO.File]::ReadAllText($f.FullName)
        if ($txt -match '\b(TcpListener|HttpListener)\b|\.Listen\(|New-Object System\.Net\.Sockets\.Socket\b|\[System\.Net\.Sockets\.Socket\]') { $problems.Add($f.Name + ' contains a way to open a listening socket') }
        if ($txt -match 'Sockets\.TcpClient') {
            $a = Get-ScriptAst $f.FullName
            $users = @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -match 'Sockets\.TcpClient' }, $true))
            foreach ($u in $users) {
                $fn = $u.Parent
                while ($null -ne $fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                $sockUsers.Add($f.Name + ':' + $fn.Name)
            }
        }
    }
    if ((@($sockUsers | Select-Object -Unique) -join '|') -ne 'cp3_lib.ps1:Send-Cp3Raw') { $problems.Add('TcpClient is used by: ' + (@($sockUsers | Select-Object -Unique) -join ' ; ')) }
    if ($problems.Count -gt 0) { return ('FAIL: ' + ($problems -join ' | ')) }
    return 'Invoke-PhaseB and Get-Cp3PostRunReport contain no delete / move / copy / overwrite cmdlet, .NET call or redirection (they only write new evidence files, in a folder that must not exist yet); Invoke-PhaseB starts programs at exactly 5 places, all inside the Job Object, marks roles started 4 times, installs the wait hook once, passes the tick to every listener / log wait, builds its controls with New-Cp3Controls, calls the final check once, runs the sensitive-data scan at 2 places (results gate and early-stop path) and the post-run report once; Invoke-PhaseA calls none of the process, request, wait or audit functions; the only socket user in the scripts is Send-Cp3Raw and none can open a listening socket'
}

# ================================================================ summary
$overall = 'PASS'
if (@($script:checks | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { $overall = 'FAIL' }
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('CP3 harness self-checks (no listener and no legacy program were started)')
$lines.Add(('{0:yyyy-MM-dd HH:mm:ss}  work folder {1}' -f (Get-Date), $fixRoot))
if ($script:onlySet.Count -gt 0) { $lines.Add('SUBSET RUN (-Only ' + ($script:onlySet -join ',') + '): this is NOT a complete harness run') }
$lines.Add('')
foreach ($c in $script:checks) { $lines.Add(('{0,-8} {1,-4} {2}' -f $c.Status, $c.Id, $c.Name)); $lines.Add('                {0}' -f $c.Detail) }
$lines.Add('')
$lines.Add(('OVERALL: {0} ({1} pass, {2} fail, {3} not run)' -f $overall, @($script:checks | Where-Object { $_.Status -eq 'PASS' }).Count, @($script:checks | Where-Object { $_.Status -eq 'FAIL' }).Count, @($script:checks | Where-Object { $_.Status -eq 'NOT RUN' }).Count))
$lines.Add('Processes started by this script (launch log):')
foreach ($l in $script:Cp3LaunchLog) { $lines.Add('  ' + $l) }
Write-Cp3Text (Join-Path $OutDir 'harness_selfchecks.txt') $lines.ToArray()
Write-Host ''
if ($script:onlySet.Count -gt 0) { Write-Host ('SUBSET RESULT ({0}): {1}  - not a complete harness run' -f ($script:onlySet -join ','), $overall) }
else { Write-Host ('OVERALL: {0}' -f $overall) }
if ($overall -eq 'PASS') { exit 0 }
exit 1
