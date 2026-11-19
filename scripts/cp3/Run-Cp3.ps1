<#
.SYNOPSIS
  CP3 orchestrator. Phase A prepares and verifies everything WITHOUT starting any listener or legacy program.
  Phase B (separate approval, needs -ConfirmStartListeners) starts the scratch copy on 127.0.0.1 only and runs the scenarios.
.DESCRIPTION
  Phase A : preflight -> patched scratch tree from the verified backup -> build (compilers only) -> disposable database copies ->
            database fixture checks and a credential-reset self-test on a throw-away copy -> harness self-checks -> secret scan of the new
            files -> postflight. It never sets the legacy-launch switch, so it cannot start API, PDP, PEP or agent.
  Phase B : verifies the Phase A manifest, resets generated credentials in the disposable database (values in memory only), starts API, PDP,
            PEP, agent (each inside a Job Object, loopback audit after every start), runs the 30 frozen steps under a run-state monitor
            (unexpected exits, unexpected job members, planned exits only at T13 / P1 / P2, listener and connection audits, live-database
            tripwire), stops everything, verifies (every recorded process exited, cleanup succeeded, originals / project / protected set /
            live database / scratch tree unchanged), then scans evidence, results and logs for synthetic patient data and credential shapes.
            Phase B has NOT been run. Its process-starting code is exercised only by the harness with harmless sleepers and a model.
  Every gate stops the run; nothing is weakened, skipped or retried to make a gate pass.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cp3\Run-Cp3.ps1 -Phase A
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('A', 'B')][string]$Phase,
    [string]$RunDir,
    [string]$WorkRoot,
    [string]$EvidenceRoot = 'C:\Ap_project_evidence\CP3',
    [string]$ProtectedEvidenceRoot = 'C:\Ap_project_evidence',
    [string]$BackupDir = 'C:\Ap_project_backup_2026-10-11',
    [string]$OriginalManifest = 'C:\Ap_project_evidence\CP2\manifest_project_before_cp2.txt',
    [string]$RunName,
    [switch]$ConfirmStartListeners
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\cp3_lib.ps1"
. "$PSScriptRoot\cp3_proc.ps1"
. "$PSScriptRoot\cp3_engine.ps1"
$repo = Get-RepoRoot
$script:Steps = New-Object System.Collections.Generic.List[object]
$script:Skipped = New-Object System.Collections.Generic.List[string]
$script:Evidence = $null

function Say([string]$s) { Write-Host $s }
function Add-Step([string]$Id, [string]$Name, [string]$Status, [string]$Detail) {
    $script:Steps.Add([pscustomobject]@{ Id = $Id; Name = $Name; Status = $Status; Detail = $Detail })
    Write-Host ('{0,-7} {1,-5} {2}' -f $Status, $Id, $Name)
    if ($Detail) { Write-Host ('               ' + $Detail) }
}
function Stop-WithFailure([string]$Id, [string]$Name, [string]$Detail) {
    Add-Step $Id $Name 'FAIL' $Detail
    throw ('GATE FAILED: ' + $Id + ' ' + $Name + ' - ' + $Detail)
}

# ---------------------------------------------------------------- shared read-only helpers
function Get-Cp3ProjectLines {
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($m in (Get-Cp3TreeManifest $repo)) { $rows.Add(('{0} {1,12}  {2}' -f $m.Hash, $m.Size, $m.Path)) }
    return $rows.ToArray()
}

function Get-Cp3ProtectedLines {
    $rows = New-Object System.Collections.Generic.List[string]
    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add($BackupDir)
    foreach ($d in (Get-ChildItem -LiteralPath $ProtectedEvidenceRoot -Directory | Sort-Object Name)) {
        if ($d.Name -eq (Split-Path -Leaf $EvidenceRoot)) { continue }
        $roots.Add($d.FullName)
    }
    foreach ($root in $roots) {
        $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
        foreach ($f in (Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force)) {
            $rel = $f.FullName.Substring($rootFull.Length + 1).Replace('\', '/')
            $rows.Add(('{0} :: {1} {2,12}  {3}' -f $rootFull, (Get-Sha256Hex $f.FullName), $f.Length, $rel))
        }
    }
    foreach ($z in @(($BackupDir + '.zip'), ($BackupDir + '.zip.sha256'))) {
        if (Test-Path -LiteralPath $z) { $rows.Add(('{0} :: {1} {2,12}  {3}' -f (Split-Path -Parent $z), (Get-Sha256Hex $z), (Get-Item -LiteralPath $z).Length, (Split-Path -Leaf $z))) }
    }
    $arr = $rows.ToArray()
    [Array]::Sort($arr, [System.StringComparer]::Ordinal)
    return $arr
}

# (Compare-Cp3Lines and Get-Cp3ManifestMismatches live in cp3_lib.ps1, where the harness tests them on fixtures.)

function Get-Cp3LiveDbPaths { return @('db\zero_trust.db', 'db\zero_trust.db-wal', 'db\zero_trust.db-shm' | ForEach-Object { Join-Path $repo $_ }) }

function Get-Cp3Preflight([string]$Label) {
    $pfLines = New-Object System.Collections.Generic.List[string]
    $problems = New-Object System.Collections.Generic.List[string]
    $pfLines.Add(('preflight "{0}"  {1:yyyy-MM-dd HH:mm:ss}' -f $Label, (Get-Date)))
    foreach ($t in @('javac', 'java', 'g++', 'objdump')) {
        $p = Find-Tool $t
        if (-not $p) { $problems.Add("$t not found on PATH"); $pfLines.Add("  tool $t : NOT FOUND") } else { $pfLines.Add("  tool $t : $p") }
    }
    $pfLines.Add('  java.exe that starts the JVM (java.home) : ' + (Get-Cp3RealJavaExe))
    $pfLines.Add('  javac : ' + (Get-ToolVersion 'javac' @('-version')))
    $pfLines.Add('  java  : ' + (Get-ToolVersion 'java' @('-version')))
    $pfLines.Add('  g++   : ' + (Get-ToolVersion 'g++' @('--version')))
    $pfLines.Add('  PowerShell ' + $PSVersionTable.PSVersion)
    $ports = @(5000, 8443, 9000, 9443, 15000, 18443, 19000)
    $conn = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $ports -contains [int]$_.LocalPort -or $ports -contains [int]$_.RemotePort })
    if ($conn.Count -gt 0) { $problems.Add("$($conn.Count) listener(s) or connection(s) on the project and test ports"); $pfLines.Add('  ports 5000 8443 9000 9443 15000 18443 19000 : IN USE') } else { $pfLines.Add('  ports 5000 8443 9000 9443 15000 18443 19000 : nothing listening or connected') }
    $px = Invoke-Native -File (Join-Path $env:SystemRoot 'System32\netsh.exe') -Arguments @('winhttp', 'show', 'proxy') -TimeoutSec 30
    if ($px.StdOut -notmatch 'Direct access') { $problems.Add('the WinHTTP machine proxy is not "Direct access"'); $pfLines.Add('  WinHTTP proxy : NOT direct') } else { $pfLines.Add('  WinHTTP proxy : Direct access (no proxy server)') }
    $names = @('java', 'javaw', 'pep_proxy', 'agent', 'node')
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName })
    $pfLines.Add('  processes named java/javaw/pep_proxy/agent/node : ' + $(if ($procs.Count -eq 0) { 'none' } else { (($procs | ForEach-Object { $_.ProcessName + ' pid ' + $_.Id }) -join '; ') }))
    $mine = @($procs | Where-Object { try { $_.Path -and $_.Path.StartsWith($WorkRootResolved, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false } })
    if ($mine.Count -gt 0) { $problems.Add('a process from the work folder is already running'); $pfLines.Add('  a process from the work folder is running') }
    $q = 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'
    $werCount = -1
    if (Test-Path -LiteralPath $q) { $werCount = @(Get-ChildItem -LiteralPath $q -ErrorAction SilentlyContinue).Count }
    $pfLines.Add('  WER ReportQueue entries : ' + $werCount)
    try { $pfLines.Add('  firewall profiles enabled : ' + ((Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.Enabled }) -join ', ')) } catch { $pfLines.Add('  firewall query failed') }
    try { $pfLines.Add('  antivirus products listed by WMI : ' + ((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) -join ', ')) } catch { $pfLines.Add('  antivirus query failed') }
    $free = [math]::Round((Get-PSDrive -Name ($WorkRootResolved.Substring(0, 1))).Free / 1GB, 1)
    $pfLines.Add("  free space on the work drive : $free GB")
    if ($free -lt 2) { $problems.Add('less than 2 GB free on the work drive') }
    $orig = Read-Cp3Manifest $OriginalManifest
    $dbStamps = Get-Cp3FileStamps (Get-Cp3LiveDbPaths)
    foreach ($rel in @('db/zero_trust.db', 'db/zero_trust.db-wal', 'db/zero_trust.db-shm')) {
        $h = Get-Sha256Hex (Join-Path $repo ($rel -replace '/', '\'))
        $ok = ($h -eq $orig[$rel].Hash)
        $pfLines.Add(('  live {0,-24} sha256 {1}...  equals the original manifest: {2}' -f $rel, $h.Substring(0, 8), $ok))
        if (-not $ok) { $problems.Add("live database file differs from the original manifest: $rel") }
    }
    return [pscustomobject]@{ Lines = $pfLines.ToArray(); Problems = $problems.ToArray(); DbStamps = $dbStamps; WerCount = $werCount }
}

function Write-Cp3ResultsFile([string]$Path, [string]$Title) {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add($Title)
    $out.Add(('{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)))
    $out.Add('')
    foreach ($s in $script:Steps) { $out.Add(('{0,-7} {1,-5} {2}' -f $s.Status, $s.Id, $s.Name)); if ($s.Detail) { $out.Add('               ' + $s.Detail) } }
    $out.Add('')
    $out.Add('NOT RUN / SKIPPED / NOT EXERCISED:')
    foreach ($k in $script:Skipped) { $out.Add('  - ' + $k) }
    $out.Add('')
    $out.Add('Processes this run started through its own wrappers (launch log):')
    foreach ($l in $script:Cp3LaunchLog) {
        $line = $l
        if ($script:RunRootForLog) { $line = $line.Replace($script:RunRootForLog, '<run>') }
        $out.Add('  ' + $line)
    }
    Write-Cp3Text $Path $out.ToArray()
}

function Get-Cp3JavaTool([string[]]$Cp, [string]$MainClass, [string[]]$MainArgs, [string]$StdIn, [string[]]$Flags, [string]$Cwd) {
    $java = Find-Tool 'java'
    $a = @()
    if ($Flags) { $a += $Flags }
    $a += @('-cp', ($Cp -join ';'), $MainClass)
    if ($MainArgs) { $a += $MainArgs }
    return (Invoke-Cp3NativeWithInput -File $java -Arguments $a -StdIn $StdIn -WorkingDirectory $Cwd -Kind 'tool' -TimeoutSec 180)
}

function ConvertFrom-Cp3Digest([string]$Text) {
    $h = @{}
    foreach ($line in ($Text -split "`r?`n")) { if ($line -match '^(\S+)\s+rows=(\d+) sha256=([0-9a-f]{64})$') { $h[$Matches[1]] = ('rows=' + $Matches[2] + ' sha256=' + $Matches[3]) } }
    return $h
}

# ======================================================================== PHASE A
function Invoke-PhaseA {
    $work = Get-WorkRoot $WorkRoot
    Assert-WorkRootSafe $work
    $script:WorkRootResolved = $work
    $runId = 'cp3-' + (New-RunId)
    if ($RunName) { $runId = $RunName }
    $runRoot = Join-Path $work $runId
    $ev = Join-Path $EvidenceRoot 'phaseA'
    if (Test-Path -LiteralPath $ev) { throw "Refusing: the evidence folder already exists: $ev" }
    New-Item -ItemType Directory -Force -Path $ev, $runRoot | Out-Null
    $script:Evidence = $ev
    $script:RunRootForLog = $runRoot
    Say ('CP3 Phase A  run folder ' + $runRoot)
    Say ('             evidence   ' + $ev)
    Say '             no listener and no legacy program will be started'

    # ---- A1 preflight
    $pf = Get-Cp3Preflight 'Phase A'
    Write-Cp3Text (Join-Path $ev '00_preflight.txt') $pf.Lines
    if ($pf.Problems.Count -gt 0) { Stop-WithFailure 'A1' 'preflight' ($pf.Problems -join '; ') }
    Add-Step 'A1' 'preflight (tools, ports free, WinHTTP direct, live DB equals the original manifest)' 'PASS' ''
    $liveStamps = $pf.DbStamps
    $dbPaths = Get-Cp3LiveDbPaths

    # ---- A2 baseline of what must not change
    $projBefore = Get-Cp3ProjectLines
    Write-Cp3Text (Join-Path $ev '00_project_manifest_phaseA_start.txt') $projBefore
    $protBefore = Get-Cp3ProtectedLines
    Write-Cp3Text (Join-Path $ev '00_protected_set_phaseA_start.txt') $protBefore
    $orig = Read-Cp3Manifest $OriginalManifest
    $changedOrig = @(Get-Cp3ManifestMismatches $repo $orig)
    if ($changedOrig.Count -gt 0) { Stop-WithFailure 'A2' ('the original ' + $orig.Count + ' files') ('changed or missing: ' + ($changedOrig -join ', ')) }
    $backupOk = @(Get-Cp3ManifestMismatches $BackupDir $orig)
    if ($backupOk.Count -gt 0) { Stop-WithFailure 'A2' 'the verified backup' ('differs from the original manifest: ' + ($backupOk -join ', ')) }
    $zip = $BackupDir + '.zip'
    $side = ([System.IO.File]::ReadAllText($zip + '.sha256') -split '\s+')[0].ToLower()
    if ((Get-Sha256Hex $zip) -ne $side) { Stop-WithFailure 'A2' 'the backup ZIP' 'its SHA-256 differs from the sidecar file' }
    Add-Step 'A2' 'baselines recorded; 116 originals and the backup folder equal the original manifest; backup ZIP equals its sidecar' 'PASS' ('project files: ' + $projBefore.Count + '; protected-set lines: ' + $protBefore.Count)

    # ---- A3 scratch tree (separate script, in-process)
    $tr = & "$PSScriptRoot\New-Cp3Tree.ps1" -RunDir $runRoot -WorkRoot $work -EvidenceDir $ev -BackupDir $BackupDir -OriginalManifest $OriginalManifest
    $tr = @($tr)[-1]
    $tree = $tr.TreeRoot
    Add-Step 'A3' 'patched scratch tree from the backup; exact-text checks, static gates G-S1..G-S3' 'PASS' ('65 files, tree digest ' + $tr.Digest)
    $afterPatch = @($tr.Manifest)

    # ---- A4 build (compilers only; the built programs are never started)
    $bps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Add-Cp3LaunchLog 'build' $bps @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $tree 'scripts\build.ps1'), '(runs javac, g++, objdump only)')
    $b = Invoke-Native -File $bps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $tree 'scripts\build.ps1')) -WorkingDirectory $tree -TimeoutSec 900
    $bdir = Join-Path $ev '06_build'
    New-Item -ItemType Directory -Force -Path $bdir | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $bdir 'build_console.txt'), ($b.StdOut + $b.StdErr), $script:Cp3Utf8)
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $tree 'build\reports') -File)) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $bdir $f.Name) }
    if ($b.ExitCode -ne 0) { Stop-WithFailure 'A4' 'build of the scratch tree' ('build.ps1 exit code ' + $b.ExitCode) }
    $rep = [System.IO.File]::ReadAllText((Join-Path $tree 'build\reports\build-report.json'), $script:Cp3Utf8) | ConvertFrom-Json
    $comps = @($rep)
    if ($comps.Count -ne 5 -or @($comps | Where-Object { $_.Status -ne 'PASS' }).Count -gt 0) { Stop-WithFailure 'A4' 'build of the scratch tree' 'not all 5 components built' }
    $hitsB = @(Find-Cp3Needles -Root (Join-Path $tree 'build') -Needles @('Ap project', 'Ap_project'))
    Write-Cp3Text (Join-Path $ev '07_binary_string_gate.txt') @('G-B1: byte search (ASCII and UTF-16LE) of every file under <tree>\build for: Ap project | Ap_project', ('files searched: ' + @(Get-ChildItem -LiteralPath (Join-Path $tree 'build') -Recurse -File).Count), ('hits: ' + $hitsB.Count))
    if ($hitsB.Count -gt 0) { Stop-WithFailure 'A4' 'G-B1 binary string gate' ('live-project path strings found in: ' + (($hitsB | ForEach-Object { $_.File }) -join ', ')) }
    $afterBuild = @(Get-Cp3TreeManifest $tree)
    $buildDigest = Get-Cp3ManifestDigest $afterBuild
    Write-Cp3Text (Join-Path $ev '08_tree_manifest_after_build.txt') (@(Format-Cp3Manifest $afterBuild) + @('', ('tree digest (sha256 of the sorted manifest lines): ' + $buildDigest)))
    $mod = @($afterPatch | Where-Object { $p = $_.Path; $x = @($afterBuild | Where-Object { $_.Path -ceq $p }); $x.Count -ne 1 -or $x[0].Hash -ne $_.Hash })
    if ($mod.Count -gt 0) { Stop-WithFailure 'A4' 'G-B2 the build did not modify any source file' ('changed: ' + (($mod | ForEach-Object { $_.Path }) -join ', ')) }
    Add-Step 'A4' 'build of the scratch tree (5 of 5 components); G-B1 no live-project string in any built file; G-B2 sources unchanged by the build' 'PASS' ('files under the tree now: ' + $afterBuild.Count + '; digest ' + $buildDigest)
    $exeInfo = @('pep_proxy.exe', 'agent.exe' | ForEach-Object { $p = Join-Path $tree ('build\cpp\' + $_); $_ + '  ' + (Get-Sha256Hex $p) + '  ' + (Get-Item -LiteralPath $p).Length + ' bytes' })

    # ---- A5 database isolation
    $dbSrc = Join-Path $BackupDir 'db'
    $disp = @(& (Join-Path $repo 'scripts\new-disposable-db.ps1') -Source $dbSrc -WorkRoot $work -RunId (Split-Path -Leaf $runRoot))[-1]
    $pristine = $disp.Dir
    $dbl = New-Object System.Collections.Generic.List[string]
    $dbl.Add('DATABASE ISOLATION (Phase A)')
    $dbl.Add('source of the copy : ' + $dbSrc + '  (the verified backup; the live db folder was never used as a source)')
    $dbl.Add('Phase B copy       : ' + $pristine + '  (never opened by any program in Phase A)')
    foreach ($rel in @('db/zero_trust.db', 'db/zero_trust.db-wal', 'db/zero_trust.db-shm')) {
        $leaf = Split-Path -Leaf $rel
        $h = Get-Sha256Hex (Join-Path $pristine $leaf)
        $dbl.Add(('  {0,-22} sha256 {1}  equals the original manifest: {2}' -f $leaf, $h, ($h -eq $orig[$rel].Hash)))
        if ($h -ne $orig[$rel].Hash) { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'disposable database copy' "$leaf differs from the original manifest" }
    }
    $pristineStamps = Get-Cp3FileStamps @((Join-Path $pristine 'zero_trust.db'), (Join-Path $pristine 'zero_trust.db-wal'), (Join-Path $pristine 'zero_trust.db-shm'))
    $inspect = Join-Path $runRoot 'inspect-db'
    New-Item -ItemType Directory -Force -Path $inspect | Out-Null
    foreach ($leaf in @('zero_trust.db', 'zero_trust.db-wal', 'zero_trust.db-shm')) {
        Copy-Item -LiteralPath (Join-Path $pristine $leaf) -Destination (Join-Path $inspect $leaf)
        if ((Get-Sha256Hex (Join-Path $pristine $leaf)) -ne (Get-Sha256Hex (Join-Path $inspect $leaf))) { Stop-WithFailure 'A5' 'inspection copy' "$leaf differs" }
    }
    $dbl.Add('inspection copy    : ' + $inspect + '  (byte copy of the Phase B copy; ALL SQLite activity of Phase A happens here)')
    $toolsOut = Join-Path $runRoot 'tools'
    New-Item -ItemType Directory -Force -Path $toolsOut | Out-Null
    $javac = Find-Tool 'javac'
    $jc = Invoke-Native -File $javac -Arguments @('-encoding', 'UTF-8', '-Xlint:all', '-d', $toolsOut, (Join-Path $repo 'scripts\tools\SeedTestUsers.java')) -WorkingDirectory $runRoot -TimeoutSec 120
    Add-Cp3LaunchLog 'compile' $javac @('SeedTestUsers.java')
    if ($jc.ExitCode -ne 0) { Stop-WithFailure 'A5' 'SeedTestUsers compiles' ($jc.StdErr.Trim()) }
    $jars = @(Get-ChildItem -LiteralPath (Join-Path $tree 'lib') -Filter '*.jar' -File | Sort-Object Name | ForEach-Object { $_.FullName })
    $cpSeed = @($toolsOut) + $jars
    $cpDb = @((Join-Path $tree 'build\tools')) + $jars
    $inspectDb = Join-Path $inspect 'zero_trust.db'
    # does this JDK need --enable-native-access for sqlite-jdbc? (information for Phase B's command lines)
    $e1 = Get-Cp3JavaTool $cpDb 'DbTool' @('check', $inspectDb) '' @() $runRoot
    $dbl.Add('')
    $dbl.Add('JDK check without --enable-native-access: exit code ' + $e1.ExitCode + '; stderr first lines:')
    foreach ($l in @(($e1.StdErr -split "`r?`n") | Where-Object { $_ } | Select-Object -First 4)) { $dbl.Add('    ' + $l) }
    $flags = @()
    if ($e1.ExitCode -ne 0 -or $e1.StdErr.Trim()) { $flags = @('--enable-native-access=ALL-UNNAMED') }
    $dbl.Add('flags used for the database tools from here on: ' + $(if ($flags.Count -eq 0) { '(none)' } else { $flags -join ' ' }))
    $c1 = Get-Cp3JavaTool $cpDb 'DbTool' @('check', $inspectDb) '' $flags $runRoot
    $dbl.Add('')
    $dbl.Add('DbTool check (inspection copy):')
    foreach ($l in ($c1.StdOut -split "`r?`n")) { if ($l) { $dbl.Add('    ' + $l) } }
    if ($c1.ExitCode -ne 0 -or $c1.StdOut -notmatch 'integrity_check\s+: ok' -or $c1.StdOut -notmatch 'foreign_key_check : 0 violations') { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'DbTool check on the copy' 'integrity or foreign-key problems' }
    $g1 = Get-Cp3JavaTool $cpDb 'DbTool' @('digest', $inspectDb) '' $flags $runRoot
    $digBefore = ConvertFrom-Cp3Digest $g1.StdOut
    $dbl.Add('')
    $dbl.Add('per-table digests before the credential self-test:')
    foreach ($k in ($digBefore.Keys | Sort-Object)) { $dbl.Add(('    {0,-22} {1}' -f $k, $digBefore[$k])) }
    $v = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('verify', $inspectDb) '' $flags $runRoot
    $dbl.Add('')
    $dbl.Add('SeedTestUsers verify (fixture facts the predictions rely on):')
    foreach ($l in ($v.StdOut -split "`r?`n")) { if ($l) { $dbl.Add('    ' + $l) } }
    if ($v.ExitCode -ne 0) { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'fixture facts' 'at least one fixture fact does not hold; the predictions would be void' }
    $g1b = Get-Cp3JavaTool $cpDb 'DbTool' @('digest', $inspectDb) '' $flags $runRoot
    $digVerify = ConvertFrom-Cp3Digest $g1b.StdOut
    if ($digVerify.Count -ne $digBefore.Count -or $digBefore.Count -lt 5) { Stop-WithFailure 'A5' 'verify is read-only' ('digest table count: ' + $digVerify.Count + ' after, ' + $digBefore.Count + ' before') }
    foreach ($k in $digBefore.Keys) { if ($digVerify[$k] -ne $digBefore[$k]) { Stop-WithFailure 'A5' 'SeedTestUsers verify is read-only' "table $k changed during verify" } }
    $dbl.Add('verify did not change any table (digests identical before and after)')
    # credential-reset mechanism on the throw-away inspection copy, with generated values that are never written anywhere
    $users = @('dr_alice', 'nurse_bob', 'front_carol', 'audit_dan')
    $test = @{}
    foreach ($u in $users) { $test[$u] = @{ Password = (New-Cp3Password); Pin = (New-Cp3Pin) } }
    $stdin = (($users | ForEach-Object { $_ + "`t" + $test[$_].Password + "`t" + $test[$_].Pin }) -join "`n") + "`n"
    $rs = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('reset', $inspectDb) $stdin $flags $runRoot
    $dbl.Add('')
    $dbl.Add('SeedTestUsers reset (generated values, stdin only): exit code ' + $rs.ExitCode + '; output: ' + ($rs.StdOut.Trim()))
    if ($rs.ExitCode -ne 0) { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'credential reset mechanism' 'reset failed' }
    $g2 = Get-Cp3JavaTool $cpDb 'DbTool' @('digest', $inspectDb) '' $flags $runRoot
    $digAfter = ConvertFrom-Cp3Digest $g2.StdOut
    $changedTables = @($digBefore.Keys | Where-Object { $digAfter[$_] -ne $digBefore[$_] } | Sort-Object)
    $dbl.Add('tables whose digest changed because of the reset: ' + ($changedTables -join ', ') + '  (expected: users only)')
    if (($changedTables -join ',') -ne 'users') { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'credential reset touches only the users table' ('changed: ' + ($changedTables -join ', ')) }
    $loginOk = $true
    foreach ($u in $users) {
        $m1 = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('check-login', $inspectDb, $u) ($test[$u].Password + "`n") $flags $runRoot
        $m2 = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('check-login', $inspectDb, $u) ((New-Cp3Password) + "`n") $flags $runRoot
        $m3 = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('check-pin', $inspectDb, $u) ($test[$u].Pin + "`n") $flags $runRoot
        $m4 = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('check-pin', $inspectDb, $u) ((New-Cp3Pin) + "`n") $flags $runRoot
        $row = ('    {0,-12} right password: {1}; random wrong password: {2}; right PIN: {3}; random wrong PIN: {4}' -f $u, $m1.StdOut.Trim(), $m2.StdOut.Trim(), $m3.StdOut.Trim(), $m4.StdOut.Trim())
        $dbl.Add($row)
        if ($m1.StdOut.Trim() -ne 'MATCH' -or $m2.StdOut.Trim() -ne 'NO MATCH' -or $m3.StdOut.Trim() -ne 'MATCH' -or $m4.StdOut.Trim() -ne 'NO MATCH') { $loginOk = $false }
    }
    if (-not $loginOk) { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'reset credentials match through the legacy comparison' 'a MATCH / NO MATCH result was wrong' }
    # generated values must not be in any file this run (or the project scripts) wrote
    $canaries = New-Object System.Collections.Generic.List[string]
    foreach ($u in $users) {
        foreach ($val in @($test[$u].Password, $test[$u].Pin)) {
            $canaries.Add($val)
        }
    }
    $hashCanaries = New-Object System.Collections.Generic.List[string]
    foreach ($c in $canaries) { $hashCanaries.Add((Get-Cp3TextSha256 $c)) }
    $leakDirs = @($ev, $toolsOut, $inspect, $pristine, (Join-Path $repo 'scripts\cp3'), (Join-Path $repo 'tests\baseline'))
    $leaks = @(Find-Cp3Leaks -Directories $leakDirs -Canaries $canaries.ToArray())
    $leakHash = @(Find-Cp3Leaks -Directories @($ev, $toolsOut, (Join-Path $repo 'scripts\cp3'), (Join-Path $repo 'tests\baseline')) -Canaries $hashCanaries.ToArray())
    $dbl.Add('')
    $dbl.Add(('leak scan: the 8 generated values (4 passwords, 4 PINs) were searched in {0} folders (evidence, tools, both database copies, scripts\cp3, tests\baseline): {1} hit(s)' -f $leakDirs.Count, $leaks.Count))
    $dbl.Add(('leak scan: their SHA-256 values were searched in the evidence, tools, scripts\cp3 and tests\baseline folders (the hashes legitimately live only in the inspection database): {0} hit(s)' -f $leakHash.Count))
    if ($leaks.Count -gt 0 -or $leakHash.Count -gt 0) { Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray(); Stop-WithFailure 'A5' 'generated credentials stay out of files' (($leaks + $leakHash) -join ', ') }
    $test = $null
    # ($canaries and $hashCanaries stay in memory until step A10 has searched the final evidence for them; they are never written anywhere)
    # the Phase B copy and the live files are unchanged
    $pristineNow = Get-Cp3FileStamps @((Join-Path $pristine 'zero_trust.db'), (Join-Path $pristine 'zero_trust.db-wal'), (Join-Path $pristine 'zero_trust.db-shm'))
    $pc = @(Compare-Cp3FileStamps $pristineStamps $pristineNow)
    $pristineHashes = @('zero_trust.db', 'zero_trust.db-wal', 'zero_trust.db-shm' | ForEach-Object { $_ + '  ' + (Get-Sha256Hex (Join-Path $pristine $_)) })
    $dbl.Add('')
    $dbl.Add('Phase B copy after all Phase A database work: changed files = ' + $pc.Count + '; hashes:')
    foreach ($h in $pristineHashes) { $dbl.Add('    ' + $h) }
    $lc = @(Compare-Cp3FileStamps $liveStamps (Get-Cp3FileStamps $dbPaths))
    $dbl.Add('live database files changed since the start of Phase A (size / last-write tripwire): ' + $lc.Count)
    Write-Cp3Text (Join-Path $ev '09_db_isolation.txt') $dbl.ToArray()
    if ($pc.Count -gt 0) { Stop-WithFailure 'A5' 'the Phase B database copy stays pristine' ('changed: ' + ($pc -join ', ')) }
    if ($lc.Count -gt 0) { Stop-WithFailure 'A5' 'the live database files stay unchanged' ('changed: ' + ($lc -join ', ')) }
    Add-Step 'A5' 'database isolation: copy from the backup, byte-identical to the originals; integrity ok; fixture facts hold; reset mechanism proven on a throw-away copy; no generated value in any file' 'PASS' ('JDK flags for the tools: ' + $(if ($flags.Count -eq 0) { 'none needed' } else { $flags -join ' ' }))

    # ---- A6 harness self-checks (child process; starts only a harmless sleeper)
    $hOut = Join-Path $ev 'harness'
    $hs = Invoke-Native -File $bps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'Test-Cp3Harness.ps1'), '-OutDir', $hOut, '-WorkRoot', $work) -WorkingDirectory $repo -TimeoutSec 900
    Add-Cp3LaunchLog 'harness' $bps @('Test-Cp3Harness.ps1 (starts only a harmless PowerShell sleeper)')
    [System.IO.File]::WriteAllText((Join-Path $ev '10_harness_console.txt'), ($hs.StdOut + $hs.StdErr), $script:Cp3Utf8)
    $hLine = @(($hs.StdOut -split "`r?`n") | Where-Object { $_ -like 'OVERALL:*' } | Select-Object -Last 1)
    if ($hs.ExitCode -ne 0) { Stop-WithFailure 'A6' 'harness self-checks' ('exit code ' + $hs.ExitCode + '; see 10_harness_console.txt') }
    $nPass = @(($hs.StdOut -split "`r?`n") | Where-Object { $_ -match '^PASS\s' }).Count
    # completeness: every check that is supposed to exist must have run and passed, and nothing else may be claimed (a check that silently did not run is a failure)
    $expectedChecks = @('H0', 'H1', 'H1b', 'H2', 'H2b', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8', 'H9', 'H10', 'H13', 'H15', 'H14', 'H16', 'H16b', 'H17', 'H18', 'H19', 'H20', 'H21', 'H24', 'H11', 'H12', 'H22', 'H23')
    $completeness = @(Get-Cp3HarnessCompletenessProblems $hs.StdOut $expectedChecks)
    if ($completeness.Count -gt 0) { Stop-WithFailure 'A6' ('harness completeness: all ' + $expectedChecks.Count + ' expected checks must show PASS') ($completeness -join '; ') }
    Add-Step 'A6' 'harness self-checks (fixtures, harmless sleepers and own probe classes only, a no-socket model dry run with mutants; includes the C1-C5 run-state monitor, wait hook, audit, shutdown-verification and sensitive-data-scan checks)' 'PASS' ($hLine[0] + '; ' + $nPass + ' checks PASS')

    # ---- A7 static check of the launch switch + secret scan of the new files
    $self = [System.IO.File]::ReadAllText($PSCommandPath, $script:Cp3Utf8)
    $needle = '$script:Cp3AllowLegacy' + 'Launch = $true'   # built in two pieces so that this line itself does not contain the needle
    # the markers are located with line-anchored patterns so that this very code (which mentions them inside strings) cannot match itself
    $occ = [regex]::Matches($self, [regex]::Escape($needle))
    $mB = [regex]::Match($self, '(?m)^function Invoke-PhaseB\b')
    $mEnd = [regex]::Match($self, '(?m)^# =+ MAIN\s*$')
    $switchOk = ($occ.Count -eq 1 -and $mB.Success -and $mEnd.Success -and $occ[0].Index -gt $mB.Index -and $occ[0].Index -lt $mEnd.Index)
    $others = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Where-Object { $_.Name -ne 'Run-Cp3.ps1' } | Where-Object { [System.IO.File]::ReadAllText($_.FullName).Contains($needle) } | ForEach-Object { $_.Name })
    $sl = @('static check of the legacy-launch switch', "  Run-Cp3.ps1 sets it exactly once and only inside Invoke-PhaseB: $switchOk", ('  other scripts that contain the assignment: ' + ($others -join ', ') + '  (Test-Cp3Harness.ps1 sets it temporarily inside check H1b, which only calls the guard function, and resets it in a finally block)'))
    Write-Cp3Text (Join-Path $ev '11_static_launch_switch.txt') $sl
    if (-not $switchOk -or ($others -join ',') -ne 'Test-Cp3Harness.ps1') { Stop-WithFailure 'A7' 'legacy-launch switch is confined to Phase B' ($sl -join ' | ') }
    $cs = Join-Path $repo 'scripts\check-secrets.ps1'
    $scanDir = Join-Path $ev '12_secret_scan'
    $scanOut = New-Object System.Collections.Generic.List[string]
    foreach ($target in @('scripts', 'tests')) {
        $o = Join-Path $scanDir $target
        $r = Invoke-Native -File $bps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $cs, '-Path', (Join-Path $repo $target), '-OutDir', $o, '-WorkRoot', $work) -WorkingDirectory $repo -TimeoutSec 600
        Add-Cp3LaunchLog 'scan' $bps @('check-secrets.ps1', $target)
        $scanOut.Add("=== check-secrets.ps1 -Path $target  (exit code $($r.ExitCode))")
        foreach ($l in ($r.StdOut -split "`r?`n")) { if ($l) { $scanOut.Add($l) } }
        if ($r.ExitCode -ne 0) { Write-Cp3Text (Join-Path $ev '12_secret_scan_summary.txt') $scanOut.ToArray(); Stop-WithFailure 'A7' ("secret scan of $target") ("exit code $($r.ExitCode); see 12_secret_scan_summary.txt") }
    }
    Write-Cp3Text (Join-Path $ev '12_secret_scan_summary.txt') $scanOut.ToArray()
    Add-Step 'A7' 'legacy-launch switch confined to Phase B; secret scan of scripts\ and tests\ (all new CP3 files included)' 'PASS' 'scanner exit code 0 for both folders'

    # ---- A8 preview of the exact Phase B command lines, validated by the launch guard in dry-check mode (nothing is started)
    $planJava = Get-Cp3RealJavaExe
    $plan = @(Get-Cp3LaunchPlan -Tree $tree -JavaExe $planJava -JavaFlags $flags)
    $pv = New-Object System.Collections.Generic.List[string]
    $pv.Add('PHASE B LAUNCH PREVIEW - these programs were NOT started in Phase A. The launch guard accepts exactly these command lines (checked now in dry-check mode).')
    $pv.Add('working directory of every program : ' + (Join-Path $runRoot 'wd') + '  (an empty folder created in Phase B)')
    $pv.Add('standard output / error             : ' + (Join-Path $runRoot 'logs') + '\<role>.out.log / <role>.err.log')
    $pv.Add('environment                         : PATH extended by ' + (Split-Path -Parent (Find-Tool 'g++')) + ' inside the orchestrator process only (MinGW runtime DLLs)')
    $pv.Add('every program is assigned to a Job Object with kill-on-close; each start is followed by a loopback-only audit of all processes in the job')
    $pv.Add('')
    $pv.Add('STOP CONDITIONS enforced by the run-state monitor in Phase B (any one stops the run at once; nothing is retried, repaired or ignored):')
    $pv.Add('  - before every request, and at the start of every slice of at most one second of every wait (including the waits for a listener or a heartbeat):')
    $pv.Add('      * a recorded process that is expected to be running has exited (reported with its exit code); an older process of a role still runs after a newer one started')
    $pv.Add('      * a process is in the Job Object that this run did not start and record (the only tolerated member is the system conhost.exe whose parent is a recorded process)')
    $pv.Add('      * a recorded running process is not a member of the Job Object')
    $pv.Add('      * a live database file changed (size / last-write tripwire on db\zero_trust.db, -wal, -shm)')
    $pv.Add('      * a listener on a test port is not on 127.0.0.1, or a connection to a test port does not have 127.0.0.1 at both ends (system-wide TCP table, cheap)')
    $pv.Add('      * the run exceeded its time limit (startup 600 s, scenarios 900 s)')
    $pv.Add('  - planned exits: the agent only at T13 (stopped by the harness, restarted before T13.5), the PEP only at P1 and P2 (expected crash, exit code 99 from the scratch terminate handler, restarted by the harness).')
    $pv.Add('    A window is opened right before the step and closed right after it; closing it requires the role to be running again; any other exit code of the PEP, a restart that failed, a window left open: the run stops.')
    $pv.Add('  - full pid-attributed listener and connection audit (any non-127.0.0.1 listener or any connection of a recorded or job process whose remote end is not 127.0.0.1 stops the run; every running server role must also be SEEN listening on its port):')
    $pv.Add('      * after every start, after the agent restart, after every PEP restart, before shutdown, about every 5 seconds before requests and during waits (sampling), and in any case before every 10th request')
    $pv.Add('  - after shutdown (gate B7): every stop result is stopped or already-gone (REFUSED = failure); every recorded process shown to have exited; no job leftovers (5 s grace) and no former member running after the job is closed;')
    $pv.Add('    nothing running from the run folder; nothing listening on the test ports; live database unchanged (hashes and stamps); the original files equal the original manifest; the project and the protected backup/evidence set unchanged;')
    $pv.Add('    the scratch tree unchanged; the disposable database passes its integrity check; no crash event of the test programs. No file is deleted, restored or overwritten to make a check pass.')
    $pv.Add('  - results gate (B8): evidence, test results and program logs scanned for synthetic patient markers, issued secrets and credential shapes (categories and locations only are reported).')
    $pv.Add('  - if the run stops early for any reason: the programs are still stopped by recorded pid, the post-run verification report and a sensitive-data scan of what exists (partial results, program logs) are still written and shown, and the original error is kept.')
    $pv.Add('')
    foreach ($e in $plan) {
        Assert-Cp3LaunchAllowed -Kind $e.Kind -File $e.File -Arguments $e.Arguments -TreeRoot $tree -DryCheck
        if (-not (Test-Path -LiteralPath $e.File -PathType Leaf)) { Stop-WithFailure 'A8' 'launch plan' ('program not found: ' + $e.File) }
        $ready = 'ready when 127.0.0.1:' + $e.Port + ' is listened on by this very process'
        if ($e.Port -eq 0) { $ready = 'ready when its log shows a heartbeat answered with HTTP 200 (no listener)' }
        $pv.Add(('{0,-6} [{1}] {2}' -f $e.Role, $e.Kind, $e.File))
        $pv.Add('       arguments : ' + (ConvertTo-ArgString $e.Arguments))
        $pv.Add('       ' + $ready)
    }
    $pv.Add('')
    $pv.Add('start order: api, pdp, pep, agent. Stop order: reverse, by recorded pid + start time + image path. Emergency stop: scripts\cp3\Stop-Cp3.ps1 -RunDir ' + $runRoot)
    $pv.Add('note: java.exe is started directly from java.home ' + $planJava + ' (the PATH java.exe is a launcher shim that starts the JVM as a child process).')
    $pv.Add('note: the flag --enable-native-access=ALL-UNNAMED only silences the JDK 25 warning about sqlite-jdbc loading its native library; it is used for the database tools and, in this plan, for API and PDP.')
    Write-Cp3Text (Join-Path $ev '14_phaseB_launch_preview.txt') $pv.ToArray()
    if ($script:Cp3AllowLegacyLaunch) { Stop-WithFailure 'A8' 'launch switch' 'the legacy-launch switch is on in Phase A' }

    # ---- A8 frozen expectations + manifest of everything Phase B will re-verify
    $expPath = Join-Path $repo 'tests\baseline\cp3_expectations.json'
    $scriptHashes = [ordered]@{}
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $repo 'scripts\cp3') -File | Sort-Object Name)) { $scriptHashes['scripts/cp3/' + $f.Name] = Get-Sha256Hex $f.FullName }
    foreach ($rel in @('scripts/tools/SeedTestUsers.java', 'scripts/common.ps1', 'scripts/build.ps1', 'scripts/new-disposable-db.ps1', 'scripts/tools/DbTool.java', 'tests/baseline/cp3_expectations.json')) { $scriptHashes[$rel] = Get-Sha256Hex (Join-Path $repo ($rel -replace '/', '\')) }
    $classHashes = [ordered]@{}
    foreach ($f in (Get-ChildItem -LiteralPath $toolsOut -File | Sort-Object Name)) { $classHashes['tools/' + $f.Name] = Get-Sha256Hex $f.FullName }
    $manifest = [ordered]@{
        schema = 1; phase = 'A'; createdUtc = (Get-Date).ToUniversalTime().ToString('o'); runId = (Split-Path -Leaf $runRoot); runDir = $runRoot; evidenceDir = $ev
        treeDigestAfterPatch = $tr.Digest; treeDigestAfterBuild = $buildDigest; treeFileCountAfterBuild = $afterBuild.Count
        patchSpecSha256 = $tr.SpecHash; expectationsSha256 = (Get-Sha256Hex $expPath)
        scripts = $scriptHashes; toolClasses = $classHashes
        disposableDbPristine = [ordered]@{ dir = $pristine; files = @('zero_trust.db', 'zero_trust.db-wal', 'zero_trust.db-shm' | ForEach-Object { [ordered]@{ name = $_; sha256 = (Get-Sha256Hex (Join-Path $pristine $_)) } }) }
        liveDbSha256 = [ordered]@{ db = $orig['db/zero_trust.db'].Hash; wal = $orig['db/zero_trust.db-wal'].Hash; shm = $orig['db/zero_trust.db-shm'].Hash }
        executables = $exeInfo; jdkFlagsForTools = $flags; javaExe = (Get-Cp3RealJavaExe)
    }
    $mj = ConvertTo-Json -InputObject $manifest -Depth 6
    [System.IO.File]::WriteAllText((Join-Path $runRoot 'phaseA_manifest.json'), $mj, $script:Cp3Utf8)
    [System.IO.File]::WriteAllText((Join-Path $ev 'phaseA_manifest.json'), $mj, $script:Cp3Utf8)
    Add-Step 'A8' 'Phase B command lines previewed and accepted by the launch guard (dry check, nothing started); expectations frozen and hashed; Phase A manifest written' 'PASS' ('expectations sha256 ' + (Get-Sha256Hex $expPath))

    # ---- A9 postflight
    $pfa = Get-Cp3Preflight 'Phase A postflight'
    Write-Cp3Text (Join-Path $ev '13_postflight.txt') $pfa.Lines
    if ($pfa.Problems.Count -gt 0) { Stop-WithFailure 'A9' 'postflight' ($pfa.Problems -join '; ') }
    $projAfter = Get-Cp3ProjectLines
    $pd = @(Compare-Cp3Lines $projBefore $projAfter)
    $protAfter = Get-Cp3ProtectedLines
    $prd = @(Compare-Cp3Lines $protBefore $protAfter)
    $lc2 = @(Compare-Cp3FileStamps $liveStamps (Get-Cp3FileStamps $dbPaths))
    $extra = @()
    $extra += 'project files at the start / end of Phase A: ' + $projBefore.Count + ' / ' + $projAfter.Count + '; differing lines: ' + $pd.Count
    $extra += 'protected set (backup folder, ZIP + sidecar, CP0, CP1, CP2, CP2b, CP3_PLAN evidence) lines at start / end: ' + $protBefore.Count + ' / ' + $protAfter.Count + '; differing lines: ' + $prd.Count
    $extra += 'live database files changed (size / last-write tripwire): ' + $lc2.Count
    $left = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and $_.Path.StartsWith($runRoot, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false } })
    $extra += 'processes running from the run folder: ' + $left.Count
    $extra += 'listeners/connections on 5000 8443 9000 9443 15000 18443 19000: ' + @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { @(5000, 8443, 9000, 9443, 15000, 18443, 19000) -contains [int]$_.LocalPort }).Count
    $origEnd = @(Get-Cp3ManifestMismatches $repo $orig)
    $backupEnd = @(Get-Cp3ManifestMismatches $BackupDir $orig)
    $extra += 'original files (' + $orig.Count + ' in the original manifest, live database files included) that are missing or differ now: ' + $origEnd.Count
    $extra += 'verified backup files (same manifest) that are missing or differ now: ' + $backupEnd.Count
    Write-Cp3Text (Join-Path $ev '13_postflight.txt') (@($pfa.Lines) + @('') + $extra + @('') + $pd + $prd + $origEnd + $backupEnd)
    if ($origEnd.Count -gt 0) { Stop-WithFailure 'A9' ('the original ' + $orig.Count + ' files are unchanged') ($origEnd -join ' | ') }
    if ($backupEnd.Count -gt 0) { Stop-WithFailure 'A9' 'the verified backup is unchanged' ($backupEnd -join ' | ') }
    if ($pd.Count -gt 0) { Stop-WithFailure 'A9' 'the project is unchanged by Phase A' ($pd -join ' | ') }
    if ($prd.Count -gt 0) { Stop-WithFailure 'A9' 'the protected backup/evidence set is unchanged' ($prd -join ' | ') }
    if ($lc2.Count -gt 0) { Stop-WithFailure 'A9' 'the live database files are unchanged' ($lc2 -join ', ') }
    if ($left.Count -gt 0) { Stop-WithFailure 'A9' 'no process left' ('running: ' + (($left | ForEach-Object { $_.Id }) -join ',')) }
    Add-Step 'A9' 'postflight: the original files, the backup, the project and the protected set are unchanged, live database unchanged, no process or listener left' 'PASS' ($extra -join ' | ')

    # ---- A10 (C5) sensitive-data scan of everything Phase A wrote (evidence, harness results and logs) and of tests\baseline
    $seeder = Join-Path $tree 'protected_app\src\app\seed\PatientSeeder.java'
    $issuedA = New-Object System.Collections.Generic.List[object]
    foreach ($v in $canaries) { $issuedA.Add([pscustomobject]@{ Category = 'issued-test-credential'; Value = $v }) }
    foreach ($v in $hashCanaries) { $issuedA.Add([pscustomobject]@{ Category = 'issued-test-credential-sha256'; Value = $v }) }
    $litA = Get-Cp3SensitiveLiterals $seeder $issuedA.ToArray()
    $targetsA = @(
        [pscustomobject]@{ Label = 'evidence (phase A)'; Path = $ev },
        [pscustomobject]@{ Label = 'tests\baseline'; Path = (Join-Path $repo 'tests\baseline') }
    )
    $scanA = Invoke-Cp3SensitiveScan -Targets $targetsA -Literals $litA -ReportPath (Join-Path $ev '15_sensitive_data_scan.txt') -Title 'CP3 PHASE A - sensitive-data scan (C5)'
    $scanProblems = @(Get-Cp3SensitiveScanProblems $scanA)
    $canaries = $null
    $hashCanaries = $null
    if ($scanProblems.Count -gt 0) { Stop-WithFailure 'A10' 'no synthetic patient marker, issued value or credential-shaped text in the evidence and test results' ($scanProblems -join ' | ') }
    Add-Step 'A10' 'sensitive-data scan (C5) of the Phase A evidence, harness results and tests\baseline: 0 patient markers, 0 issued values, 0 credential-shaped strings' 'PASS' ('files scanned: ' + (($scanA.Targets | ForEach-Object { $_.Label + ' ' + $_.Files }) -join ', ') + '; literal values searched: ' + $litA.Count)

    $script:Skipped.Add('Java/JUnit unit tests: NOT RUN (dependency gate G1 not approved, no JUnit jar, no Java test sources).')
    $script:Skipped.Add('All 30 CP3 scenario steps: NOT RUN (Phase B needs your approval). The model dry run in H11/H12 shows the engine and verdict logic work; it proves nothing about the real system.')
    $script:Skipped.Add('Starting API, PDP, PEP or agent: NOT DONE. Not exercised: Start-Cp3Process with a legacy program, Send-Cp3Raw against a real socket, Wait-Cp3Listener against a real listener, Invoke-PhaseB as a whole (including the post-run report and the final integrity step against a real run), Stop-Cp3.ps1 against the real programs (the harness exercises it with harmless sleepers).')
    $script:Skipped.Add('INDIRECT only (harmless sleepers, synthetic records, the TCP table of this machine and the no-socket model; never the real programs): the run-state monitor, the planned-exit windows, the Job Object membership rules incl. the conhost.exe exception, the pid-attributed audit and the listener-coverage check, the wait hook, the shutdown verification helpers. The periodic full audit is a SAMPLE (about every 5 s); a connection that opens and closes between two samples is only caught by the stage audits if it is still open then, and the quick per-request check sees test-port sockets by port, not by owner.')
    $script:Skipped.Add('Known gap, unchanged from Phase A: a program is assigned to the Job Object right after it was created (not created suspended), so a child it started in that instant would not be a member; the legacy programs start no child processes.')
    $script:Skipped.Add('scripts\run-tests.ps1 (the CP2 regression run): SKIPPED on purpose - it regenerates files under the repository build\ folder; no CP2 script was modified in Phase A (only scripts\README.md, documentation text).')
    $script:Skipped.Add('The built scratch executables pep_proxy.exe and agent.exe were never started; only their bytes were hashed and searched.')
    Write-Cp3ResultsFile (Join-Path $ev 'CP3A_RESULTS.txt') 'CP3 PHASE A RESULTS'
    Say ''
    Say ('PHASE A: PASS  (' + @($script:Steps | Where-Object { $_.Status -eq 'PASS' }).Count + ' steps PASS, 0 FAIL)')
    Say ('run folder (for Phase B): ' + $runRoot)
}

# ======================================================================== PHASE B
# C4: everything that must be true once the programs are stopped. It only READS: nothing in it deletes, restores or rewrites a file, so a failed
# integrity check stays visible. Every section catches its own errors and turns them into problems (a check that cannot run is a failure).
function Get-Cp3PostRunReport {
    param($S)
    $lines = New-Object System.Collections.Generic.List[string]
    $problems = New-Object System.Collections.Generic.List[string]
    $lines.Add('POST-RUN VERIFICATION  ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '   (read-only: nothing is deleted, restored or overwritten)')
    $lines.Add('')

    $lines.Add('1. cleanup: result of stopping each recorded process, newest first (every result must be stopped or already-gone):')
    foreach ($r in @($S.StopResults)) { $lines.Add('     ' + $r) }
    foreach ($e in @($S.ShutdownErrors)) { $lines.Add('     ERROR ' + $e) }
    foreach ($x in @(Get-Cp3CleanupProblems $S.StopResults $S.ShutdownErrors)) { $problems.Add($x) }

    $lines.Add('2. every recorded process has exited (one row per record in the pid file):')
    try {
        $tbl = @(Get-Cp3RecordExitTable $S.PidFile)
        if ($tbl.Count -eq 0) { $lines.Add('     (the pid file holds no record)') }
        foreach ($t in $tbl) {
            $lines.Add(('     {0,-6} pid {1,6}  exited: {2}  exit code: {3}  decided by: {4}' -f $t.Role, $t.Pid, $t.Exited, (Format-Cp3ExitCode $t.ExitCode), $t.Source))
            if (-not $t.Exited) { $problems.Add(('the recorded {0} process (pid {1}) has not exited' -f $t.Role, $t.Pid)) }
        }
    } catch { $problems.Add('the exit table could not be built: ' + $_.Exception.Message) }

    $lines.Add('3. Job Object: members left after the stop loop (5 s grace) = ' + @($S.JobLeft).Count + '; former members still running after the job was closed (5 s grace) = ' + @($S.Survivors).Count)
    foreach ($x in @($S.JobLeft)) { $lines.Add('     ' + $x); $problems.Add('job leftover: ' + $x) }
    foreach ($x in @($S.Survivors)) { $lines.Add('     ' + $x); $problems.Add('job survivor: ' + $x) }

    try {
        $left = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and $_.Path.StartsWith($S.RunRoot, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false } })
        $lines.Add('4. processes running from the run folder: ' + $left.Count)
        if ($left.Count -gt 0) { $problems.Add('processes still running from the run folder: ' + (($left | ForEach-Object { $_.Id }) -join ',')) }
        $busy = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $script:Cp3TestPorts -contains [int]$_.LocalPort -and [string]$_.State -eq 'Listen' })
        $lines.Add('   listeners on the three test ports: ' + $busy.Count)
        if ($busy.Count -gt 0) { $problems.Add('listeners still present on the test ports: ' + $busy.Count) }
    } catch { $problems.Add('the process / listener check could not be completed: ' + $_.Exception.Message) }

    try {
        $lc = @(Compare-Cp3FileStamps $S.LiveStamps (Get-Cp3FileStamps $S.DbPaths))
        $lines.Add('5. live database files changed (size / last-write tripwire): ' + $lc.Count)
        foreach ($x in $lc) { $problems.Add('live database file changed (stamp): ' + $x) }
        foreach ($leaf in @('zero_trust.db', 'zero_trust.db-wal', 'zero_trust.db-shm')) {
            $h = Get-Sha256Hex (Join-Path $repo ('db\' + $leaf))
            $same = ($h -eq $S.Orig[('db/' + $leaf)].Hash)
            $lines.Add(('   live {0,-20} sha256 {1}  equals the original manifest: {2}' -f $leaf, $h, $same))
            if (-not $same) { $problems.Add('live database file differs from the original manifest: ' + $leaf) }
        }
    } catch { $problems.Add('the live database check could not be completed: ' + $_.Exception.Message) }

    try {
        $om = @(Get-Cp3ManifestMismatches $repo $S.Orig)
        $lines.Add('6. original files (' + $S.Orig.Count + ' in the original manifest) that are missing or differ: ' + $om.Count)
        foreach ($x in $om) { $lines.Add('     ' + $x); $problems.Add('original file: ' + $x) }
    } catch { $problems.Add('the original-files check could not be completed: ' + $_.Exception.Message) }

    try {
        $pEnd = @(Get-Cp3ProjectLines)
        $pd = @(Compare-Cp3Lines $S.ProjBefore $pEnd)
        $lines.Add('7. project files at the start / now: ' + @($S.ProjBefore).Count + ' / ' + $pEnd.Count + '; differing lines: ' + $pd.Count + '  (taken before the result files are written)')
        foreach ($x in $pd) { $lines.Add('     ' + $x); $problems.Add('project: ' + $x) }
    } catch { $problems.Add('the project comparison could not be completed: ' + $_.Exception.Message) }

    try {
        $prEnd = @(Get-Cp3ProtectedLines)
        $prd = @(Compare-Cp3Lines $S.ProtBefore $prEnd)
        $lines.Add('8. protected backup / evidence set lines at the start / now: ' + @($S.ProtBefore).Count + ' / ' + $prEnd.Count + '; differing lines: ' + $prd.Count)
        foreach ($x in $prd) { $lines.Add('     ' + $x); $problems.Add('protected set: ' + $x) }
    } catch { $problems.Add('the protected-set comparison could not be completed: ' + $_.Exception.Message) }

    try {
        $digestNow = Get-Cp3ManifestDigest (Get-Cp3TreeManifest $S.Tree)
        $lines.Add('9. scratch tree digest now ' + $digestNow + '; Phase A manifest ' + $S.TreeDigest + '; equal: ' + ($digestNow -eq $S.TreeDigest))
        if ($digestNow -ne $S.TreeDigest) { $problems.Add('the scratch tree differs from the Phase A manifest (a program wrote inside it?)') }
    } catch { $problems.Add('the scratch tree check could not be completed: ' + $_.Exception.Message) }

    if ($null -eq $S.CpDb) {
        $lines.Add('10. disposable database check: not reached (the run stopped before the database tools were prepared)')
    } else {
        try {
            $c1 = Get-Cp3JavaTool $S.CpDb 'DbTool' @('check', $S.DbFile) '' $S.Flags $S.RunRoot
            $lines.Add('10. disposable database after the run (DbTool check, exit code ' + $c1.ExitCode + '):')
            foreach ($l in @($c1.StdOut -split "`r?`n" | Where-Object { $_ })) { $lines.Add('      ' + $l) }
            if ($c1.ExitCode -ne 0 -or $c1.StdOut -notmatch 'integrity_check\s+: ok' -or $c1.StdOut -notmatch 'foreign_key_check : 0 violations') { $problems.Add('the disposable database failed its integrity / foreign-key check') }
            $g1 = Get-Cp3JavaTool $S.CpDb 'DbTool' @('digest', $S.DbFile) '' $S.Flags $S.RunRoot
            $d1 = ConvertFrom-Cp3Digest $g1.StdOut
            $lines.Add('    per-table digests before / after the run (information: the scenarios are expected to change some tables):')
            foreach ($k in @($S.DigestBefore.Keys | Sort-Object)) { $lines.Add(('      {0,-22} before {1}   after {2}' -f $k, $S.DigestBefore[$k], $d1[$k])) }
        } catch { $problems.Add('the disposable database check could not be completed: ' + $_.Exception.Message) }
    }

    try {
        $q = 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'
        $werNow = -1
        if (Test-Path -LiteralPath $q) { $werNow = @(Get-ChildItem -LiteralPath $q -ErrorAction SilentlyContinue).Count }
        $werEvents = @()
        try { $werEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop | Where-Object { $_.Message -match 'pep_proxy|agent\.exe|java' }) }
        catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
        $lines.Add('11. WER ReportQueue entries before / after: ' + $S.WerBefore + ' / ' + $werNow + ' (information); Application Error events naming the test programs in the last 30 minutes: ' + $werEvents.Count)
        if ($werEvents.Count -gt 0) { $problems.Add('Windows logged ' + $werEvents.Count + ' Application Error event(s) naming the test programs') }
    } catch { $problems.Add('the crash-report check could not be completed: ' + $_.Exception.Message) }

    if ($S.AuditNote) { $lines.Add('12. ' + $S.AuditNote) }
    $lines.Add('')
    $lines.Add('problems: ' + $problems.Count)
    foreach ($p in $problems) { $lines.Add('  PROBLEM ' + $p) }
    return [pscustomobject]@{ Lines = $lines.ToArray(); Problems = $problems.ToArray() }
}

# The values this run issued (passwords, PINs, their SHA-256 values, tokens, session ids), as literals for the sensitive-data scan.
function Get-Cp3IssuedLiterals($Creds, $Redactor) {
    $issued = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Creds) {
        foreach ($u in $Creds.Keys) {
            $issued.Add([pscustomobject]@{ Category = 'issued-password'; Value = [string]$Creds[$u].Password })
            $issued.Add([pscustomobject]@{ Category = 'issued-pin'; Value = [string]$Creds[$u].Pin })
            $issued.Add([pscustomobject]@{ Category = 'issued-password-sha256'; Value = (Get-Cp3TextSha256 ([string]$Creds[$u].Password)) })
            $issued.Add([pscustomobject]@{ Category = 'issued-pin-sha256'; Value = (Get-Cp3TextSha256 ([string]$Creds[$u].Pin)) })
        }
    }
    foreach ($rv in $Redactor.Values) {
        if ([string]$rv.Label -ceq 'token') { $issued.Add([pscustomobject]@{ Category = 'issued-token'; Value = [string]$rv.Value }) }
        if ([string]$rv.Label -ceq 'session') { $issued.Add([pscustomobject]@{ Category = 'issued-session-id'; Value = [string]$rv.Value }) }
    }
    return $issued.ToArray()
}

function Invoke-PhaseB {
    if (-not $ConfirmStartListeners) { throw 'Phase B starts the scratch copy of the legacy programs on 127.0.0.1. It needs -ConfirmStartListeners and your approval.' }
    if (-not $RunDir) { throw '-RunDir (the run folder printed by Phase A) is required for Phase B' }
    $work = Get-WorkRoot $WorkRoot
    Assert-WorkRootSafe $work
    $script:WorkRootResolved = $work
    $runRoot = [System.IO.Path]::GetFullPath($RunDir).TrimEnd('\')
    if (-not (Test-PathInside $runRoot $work)) { throw 'RunDir is not inside the work folder' }
    $tree = Join-Path $runRoot 'tree'
    $pa = [System.IO.File]::ReadAllText((Join-Path $runRoot 'phaseA_manifest.json'), $script:Cp3Utf8) | ConvertFrom-Json
    $ev = Join-Path $EvidenceRoot 'phaseB'
    if (Test-Path -LiteralPath $ev) { throw "Refusing: the evidence folder already exists: $ev" }
    New-Item -ItemType Directory -Force -Path $ev | Out-Null
    $script:Evidence = $ev
    $script:RunRootForLog = $runRoot
    $logs = Join-Path $runRoot 'logs'
    $wd = Join-Path $runRoot 'wd'
    New-Item -ItemType Directory -Force -Path $logs, $wd | Out-Null
    $pidFile = Join-Path $runRoot 'pids.tsv'
    Say ('CP3 Phase B  run folder ' + $runRoot)

    # ---- B1 everything Phase A produced must be byte-identical
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($p in $pa.scripts.PSObject.Properties) { if ((Get-Sha256Hex (Join-Path $repo ($p.Name -replace '/', '\'))) -ne $p.Value) { $bad.Add('script changed since Phase A: ' + $p.Name) } }
    foreach ($p in $pa.toolClasses.PSObject.Properties) { if ((Get-Sha256Hex (Join-Path $runRoot ($p.Name -replace '/', '\'))) -ne $p.Value) { $bad.Add('tool class changed: ' + $p.Name) } }
    $treeNow = Get-Cp3ManifestDigest (Get-Cp3TreeManifest $tree)
    if ($treeNow -ne $pa.treeDigestAfterBuild) { $bad.Add('the scratch tree differs from the Phase A manifest') }
    foreach ($f in @($pa.disposableDbPristine.files)) { if ((Get-Sha256Hex (Join-Path $pa.disposableDbPristine.dir $f.name)) -ne $f.sha256) { $bad.Add('Phase B database copy changed: ' + $f.name) } }
    if ((Get-Sha256Hex (Join-Path $repo 'tests\baseline\cp3_expectations.json')) -ne $pa.expectationsSha256) { $bad.Add('the frozen expectations differ') }
    if ((Get-Cp3RealJavaExe) -ine [string]$pa.javaExe) { $bad.Add('the JVM changed since Phase A') }
    if ($bad.Count -gt 0) { Stop-WithFailure 'B1' 'Phase A manifest verification' ($bad -join '; ') }
    Add-Step 'B1' 'scripts, tools, scratch tree, database copy and frozen expectations are byte-identical to the Phase A manifest' 'PASS' ''

    # ---- B2 preflight and baselines
    $pf = Get-Cp3Preflight 'Phase B'
    Write-Cp3Text (Join-Path $ev '00_preflight.txt') $pf.Lines
    if ($pf.Problems.Count -gt 0) { Stop-WithFailure 'B2' 'preflight' ($pf.Problems -join '; ') }
    $liveStamps = $pf.DbStamps
    $dbPaths = Get-Cp3LiveDbPaths
    $orig = Read-Cp3Manifest $OriginalManifest
    $origStart = @(Get-Cp3ManifestMismatches $repo $orig)
    if ($origStart.Count -gt 0) { Stop-WithFailure 'B2' ('the original ' + $orig.Count + ' files equal the original manifest before the run') ($origStart -join ', ') }
    # the two result files are created by this run; an existing file of that name is never overwritten
    foreach ($rf in @('cp3_results.json', 'cp3_results.md')) {
        if (Test-Path -LiteralPath (Join-Path $repo ('tests\baseline\' + $rf))) { Stop-WithFailure 'B2' 'no earlier result file in tests\baseline' ('refusing to overwrite the existing ' + $rf) }
    }
    $projBefore = Get-Cp3ProjectLines
    $protBefore = Get-Cp3ProtectedLines
    Write-Cp3Text (Join-Path $ev '00_project_manifest_phaseB_start.txt') $projBefore
    Write-Cp3Text (Join-Path $ev '00_protected_set_phaseB_start.txt') $protBefore
    Add-Step 'B2' 'preflight; the original files equal the original manifest' 'PASS' ''

    $job = New-Cp3Job
    $expect = New-Cp3Expect
    $mon = New-Cp3Monitor -PidFile $pidFile -Job $job -Expect $expect -LivePaths $dbPaths -LiveStamps $liveStamps -AuditFile (Join-Path $ev '02_listener_audit.txt') -Ports $script:Cp3TestPorts -ExpectedListeners @{ api = 19000; pdp = 18443; pep = 15000 } -WatchdogSec 600 -AuditEverySec 5
    $tick = { Invoke-Cp3MonitorTick $mon }.GetNewClosure()
    $ctx = $null
    $started = New-Object System.Collections.Generic.List[object]
    $summary = $null
    $finalDone = $false
    $redactor = New-Cp3Redactor
    $creds = $null
    $cpDb = $null
    $flags = @()
    $dbFile = ''
    $digestBefore = @{}
    $stopResults = New-Object System.Collections.Generic.List[string]
    $shutdownErrors = New-Object System.Collections.Generic.List[string]
    $jobLeft = @()
    $survivors = @()
    $auditNote = ''
    $post = $null
    try {
        # ---- B3 credentials: generated now, kept in memory only, written to the disposable database through stdin
        $java = Get-Cp3RealJavaExe
        $jars = @(Get-ChildItem -LiteralPath (Join-Path $tree 'lib') -Filter '*.jar' -File | Sort-Object Name | ForEach-Object { $_.FullName })
        $flags = @($pa.jdkFlagsForTools)
        $cpSeed = @((Join-Path $runRoot 'tools')) + $jars
        $cpDb = @((Join-Path $tree 'build\tools')) + $jars
        $dbFile = Join-Path $pa.disposableDbPristine.dir 'zero_trust.db'
        $v = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('verify', $dbFile) '' $flags $runRoot
        if ($v.ExitCode -ne 0) { Stop-WithFailure 'B3' 'fixture facts on the Phase B database copy' 'a fixture fact does not hold' }
        $users = @('dr_alice', 'nurse_bob', 'front_carol', 'audit_dan')
        $creds = @{}
        foreach ($u in $users) { $creds[$u] = @{ Password = (New-Cp3Password); Pin = (New-Cp3Pin) } }
        $stdin = (($users | ForEach-Object { $_ + "`t" + $creds[$_].Password + "`t" + $creds[$_].Pin }) -join "`n") + "`n"
        $rs = Get-Cp3JavaTool $cpSeed 'SeedTestUsers' @('reset', $dbFile) $stdin $flags $runRoot
        if ($rs.ExitCode -ne 0) { Stop-WithFailure 'B3' 'credential reset in the disposable database' 'reset failed' }
        $g0 = Get-Cp3JavaTool $cpDb 'DbTool' @('digest', $dbFile) '' $flags $runRoot
        Write-Cp3Text (Join-Path $ev '01_db_digest_before_run.txt') @($g0.StdOut -split "`r?`n")
        $digestBefore = ConvertFrom-Cp3Digest $g0.StdOut
        Add-Step 'B3' 'fixture facts verified; 4 credential pairs generated (memory only) and stored as hashes in the disposable database' 'PASS' ''

        # ---- B4 start the four programs, one after the other. From the first start on the run-state monitor watches the processes during every wait.
        $script:Cp3AllowLegacyLaunch = $true
        $mingw = Split-Path -Parent (Find-Tool 'g++')
        $env:PATH = $mingw + ';' + $env:PATH
        $plan = @(Get-Cp3LaunchPlan -Tree $tree -JavaExe $java -JavaFlags @($pa.jdkFlagsForTools))
        $planApi = @($plan | Where-Object { $_.Role -eq 'api' })[0]
        $planPdp = @($plan | Where-Object { $_.Role -eq 'pdp' })[0]
        $planPep = @($plan | Where-Object { $_.Role -eq 'pep' })[0]
        $planAgent = @($plan | Where-Object { $_.Role -eq 'agent' })[0]
        $api = Start-Cp3Process -Role $planApi.Role -Kind $planApi.Kind -File $planApi.File -Arguments $planApi.Arguments -WorkingDirectory $wd -StdOutPath (Join-Path $logs 'api.out.log') -StdErrPath (Join-Path $logs 'api.err.log') -Job $job -PidFile $pidFile -TreeRoot $tree
        $started.Add($api)
        Set-Cp3RoleStarted $expect 'api'
        if ($null -eq (Wait-Cp3Listener -Port 19000 -ExpectedPid $api.Pid -TimeoutSec 40 -Tick $tick)) { Stop-WithFailure 'B4' 'API listening on 127.0.0.1:19000' 'no listener within 40 s' }
        Invoke-Cp3MonitorAudit $mon 'after the API started'
        $pdp = Start-Cp3Process -Role $planPdp.Role -Kind $planPdp.Kind -File $planPdp.File -Arguments $planPdp.Arguments -WorkingDirectory $wd -StdOutPath (Join-Path $logs 'pdp.out.log') -StdErrPath (Join-Path $logs 'pdp.err.log') -Job $job -PidFile $pidFile -TreeRoot $tree
        $started.Add($pdp)
        Set-Cp3RoleStarted $expect 'pdp'
        if ($null -eq (Wait-Cp3Listener -Port 18443 -ExpectedPid $pdp.Pid -TimeoutSec 40 -Tick $tick)) { Stop-WithFailure 'B4' 'PDP listening on 127.0.0.1:18443' 'no listener within 40 s' }
        Invoke-Cp3MonitorAudit $mon 'after the PDP started'
        $seq = @{ agent = 0; pep = 1 }
        $pep = Start-Cp3Process -Role $planPep.Role -Kind $planPep.Kind -File $planPep.File -Arguments $planPep.Arguments -WorkingDirectory $wd -StdOutPath (Join-Path $logs 'pep.out.log') -StdErrPath (Join-Path $logs 'pep.err.log') -Job $job -PidFile $pidFile -TreeRoot $tree
        $started.Add($pep)
        Set-Cp3RoleStarted $expect 'pep'
        if ($null -eq (Wait-Cp3Listener -Port 15000 -ExpectedPid $pep.Pid -TimeoutSec 30 -Tick $tick)) { Stop-WithFailure 'B4' 'PEP listening on 127.0.0.1:15000' 'no listener within 30 s' }
        Invoke-Cp3MonitorAudit $mon 'after the PEP started'
        # the starters used for the first start (agent) and for every restart; they return $true when the program is ready
        $startAgent = {
            $seq.agent++
            $n = $seq.agent
            $rec = Start-Cp3Process -Role $planAgent.Role -Kind $planAgent.Kind -File $planAgent.File -Arguments $planAgent.Arguments -WorkingDirectory $wd -StdOutPath (Join-Path $logs "agent$n.out.log") -StdErrPath (Join-Path $logs "agent$n.err.log") -Job $job -PidFile $pidFile -TreeRoot $tree
            $started.Add($rec)
            if ($n -eq 1) { Set-Cp3RoleStarted $expect 'agent' }
            return (Wait-Cp3LogMatch (Join-Path $logs "agent$n.out.log") 'heartbeat:.*HTTP 200' 30 -Tick $tick)
        }.GetNewClosure()
        $startPep = {
            $seq.pep++
            $n = $seq.pep
            $rec = Start-Cp3Process -Role $planPep.Role -Kind $planPep.Kind -File $planPep.File -Arguments $planPep.Arguments -WorkingDirectory $wd -StdOutPath (Join-Path $logs "pep$n.out.log") -StdErrPath (Join-Path $logs "pep$n.err.log") -Job $job -PidFile $pidFile -TreeRoot $tree
            $started.Add($rec)
            return ($null -ne (Wait-Cp3Listener -Port 15000 -ExpectedPid $rec.Pid -TimeoutSec 30 -Tick $tick))
        }.GetNewClosure()
        if (-not (& $startAgent)) { Stop-WithFailure 'B4' 'agent heartbeat accepted by the PDP' 'no HTTP 200 heartbeat within 30 s' }
        Invoke-Cp3MonitorAudit $mon 'after the agent started'
        $deviceId = $null
        $t1 = Read-Cp3SharedText (Join-Path $logs 'agent1.out.log')
        if ($t1 -match 'device_id = (DEV-\S+)') { $deviceId = $Matches[1] }
        if (-not $deviceId -or $deviceId -cne ('DEV-' + $env:COMPUTERNAME)) { Stop-WithFailure 'B4' 'device id' 'the agent device id is missing or differs from DEV-<computer name>' }
        Add-Step 'B4' 'API, PDP, PEP and agent started on 127.0.0.1 only; run-state monitor and loopback audit clean after each start' 'PASS' ''

        # ---- B5 the scenarios. The guard runs before every request, the wait hook at the start of every slice of at most one second of every wait.
        Set-Cp3WatchdogLimit $mon 900
        $guard = { Invoke-Cp3MonitorGuard $mon }.GetNewClosure()
        Set-Cp3WaitHook ({ Invoke-Cp3MonitorWait $mon }.GetNewClosure())
        $control = New-Cp3Controls -Mon $mon -StartAgent $startAgent -StartPep $startPep
        $exp = Read-Cp3Expectations (Join-Path $repo 'tests\baseline\cp3_expectations.json')
        $send = { param($bytes) Send-Cp3Raw -RequestBytes $bytes }
        $ctx = New-Cp3Context -Expectations $exp -Send $send -Guard $guard -Control $control -Device $deviceId -Creds $creds -Redactor $redactor
        Invoke-Cp3AllScenarios $ctx
        Clear-Cp3WaitHook
        $summary = Get-Cp3Summary $ctx
        Add-Step 'B5' 'the 30 frozen steps were executed' 'PASS' ('baseline PASS ' + $summary.BaselinePass + ', FAIL ' + $summary.BaselineFail + ', observation ' + $summary.Observation + '; predictions held ' + $summary.PredictionHeld + ' of ' + $summary.Steps)

        # ---- B6 before shutdown: every planned-exit window closed, all four roles running, one more tick and one more full audit
        Invoke-Cp3MonitorFinal $mon
        $finalDone = $true
        Add-Step 'B6' 'run-state monitor: no unexpected exit, no unexpected job member, live database untouched, every audit clean (including the audit before shutdown)' 'PASS' ('ticks ' + $mon.Ticks + ', requests guarded ' + $mon.Requests + ', full audits ' + $mon.Audits)
    } finally {
        # ---- shutdown: always, in reverse order, by recorded pid only; nothing here replaces the error that stopped the run
        Clear-Cp3WaitHook
        $script:Cp3AllowLegacyLaunch = $false
        if (-not $finalDone -and @(Read-Cp3PidFile $pidFile).Count -gt 0) {
            try { Invoke-Cp3MonitorAudit $mon 'before shutdown (the run stopped early)' } catch { $auditNote = 'audit before shutdown on the early-stop path: ' + $_.Exception.Message }
        }
        $stopLines = New-Object System.Collections.Generic.List[string]
        $stopLines.Add('processes started by this run: ' + (($started | ForEach-Object { $_.Role + ' pid ' + $_.Pid }) -join ', '))
        try {
            foreach ($rec in @(Read-Cp3PidFile $pidFile | Sort-Object -Property StartUtcTicks -Descending)) {
                $res = ('{0,-6} pid {1,6}: {2}' -f $rec.Role, $rec.Pid, (Stop-Cp3Recorded $rec))
                $stopResults.Add($res)
                $stopLines.Add($res)
            }
        } catch { $shutdownErrors.Add('stop loop: ' + $_.Exception.Message) }
        # the Job Object also holds the console host (conhost.exe) that Windows creates for every hidden console program; it is tolerated while it ends by itself
        try {
            $drain = (Get-Date).AddSeconds(5)
            do {
                $jobLeft = @(Get-Cp3JobLeftovers $job $pidFile)
                if ($jobLeft.Count -eq 0) { break }
                Start-Sleep -Milliseconds 300
            } while ((Get-Date) -lt $drain)
            $stopLines.Add('job members left after the stop loop (recorded, or unrecorded and not an acceptable console host): ' + $jobLeft.Count)
        } catch { $shutdownErrors.Add('job leftover check: ' + $_.Exception.Message) }
        $jobSnapshot = @()
        try { $jobSnapshot = @(Get-Cp3JobSnapshot $job) } catch { $shutdownErrors.Add('job snapshot: ' + $_.Exception.Message) }
        try { Close-Cp3Job $job } catch { $shutdownErrors.Add('closing the Job Object: ' + $_.Exception.Message) }
        try {
            $drain2 = (Get-Date).AddSeconds(5)
            do {
                $survivors = @(Get-Cp3SnapshotSurvivors $jobSnapshot)
                if ($survivors.Count -eq 0) { break }
                Start-Sleep -Milliseconds 300
            } while ((Get-Date) -lt $drain2)
            $stopLines.Add('former job members still running 5 s after the job was closed: ' + $survivors.Count)
        } catch { $shutdownErrors.Add('survivor check: ' + $_.Exception.Message) }
        if ($null -ne $ctx -and $ctx.Results.Count -gt 0) {
            try {
                [System.IO.File]::WriteAllText((Join-Path $ev 'partial_results.json'), (ConvertTo-Json -InputObject $ctx.Results.ToArray() -Depth 8), $script:Cp3Utf8)
                Write-Cp3Text (Join-Path $ev 'partial_transcript_redacted.txt') $ctx.Transcript.ToArray()
            } catch { $shutdownErrors.Add('partial results: ' + $_.Exception.Message) }
        }
        Write-Cp3Text (Join-Path $ev '03_shutdown.txt') $stopLines.ToArray()
        # C5 also on the early-stop path: what exists (evidence so far, partial results, program logs) is scanned; the outcome is reported, never hidden
        if (-not $finalDone) {
            try {
                $litE = Get-Cp3SensitiveLiterals (Join-Path $tree 'protected_app\src\app\seed\PatientSeeder.java') (Get-Cp3IssuedLiterals $creds $redactor)
                $targetsE = @([pscustomobject]@{ Label = 'evidence (phase B, stopped early)'; Path = $ev })
                if (@(Get-ChildItem -LiteralPath $logs -File -ErrorAction SilentlyContinue).Count -gt 0) { $targetsE += [pscustomobject]@{ Label = 'program logs'; Path = $logs } }
                $scanE = Invoke-Cp3SensitiveScan -Targets $targetsE -Literals $litE -ReportPath (Join-Path $ev '06_sensitive_data_scan_early_stop.txt') -Title 'CP3 PHASE B (stopped early) - sensitive-data scan (C5)'
                $probE = @(Get-Cp3SensitiveScanProblems $scanE)
                Say ('SENSITIVE-DATA SCAN after an early stop: ' + $probE.Count + ' problem(s); report: ' + (Join-Path $ev '06_sensitive_data_scan_early_stop.txt'))
                foreach ($x in $probE) { Say ('  PROBLEM ' + $x) }
            } catch { $shutdownErrors.Add('sensitive-data scan on the early-stop path: ' + $_.Exception.Message); Say ('SENSITIVE-DATA SCAN after an early stop could not be completed: ' + $_.Exception.Message) }
        }
        Start-Sleep -Seconds 3
        # ---- B7 (C4) verification after the programs are gone. On the early-stop path the report is still written and its problems are shown.
        try {
            $postIn = [pscustomobject]@{
                PidFile = $pidFile; RunRoot = $runRoot; Tree = $tree; TreeDigest = [string]$pa.treeDigestAfterBuild; LiveStamps = $liveStamps; DbPaths = $dbPaths
                ProjBefore = $projBefore; ProtBefore = $protBefore; Orig = $orig; StopResults = $stopResults.ToArray(); ShutdownErrors = $shutdownErrors.ToArray()
                JobLeft = @($jobLeft); Survivors = @($survivors); AuditNote = $auditNote; WerBefore = $pf.WerCount; CpDb = $cpDb; DbFile = $dbFile; Flags = $flags; DigestBefore = $digestBefore
            }
            $post = Get-Cp3PostRunReport $postIn
            Write-Cp3Text (Join-Path $ev '04_postflight.txt') $post.Lines
            if (-not $finalDone) {
                Say ''
                Say ('POST-RUN VERIFICATION after an early stop: ' + $post.Problems.Count + ' problem(s); report: ' + (Join-Path $ev '04_postflight.txt'))
                foreach ($x in $post.Problems) { Say ('  PROBLEM ' + $x) }
            }
        } catch {
            $shutdownErrors.Add('post-run report: ' + $_.Exception.Message)
            Say ('POST-RUN VERIFICATION could not be completed: ' + $_.Exception.Message)
        }
    }

    # ---- B7 gate (reached only when B1-B6 passed)
    if ($null -eq $post) { Stop-WithFailure 'B7' 'post-run verification' ('the report could not be produced: ' + ($shutdownErrors -join '; ')) }
    if ($post.Problems.Count -gt 0) { Stop-WithFailure 'B7' 'post-run verification: every recorded process has exited, cleanup succeeded, originals / backup / project / protected set / live database / scratch tree unchanged' ($post.Problems -join ' | ') }
    Add-Step 'B7' 'post-run verification: every recorded process has exited, cleanup succeeded, no job leftover, originals, project, protected set, live database and scratch tree unchanged, disposable database intact' 'PASS' ('see 04_postflight.txt; ' + $stopResults.Count + ' stop result(s)')

    # ---- B8 results (redacted) -> evidence and tests\baseline, then the C5 scan of evidence, test results and program logs
    $json = ConvertTo-Json -InputObject ([ordered]@{ summary = $summary; results = $ctx.Results.ToArray(); retriedFirstAttempts = $ctx.Retried.ToArray(); notes = $ctx.Notes.ToArray() }) -Depth 8
    $md = Format-Cp3ResultsMarkdown $ctx $summary
    foreach ($dir in @($ev, (Join-Path $repo 'tests\baseline'))) {
        [System.IO.File]::WriteAllText((Join-Path $dir 'cp3_results.json'), $json, $script:Cp3Utf8)
        Write-Cp3Text (Join-Path $dir 'cp3_results.md') $md
    }
    Write-Cp3Text (Join-Path $ev '05_transcript_redacted.txt') $ctx.Transcript.ToArray()
    $lit = Get-Cp3SensitiveLiterals (Join-Path $tree 'protected_app\src\app\seed\PatientSeeder.java') (Get-Cp3IssuedLiterals $creds $redactor)
    $targetsB = @(
        [pscustomobject]@{ Label = 'evidence (phase B)'; Path = $ev },
        [pscustomobject]@{ Label = 'program logs'; Path = $logs },
        [pscustomobject]@{ Label = 'tests\baseline'; Path = (Join-Path $repo 'tests\baseline') }
    )
    $scanB = Invoke-Cp3SensitiveScan -Targets $targetsB -Literals $lit -ReportPath (Join-Path $ev '06_sensitive_data_scan.txt') -Title 'CP3 PHASE B - sensitive-data scan (C5)'
    $scanBProblems = @(Get-Cp3SensitiveScanProblems $scanB)
    if ($scanBProblems.Count -gt 0) { Stop-WithFailure 'B8' 'no synthetic patient marker, issued value or credential-shaped text in the evidence, test results and program logs' ($scanBProblems -join ' | ') }
    Add-Step 'B8' 'results written (redacted); sensitive-data scan of evidence, test results and program logs: 0 patient markers, 0 issued values, 0 credential-shaped strings' 'PASS' ('files scanned: ' + (($scanB.Targets | ForEach-Object { $_.Label + ' ' + $_.Files }) -join ', '))

    # ---- B9 final integrity after the result files exist: the project differs from its start by exactly the two result files, nothing else changed
    $projEnd = @(Get-Cp3ProjectLines)
    $dEnd = @(Compare-Cp3Lines $projBefore $projEnd)
    $unexpected = @($dEnd | Where-Object { $_ -notmatch '^only after : \S+\s+\d+\s+tests/baseline/cp3_results\.(json|md)$' })
    $finalProblems = New-Object System.Collections.Generic.List[string]
    foreach ($x in $unexpected) { $finalProblems.Add('project: ' + $x) }
    if ($dEnd.Count -ne 2) { $finalProblems.Add('the project differs from its start in ' + $dEnd.Count + ' line(s); exactly 2 (the two new result files) are expected') }
    foreach ($x in @(Get-Cp3ManifestMismatches $repo $orig)) { $finalProblems.Add('original file: ' + $x) }
    foreach ($x in @(Compare-Cp3Lines $protBefore @(Get-Cp3ProtectedLines))) { $finalProblems.Add('protected set: ' + $x) }
    foreach ($x in @(Compare-Cp3FileStamps $liveStamps (Get-Cp3FileStamps $dbPaths))) { $finalProblems.Add('live database file changed (stamp): ' + $x) }
    foreach ($f in @('cp3_results.json', 'cp3_results.md')) {
        if ((Get-Sha256Hex (Join-Path $ev $f)) -ne (Get-Sha256Hex (Join-Path $repo ('tests\baseline\' + $f)))) { $finalProblems.Add('the copy of ' + $f + ' in tests\baseline differs from the evidence copy') }
    }
    Write-Cp3Text (Join-Path $ev '07_final_integrity.txt') (@('FINAL INTEGRITY (after the result files were written)', ('project lines at the start / now: ' + @($projBefore).Count + ' / ' + $projEnd.Count), 'differing lines (expected: exactly the two new result files):') + $dEnd + @('', ('problems: ' + $finalProblems.Count)) + @($finalProblems | ForEach-Object { '  PROBLEM ' + $_ }))
    if ($finalProblems.Count -gt 0) { Stop-WithFailure 'B9' 'final integrity: only the two result files were added; originals, protected set and live database unchanged' ($finalProblems -join ' | ') }
    Add-Step 'B9' 'final integrity: the project differs from its start only by the two result files; originals, protected set and live database unchanged' 'PASS' ''
    Write-Cp3ResultsFile (Join-Path $ev 'CP3B_RESULTS.txt') 'CP3 PHASE B RESULTS'
    Say ''
    Say ('PHASE B finished. Baseline PASS ' + $summary.BaselinePass + ', FAIL ' + $summary.BaselineFail + ', observation ' + $summary.Observation + '; predictions held ' + $summary.PredictionHeld + ' of ' + $summary.Steps)
}

# ======================================================================== MAIN
try {
    if ($Phase -eq 'A') { Invoke-PhaseA } else { Invoke-PhaseB }
    exit 0
} catch {
    Write-Host ''
    Write-Host ('STOPPED: ' + $_.Exception.Message)
    if ($script:Evidence) {
        try { Write-Cp3ResultsFile (Join-Path $script:Evidence 'RESULTS_STOPPED.txt') ('CP3 PHASE ' + $Phase + ' STOPPED') } catch { }
    }
    exit 1
}
