<#
.SYNOPSIS
  Runs the project's test suites and reports an explicit verdict for each: PASS, FAIL or NOT RUN.
.DESCRIPTION
  Suites:
    cpp                C++ unit tests (tests\cpp\test_*.cpp, built with g++ and the small mini_test.h header)
    scanner            self-test of the secret scanner against planted fake secrets and a clean file (needs Node.js)
    dbtool             database copy / check / backup workflow on a DISPOSABLE copy (needs -DbSource)
    scan-options       check-secrets.ps1 -FailOnPossible and its exit codes, on small fixture folders (needs Node.js)
    backup-options     backup-db.ps1 -AllowProjectDb, run ONLY inside a throw-away copy of the scripts whose db folder
                       holds a disposable fixture database (needs -DbSource)
    harness-selfcheck  proves the runner itself: an injected failing test must exit 1, and NOT RUN must never be reported as PASS
    java-junit         JUnit suites - NOT RUN until the JUnit console jar is approved and added (dependency gate G1)
  Exit code: 0 = no FAIL (and no NOT RUN under -Strict); 1 = at least one FAIL (or a NOT RUN under -Strict); 2 = harness error.
  Database tests only ever use disposable copies below the work folder (outside the repository); the project's db folder
  and the -DbSource folder are only read for file hashes and file copies, never opened by SQLite.
  Nothing is downloaded and no network listener is started.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run-tests.ps1 -DbSource <folder-with-the-verified-db-files>
#>
[CmdletBinding()]
param(
    [ValidateSet('cpp', 'scanner', 'dbtool', 'scan-options', 'backup-options', 'harness-selfcheck', 'java-junit')][string[]]$Suite = @('cpp', 'scanner', 'dbtool', 'scan-options', 'backup-options', 'harness-selfcheck', 'java-junit'),
    [string]$WorkRoot,
    [string]$DbSource,
    [string]$ReportDir,
    [switch]$InjectFailure,
    [switch]$Strict
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
$root = Get-RepoRoot
try {
    $work = Get-WorkRoot $WorkRoot
    Assert-WorkRootSafe $work
    if (-not $ReportDir) { $ReportDir = Join-Path $root 'build\reports' }
    $ReportDir = [System.IO.Path]::GetFullPath($ReportDir)
    if ((Test-PathInside $ReportDir $root) -and -not (Test-PathInside $ReportDir (Join-Path $root 'build'))) {
        throw "Refusing: the report folder must be inside <repo>\build or outside the repository."
    }
    $runId = New-RunId
    $runDir = Join-Path $work $runId
    New-Item -ItemType Directory -Force -Path $runDir, $ReportDir | Out-Null
} catch {
    Write-Host ("HARNESS ERROR: " + $_.Exception.Message)
    exit 2
}

function Test-JUnitJar {
    $j = @(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -Filter 'junit-platform-console-standalone*.jar' -File -ErrorAction SilentlyContinue)
    return ($j.Count -gt 0)
}

# ---------------------------------------------------------------- cpp
function Invoke-CppSuite {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $gpp = Find-Tool 'g++'
    if (-not $gpp) { return (New-Result 'cpp' 'C++ unit tests' 'NOT RUN' 'g++ was not found on PATH') }
    $testDir = Join-Path $root 'tests\cpp'
    $outDir = Join-Path $root 'build\cpp\tests'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $files = @(Get-ChildItem -LiteralPath $testDir -Filter 'test_*.cpp' -File | Sort-Object Name)
    if (-not $InjectFailure) { $files = @($files | Where-Object { $_.Name -ne 'test_selfcheck_fail.cpp' }) }
    if ($files.Count -eq 0) { return (New-Result 'cpp' 'C++ unit tests' 'NOT RUN' 'no tests\cpp\test_*.cpp files found') }
    $problems = New-Object System.Collections.Generic.List[string]
    $tests = 0
    $passed = 0
    foreach ($f in $files) {
        $exe = Join-Path $outDir ($f.BaseName + '.exe')
        $c = Invoke-Native -File $gpp -Arguments @('-std=c++17', '-O0', '-Wall', '-Wextra', '-o', $exe, $f.FullName) -WorkingDirectory $root -TimeoutSec 300
        if ($c.ExitCode -ne 0) { $problems.Add($f.Name + ': compile failed'); continue }
        $r = Invoke-Native -File $exe -WorkingDirectory $root -TimeoutSec 120
        if ($r.TimedOut) { $problems.Add($f.Name + ': timed out'); continue }
        $lines = @($r.StdOut -split "`r?`n")
        $sum = @($lines | Where-Object { $_ -like 'SUMMARY *' } | Select-Object -Last 1)
        if ($sum.Count -eq 0) { $problems.Add($f.Name + ': no SUMMARY line (crash?), exit code ' + $r.ExitCode); continue }
        $m = [regex]::Match($sum[0], 'tests=(\d+) passed=(\d+) failed=(\d+)')
        $tests += [int]$m.Groups[1].Value
        $passed += [int]$m.Groups[2].Value
        if ($r.ExitCode -ne 0 -or $m.Groups[3].Value -ne '0') {
            $failedNames = @($lines | Where-Object { $_ -like 'FAIL *' } | ForEach-Object { $_.Substring(5) })
            $problems.Add($f.Name + ': failed ' + ($failedNames -join ', '))
        }
    }
    $sw.Stop()
    if ($problems.Count -gt 0) {
        return (New-Result 'cpp' 'C++ unit tests' 'FAIL' ("$passed of $tests tests passed; " + ($problems -join '; ')) $sw.Elapsed.TotalSeconds)
    }
    return (New-Result 'cpp' 'C++ unit tests' 'PASS' ("$passed of $tests tests passed in $($files.Count) file(s)") $sw.Elapsed.TotalSeconds)
}

# ---------------------------------------------------------------- scanner
function Invoke-ScannerSuite {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $node = Find-Tool 'node'
    if (-not $node) { return (New-Result 'scanner' 'Secret scanner self-test' 'NOT RUN' 'node was not found on PATH (needed only for the secret scan)') }
    $r = Invoke-Native -File $node -Arguments @((Join-Path $PSScriptRoot 'tools\secret_scan.js'), 'selftest', '--root', (Join-Path $runDir 'scanner-controls'), '--out', (Join-Path $runDir 'scanner-out')) -WorkingDirectory $root -TimeoutSec 120
    $sw.Stop()
    $overall = @($r.StdOut -split "`r?`n" | Where-Object { $_ -like 'OVERALL:*' } | Select-Object -Last 1)
    $text = ''
    if ($overall.Count -gt 0) { $text = $overall[0] }
    if ($r.ExitCode -eq 0 -and $overall.Count -gt 0) {
        return (New-Result 'scanner' 'Secret scanner self-test' 'PASS' ('scanner controls ' + $text) $sw.Elapsed.TotalSeconds)
    }
    return (New-Result 'scanner' 'Secret scanner self-test' 'FAIL' ('exit code ' + $r.ExitCode + '; ' + $text + ' ' + $r.StdErr.Trim()) $sw.Elapsed.TotalSeconds)
}

# ---------------------------------------------------------------- dbtool
function Add-DbCheck([string]$Name, [bool]$Ok, [string]$Why) {
    $script:dbChecks.Add([pscustomobject]@{ Name = $Name; Ok = $Ok; Why = $Why })
}

function Invoke-DbToolSuite {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $name = 'Disposable database workflow'
    $java = Find-Tool 'java'
    $ps = Find-Tool 'powershell.exe'
    if (-not $java -or -not $ps) { return (New-Result 'dbtool' $name 'NOT RUN' 'java or powershell.exe was not found on PATH') }
    $sqlite = @(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -Filter 'sqlite-jdbc*.jar' -File -ErrorAction SilentlyContinue)
    if ($sqlite.Count -eq 0) { return (New-Result 'dbtool' $name 'NOT RUN' 'the sqlite-jdbc jar was not found in lib\') }
    if (-not $DbSource) { return (New-Result 'dbtool' $name 'NOT RUN' 'no -DbSource given (pass the folder that holds a verified copy of zero_trust.db, -wal and -shm)') }
    if (-not (Test-Path -LiteralPath $DbSource)) { return (New-Result 'dbtool' $name 'FAIL' ('-DbSource folder not found: ' + $DbSource)) }
    $srcDir = (Resolve-Path -LiteralPath $DbSource).Path.TrimEnd('\')
    $script:dbChecks = New-Object System.Collections.Generic.List[object]
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File')

    # Everything that must stay byte-identical: the verified source copy and the project's own db files.
    $watch = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $srcDir -File | Where-Object { $_.Name -like 'zero_trust.db*' })) { $watch[$f.FullName] = Get-Sha256Hex $f.FullName }
    foreach ($n in @('zero_trust.db', 'zero_trust.db-wal', 'zero_trust.db-shm')) {
        $p = Join-Path $root ('db\' + $n)
        if (Test-Path -LiteralPath $p) { $watch[$p] = Get-Sha256Hex $p }
    }

    $bt = Invoke-Native -File $ps -Arguments ($psArgs + @((Join-Path $PSScriptRoot 'build.ps1'), '-Component', 'tools')) -WorkingDirectory $root -TimeoutSec 300
    $toolsDir = Join-Path $root 'build\tools'
    Add-DbCheck 'DbTool builds' (($bt.ExitCode -eq 0) -and (Test-Path -LiteralPath (Join-Path $toolsDir 'DbTool.class'))) ('build exit code ' + $bt.ExitCode)
    $jargs = @('--enable-native-access=ALL-UNNAMED', '-cp', ($toolsDir + ';' + (Get-JavaClasspath)), 'DbTool')

    $d = $null
    try { $d = & "$PSScriptRoot\new-disposable-db.ps1" -Source $srcDir -WorkRoot $work -RunId $runId 6>$null } catch { Add-DbCheck 'disposable copy is made' $false $_.Exception.Message }
    $made = ($null -ne $d) -and (Test-Path -LiteralPath $d.DbPath)
    if ($made) { Add-DbCheck 'disposable copy is made and hash-verified' $true ($d.Files -join ', ') }
    if ($made) {
        Add-DbCheck 'the copy is inside the work folder, outside the repository' ((Test-PathInside $d.DbPath $work) -and -not (Test-PathInside $d.DbPath $root)) $d.DbPath
        $c1 = Invoke-Native -File $java -Arguments ($jargs + @('check', $d.DbPath)) -WorkingDirectory $root -TimeoutSec 120
        Add-DbCheck 'check: integrity ok and 0 foreign-key violations on the copy' (($c1.ExitCode -eq 0) -and ($c1.StdOut -match 'integrity_check\s*:\s*ok') -and ($c1.StdOut -match 'foreign_key_check\s*:\s*0 violations')) ('exit code ' + $c1.ExitCode)
        $dg1 = Invoke-Native -File $java -Arguments ($jargs + @('digest', $d.DbPath)) -WorkingDirectory $root -TimeoutSec 120
        Add-DbCheck 'digest lists per-table content hashes' (($dg1.ExitCode -eq 0) -and ($dg1.StdOut -match 'sha256=')) ('exit code ' + $dg1.ExitCode)

        $bk = Join-Path $runDir 'backup'
        New-Item -ItemType Directory -Force -Path $bk | Out-Null
        $bkFile = Join-Path $bk 'zero_trust.backup.db'
        $b = Invoke-Native -File $ps -Arguments ($psArgs + @((Join-Path $PSScriptRoot 'backup-db.ps1'), '-DbPath', $d.DbPath, '-Dest', $bkFile)) -WorkingDirectory $root -TimeoutSec 300
        Add-DbCheck 'backup-db.ps1 writes a backup that verifies table by table' (($b.ExitCode -eq 0) -and ($b.StdOut -match 'BACKUP: OK') -and (Test-Path -LiteralPath $bkFile)) ('exit code ' + $b.ExitCode)
        if (Test-Path -LiteralPath $bkFile) {
            $c2 = Invoke-Native -File $java -Arguments ($jargs + @('check', $bkFile)) -WorkingDirectory $root -TimeoutSec 120
            Add-DbCheck 'check: the backup passes integrity and foreign-key checks' (($c2.ExitCode -eq 0) -and ($c2.StdOut -match 'integrity_check\s*:\s*ok')) ('exit code ' + $c2.ExitCode)
            $dg2 = Invoke-Native -File $java -Arguments ($jargs + @('digest', $bkFile)) -WorkingDirectory $root -TimeoutSec 120
            Add-DbCheck 'backup content equals the copy (per-table digests identical)' (($dg1.StdOut.Trim() -eq $dg2.StdOut.Trim()) -and ($dg1.StdOut.Trim().Length -gt 0)) ''
        }
        $b2 = Invoke-Native -File $ps -Arguments ($psArgs + @((Join-Path $PSScriptRoot 'backup-db.ps1'), '-DbPath', $d.DbPath, '-Dest', $bkFile)) -WorkingDirectory $root -TimeoutSec 120
        Add-DbCheck 'backup-db.ps1 refuses to overwrite an existing backup' (($b2.ExitCode -ne 0) -and (($b2.StdOut + $b2.StdErr) -match 'Refusing')) ('exit code ' + $b2.ExitCode)
    }

    # Guards: the project's live db folder must be refused BEFORE anything opens it.
    $refusedBackup = Join-Path $runDir 'refused-backup.db'
    $g1 = Invoke-Native -File $ps -Arguments ($psArgs + @((Join-Path $PSScriptRoot 'backup-db.ps1'), '-DbPath', (Join-Path $root 'db\zero_trust.db'), '-Dest', $refusedBackup)) -WorkingDirectory $root -TimeoutSec 120
    Add-DbCheck 'backup-db.ps1 refuses the project live db and writes nothing' (($g1.ExitCode -ne 0) -and (($g1.StdOut + $g1.StdErr) -match 'Refusing') -and -not (Test-Path -LiteralPath $refusedBackup)) ('exit code ' + $g1.ExitCode)
    $refusedId = $runId + '-refused'
    $g2 = Invoke-Native -File $ps -Arguments ($psArgs + @((Join-Path $PSScriptRoot 'new-disposable-db.ps1'), '-Source', (Join-Path $root 'db'), '-WorkRoot', $work, '-RunId', $refusedId)) -WorkingDirectory $root -TimeoutSec 120
    Add-DbCheck 'new-disposable-db.ps1 refuses the project live db folder and copies nothing' (($g2.ExitCode -ne 0) -and (($g2.StdOut + $g2.StdErr) -match 'Refusing') -and -not (Test-Path -LiteralPath (Join-Path $work $refusedId))) ('exit code ' + $g2.ExitCode)

    $changed = @()
    foreach ($k in $watch.Keys) {
        if (-not (Test-Path -LiteralPath $k) -or ((Get-Sha256Hex $k) -ne $watch[$k])) { $changed += $k }
    }
    Add-DbCheck ('the verified source copy and the project db files ('  + $watch.Count + ' files) are byte-identical after all steps') ($changed.Count -eq 0) ($changed -join ', ')

    $sw.Stop()
    $lines = @($script:dbChecks | ForEach-Object { $(if ($_.Ok) { 'PASS  ' } else { 'FAIL  ' }) + $_.Name + $(if ($_.Why) { '   [' + $_.Why + ']' } else { '' }) })
    [System.IO.File]::WriteAllLines((Join-Path $ReportDir 'dbtool-checks.txt'), [string[]]$lines)
    $bad = @($script:dbChecks | Where-Object { -not $_.Ok })
    $total = $script:dbChecks.Count
    if ($bad.Count -gt 0) {
        return (New-Result 'dbtool' $name 'FAIL' (($total - $bad.Count).ToString() + " of $total checks passed; failed: " + (($bad | ForEach-Object { $_.Name }) -join '; ')) $sw.Elapsed.TotalSeconds)
    }
    return (New-Result 'dbtool' $name 'PASS' "$total of $total checks passed, all on a disposable copy" $sw.Elapsed.TotalSeconds)
}

# ---------------------------------------------------------------- scan-options and backup-options (fixtures only)
function Add-OptCheck([string]$Name, [bool]$Ok, [string]$Why) {
    $script:optChecks.Add([pscustomobject]@{ Name = $Name; Ok = $Ok; Why = $Why })
}

function Complete-OptSuite([string]$Id, [string]$Name, [string]$ReportFile, $Stopwatch) {
    $Stopwatch.Stop()
    $lines = @($script:optChecks | ForEach-Object { $(if ($_.Ok) { 'PASS  ' } else { 'FAIL  ' }) + $_.Name + $(if ($_.Why) { '   [' + $_.Why + ']' } else { '' }) })
    [System.IO.File]::WriteAllLines((Join-Path $ReportDir $ReportFile), [string[]]$lines)
    $bad = @($script:optChecks | Where-Object { -not $_.Ok })
    $total = $script:optChecks.Count
    if ($bad.Count -gt 0) {
        return (New-Result $Id $Name 'FAIL' (($total - $bad.Count).ToString() + " of $total checks passed; failed: " + (($bad | ForEach-Object { $_.Name }) -join '; ')) $Stopwatch.Elapsed.TotalSeconds)
    }
    return (New-Result $Id $Name 'PASS' "$total of $total checks passed" $Stopwatch.Elapsed.TotalSeconds)
}

# check-secrets.ps1 -FailOnPossible and its exit codes, on small fixture folders built at run time.
function Invoke-ScanOptionsSuite {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $name = 'check-secrets.ps1 options and exit codes (fixture folders)'
    $node = Find-Tool 'node'
    $ps = Find-Tool 'powershell.exe'
    if (-not $node -or -not $ps) { return (New-Result 'scan-options' $name 'NOT RUN' 'node or powershell.exe was not found on PATH') }
    $script:optChecks = New-Object System.Collections.Generic.List[object]
    $q = [string][char]34
    $hex = 'ab' * 32
    $secretValue = ('planted', 'fake', 'secret', 'Zk3x9QpL7vTn2') -join '-'
    $vectorLine = '    Object o = verifier.check(' + $q + $hex + $q + ')'
    $fx = Join-Path $runDir 'scan-option-fixtures'
    $cases = @(
        @{ Case = 'clean'; File = 'Clean.java'; Lines = @('public class Clean {', '    static final int PORT = 5000;', '}'); Plain = 0; WithFlag = 0; Counts = 'CONFIRMED=0 POSSIBLE=0 ALLOWED=0' },
        @{ Case = 'possible'; File = 'Possible.java'; Lines = @('public class Possible {', ($vectorLine + ';'), '}'); Plain = 0; WithFlag = 1; Counts = 'CONFIRMED=0 POSSIBLE=1 ALLOWED=0' },
        @{ Case = 'confirmed'; File = 'Confirmed.java'; Lines = @('public class Confirmed {', ('    static final String HMAC_SECRET = ' + $q + $secretValue + $q + ';'), '}'); Plain = 1; WithFlag = 1; Counts = 'CONFIRMED=1 POSSIBLE=0 ALLOWED=0' },
        @{ Case = 'marker-in-tests'; File = 'tests\Vector.java'; Lines = @('public class Vector {', ($vectorLine + '; // secret-scan: allow public vector'), '}'); Plain = 0; WithFlag = 0; Counts = 'CONFIRMED=0 POSSIBLE=0 ALLOWED=1' },
        @{ Case = 'marker-outside-tests'; File = 'Vector.java'; Lines = @('public class Vector {', ($vectorLine + '; // secret-scan: allow public vector'), '}'); Plain = 0; WithFlag = 1; Counts = 'CONFIRMED=0 POSSIBLE=1 ALLOWED=0' },
        @{ Case = 'marker-without-reason'; File = 'tests\NoReason.java'; Lines = @('public class NoReason {', ($vectorLine + '; // secret-scan: allow'), '}'); Plain = 0; WithFlag = 1; Counts = 'CONFIRMED=0 POSSIBLE=1 ALLOWED=0' }
    )
    $script1 = Join-Path $PSScriptRoot 'check-secrets.ps1'
    foreach ($c in $cases) {
        $dir = Join-Path $fx $c.Case
        $file = Join-Path $dir $c.File
        New-Item -ItemType Directory -Force -Path (Split-Path $file -Parent) | Out-Null
        [System.IO.File]::WriteAllLines($file, [string[]]$c.Lines)
        foreach ($mode in @('plain', 'with -FailOnPossible')) {
            $extra = @()
            $want = $c.Plain
            if ($mode -ne 'plain') { $extra = @('-FailOnPossible'); $want = $c.WithFlag }
            $out = Join-Path $fx ('out\' + $c.Case + '-' + $extra.Count)
            $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script1, '-Path', $dir, '-OutDir', $out, '-WorkRoot', $work) + $extra
            $r = Invoke-Native -File $ps -Arguments $childArgs -WorkingDirectory $root -TimeoutSec 120
            $ok = ($r.ExitCode -eq $want) -and ($r.StdOut -match [regex]::Escape($c.Counts))
            Add-OptCheck ($c.Case + ' / ' + $mode + ': exit code ' + $want + ' with ' + $c.Counts) $ok ('exit code ' + $r.ExitCode)
        }
    }
    return (Complete-OptSuite 'scan-options' $name 'scan-options-checks.txt' $sw)
}

# backup-db.ps1 -AllowProjectDb, exercised ONLY inside a throw-away copy of the scripts whose db folder holds a disposable
# fixture database. The real project db folder is never passed to any command in this suite.
function Invoke-BackupOptionsSuite {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $name = 'backup-db.ps1 -AllowProjectDb (fixture repository only)'
    $java = Find-Tool 'java'
    $ps = Find-Tool 'powershell.exe'
    if (-not $java -or -not $ps) { return (New-Result 'backup-options' $name 'NOT RUN' 'java or powershell.exe was not found on PATH') }
    $sqlite = @(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -Filter 'sqlite-jdbc*.jar' -File -ErrorAction SilentlyContinue)
    if ($sqlite.Count -eq 0) { return (New-Result 'backup-options' $name 'NOT RUN' 'the sqlite-jdbc jar was not found in lib\') }
    if (-not $DbSource) { return (New-Result 'backup-options' $name 'NOT RUN' 'no -DbSource given (pass the folder that holds a verified copy of zero_trust.db, -wal and -shm)') }
    if (-not (Test-Path -LiteralPath $DbSource)) { return (New-Result 'backup-options' $name 'FAIL' ('-DbSource folder not found: ' + $DbSource)) }
    $srcDir = (Resolve-Path -LiteralPath $DbSource).Path.TrimEnd('\')
    $script:optChecks = New-Object System.Collections.Generic.List[object]
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File')

    $watch = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $srcDir -File | Where-Object { $_.Name -like 'zero_trust.db*' })) { $watch[$f.FullName] = Get-Sha256Hex $f.FullName }
    foreach ($n in @('zero_trust.db', 'zero_trust.db-wal', 'zero_trust.db-shm')) {
        $p = Join-Path $root ('db\' + $n)
        if (Test-Path -LiteralPath $p) { $watch[$p] = Get-Sha256Hex $p }
    }

    # The fixture "repository": copies of the real scripts, the jars, and a db folder holding a disposable database.
    $fake = Join-Path $runDir 'fake-repo'
    foreach ($d in @('scripts\tools', 'lib', 'db')) { New-Item -ItemType Directory -Force -Path (Join-Path $fake $d) | Out-Null }
    $copies = @('common.ps1', 'build.ps1', 'backup-db.ps1', 'tools\DbTool.java')
    $identical = $true
    foreach ($f in $copies) {
        $to = Join-Path $fake ('scripts\' + $f)
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $to
        if ((Get-Sha256Hex $to) -ne (Get-Sha256Hex (Join-Path $PSScriptRoot $f))) { $identical = $false }
    }
    foreach ($j in @(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -Filter '*.jar' -File)) { Copy-Item -LiteralPath $j.FullName -Destination (Join-Path $fake 'lib') }
    Add-OptCheck 'the fixture repository holds byte-identical copies of the real scripts being tested' $identical ($copies -join ', ')
    $d = $null
    try { $d = & "$PSScriptRoot\new-disposable-db.ps1" -Source $srcDir -WorkRoot $work -RunId ($runId + '-fixture') 6>$null } catch { Add-OptCheck 'fixture database copy' $false $_.Exception.Message }
    if ($null -eq $d) { return (Complete-OptSuite 'backup-options' $name 'backup-options-checks.txt' $sw) }
    foreach ($f in $d.Files) { Copy-Item -LiteralPath (Join-Path $d.Dir $f) -Destination (Join-Path $fake ('db\' + $f)) }
    $fixtureDb = Join-Path $fake 'db\zero_trust.db'
    $fakeScript = Join-Path $fake 'scripts\backup-db.ps1'
    $bkDir = Join-Path $runDir 'fake-backups'
    New-Item -ItemType Directory -Force -Path $bkDir | Out-Null

    # DbTool (for the digest and integrity checks below) must exist; do not rely on an earlier suite having built it.
    $bt = Invoke-Native -File $ps -Arguments ($psArgs + @((Join-Path $PSScriptRoot 'build.ps1'), '-Component', 'tools')) -WorkingDirectory $root -TimeoutSec 300
    Add-OptCheck 'DbTool is built for the digest and integrity checks' (($bt.ExitCode -eq 0) -and (Test-Path -LiteralPath (Join-Path $root 'build\tools\DbTool.class'))) ('build exit code ' + $bt.ExitCode)

    $a = Join-Path $bkDir 'a.db'
    $r1 = Invoke-Native -File $ps -Arguments ($psArgs + @($fakeScript, '-DbPath', $fixtureDb, '-Dest', $a)) -WorkingDirectory $fake -TimeoutSec 120
    Add-OptCheck 'without -AllowProjectDb the fixture repository db folder is refused and nothing is written' (($r1.ExitCode -ne 0) -and (($r1.StdOut + $r1.StdErr) -match 'Refusing') -and -not (Test-Path -LiteralPath $a)) ('exit code ' + $r1.ExitCode)

    $r2 = Invoke-Native -File $ps -Arguments ($psArgs + @($fakeScript, '-DbPath', $fixtureDb, '-Dest', $a, '-AllowProjectDb')) -WorkingDirectory $fake -TimeoutSec 300
    Add-OptCheck 'with -AllowProjectDb a backup of the fixture database is written and verified' (($r2.ExitCode -eq 0) -and ($r2.StdOut -match 'BACKUP: OK') -and (Test-Path -LiteralPath $a)) ('exit code ' + $r2.ExitCode)
    Add-OptCheck 'the fixture repository built its own DbTool (the real build folder was not used)' (Test-Path -LiteralPath (Join-Path $fake 'build\tools\DbTool.class')) ''

    $toolsDir = Join-Path $root 'build\tools'
    $jargs = @('--enable-native-access=ALL-UNNAMED', '-cp', ($toolsDir + ';' + (Get-JavaClasspath)), 'DbTool')
    if (Test-Path -LiteralPath $a) {
        $dgSrc = Invoke-Native -File $java -Arguments ($jargs + @('digest', $fixtureDb)) -WorkingDirectory $root -TimeoutSec 120
        $dgBk = Invoke-Native -File $java -Arguments ($jargs + @('digest', $a)) -WorkingDirectory $root -TimeoutSec 120
        Add-OptCheck 'the -AllowProjectDb backup equals the fixture database (per-table digests)' (($dgSrc.StdOut.Trim() -eq $dgBk.StdOut.Trim()) -and ($dgSrc.StdOut.Trim().Length -gt 0)) ''
        $ck = Invoke-Native -File $java -Arguments ($jargs + @('check', $a)) -WorkingDirectory $root -TimeoutSec 120
        Add-OptCheck 'the -AllowProjectDb backup passes the integrity and foreign-key checks' (($ck.ExitCode -eq 0) -and ($ck.StdOut -match 'integrity_check\s*:\s*ok')) ''
    }

    $r3 = Invoke-Native -File $ps -Arguments ($psArgs + @($fakeScript, '-DbPath', $fixtureDb, '-Dest', $a, '-AllowProjectDb')) -WorkingDirectory $fake -TimeoutSec 120
    Add-OptCheck '-AllowProjectDb still refuses to overwrite an existing backup' (($r3.ExitCode -ne 0) -and (($r3.StdOut + $r3.StdErr) -match 'Refusing')) ('exit code ' + $r3.ExitCode)

    $inside = Join-Path $fake 'out\b.db'
    $r4 = Invoke-Native -File $ps -Arguments ($psArgs + @($fakeScript, '-DbPath', $fixtureDb, '-Dest', $inside, '-AllowProjectDb')) -WorkingDirectory $fake -TimeoutSec 120
    Add-OptCheck '-AllowProjectDb still refuses a backup destination inside the repository' (($r4.ExitCode -ne 0) -and (($r4.StdOut + $r4.StdErr) -match 'Refusing') -and -not (Test-Path -LiteralPath $inside)) ('exit code ' + $r4.ExitCode)

    $inBuild = Join-Path $fake 'build\bk.db'
    $r5 = Invoke-Native -File $ps -Arguments ($psArgs + @($fakeScript, '-DbPath', $fixtureDb, '-Dest', $inBuild, '-AllowProjectDb')) -WorkingDirectory $fake -TimeoutSec 300
    Add-OptCheck 'the one allowed in-repository destination, <repo>\build, works (positive control)' (($r5.ExitCode -eq 0) -and (Test-Path -LiteralPath $inBuild)) ('exit code ' + $r5.ExitCode)

    $r6 = Invoke-Native -File $ps -Arguments ($psArgs + @($fakeScript, '-DbPath', (Join-Path $fake 'db\missing.db'), '-Dest', (Join-Path $bkDir 'c.db'), '-AllowProjectDb')) -WorkingDirectory $fake -TimeoutSec 120
    Add-OptCheck '-AllowProjectDb with a missing database fails and writes nothing' (($r6.ExitCode -ne 0) -and (($r6.StdOut + $r6.StdErr) -match 'not found') -and -not (Test-Path -LiteralPath (Join-Path $bkDir 'c.db'))) ('exit code ' + $r6.ExitCode)

    $changed = @()
    foreach ($k in $watch.Keys) {
        if (-not (Test-Path -LiteralPath $k) -or ((Get-Sha256Hex $k) -ne $watch[$k])) { $changed += $k }
    }
    Add-OptCheck ('the real project db files and the verified source copy (' + $watch.Count + ' files) are byte-identical after all steps') ($changed.Count -eq 0) ($changed -join ', ')
    return (Complete-OptSuite 'backup-options' $name 'backup-options-checks.txt' $sw)
}

# ---------------------------------------------------------------- harness-selfcheck
function Invoke-SelfCheckSuite {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $name = 'Runner self-check'
    $ps = Find-Tool 'powershell.exe'
    if (-not $ps) { return (New-Result 'harness-selfcheck' $name 'NOT RUN' 'powershell.exe was not found on PATH') }
    $self = Join-Path $PSScriptRoot 'run-tests.ps1'
    $cases = New-Object System.Collections.Generic.List[object]
    $cases.Add(@{ Name = 'an injected failing test makes the run FAIL with exit code 1'; Extra = @('-Suite', 'cpp', '-InjectFailure'); Expect = 1; Id = 'cpp'; Status = 'FAIL' })
    if (-not (Test-JUnitJar)) {
        $cases.Add(@{ Name = 'a NOT RUN suite is reported as NOT RUN and does not fail a normal run (exit 0)'; Extra = @('-Suite', 'java-junit'); Expect = 0; Id = 'java-junit'; Status = 'NOT RUN' })
        $cases.Add(@{ Name = 'a NOT RUN suite fails a -Strict run (exit 1)'; Extra = @('-Suite', 'java-junit', '-Strict'); Expect = 1; Id = 'java-junit'; Status = 'NOT RUN' })
    }
    $bad = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($c in $cases) {
        $i++
        $sub = Join-Path $runDir ('selfcheck-' + $i)
        $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $self) + $c.Extra + @('-WorkRoot', $work, '-ReportDir', (Join-Path $sub 'report'))
        $r = Invoke-Native -File $ps -Arguments $childArgs -WorkingDirectory $root -TimeoutSec 600
        $statusSeen = '(no report)'
        $json = Join-Path $sub 'report\test-results.json'
        if (Test-Path -LiteralPath $json) {
            $data = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
            $row = @($data.results | Where-Object { $_.Id -eq $c.Id })
            if ($row.Count -eq 1) { $statusSeen = [string]$row[0].Status }
        }
        if ($r.ExitCode -ne $c.Expect -or $statusSeen -ne $c.Status) {
            $bad.Add($c.Name + ' [exit code ' + $r.ExitCode + ' (wanted ' + $c.Expect + '), ' + $c.Id + ' was ' + $statusSeen + ' (wanted ' + $c.Status + ')]')
        }
    }
    $sw.Stop()
    if ($bad.Count -gt 0) { return (New-Result 'harness-selfcheck' $name 'FAIL' ($bad -join '; ') $sw.Elapsed.TotalSeconds) }
    return (New-Result 'harness-selfcheck' $name 'PASS' ("$($cases.Count) of $($cases.Count) runner behaviours confirmed in child runs") $sw.Elapsed.TotalSeconds)
}

# ---------------------------------------------------------------- java-junit
function Invoke-JUnitSuite {
    if (-not (Test-JUnitJar)) {
        return (New-Result 'java-junit' 'Java tests (JUnit)' 'NOT RUN' 'the JUnit console jar is not in lib\ (dependency gate G1 has not been granted), and no Java test sources exist yet')
    }
    return (New-Result 'java-junit' 'Java tests (JUnit)' 'NOT RUN' 'the JUnit jar is present, but the Java test sources and the runner step are added in a later checkpoint')
}

# ---------------------------------------------------------------- main
$results = New-Object System.Collections.Generic.List[object]
foreach ($s in $Suite) {
    try {
        switch ($s) {
            'cpp' { $results.Add((Invoke-CppSuite)) }
            'scanner' { $results.Add((Invoke-ScannerSuite)) }
            'dbtool' { $results.Add((Invoke-DbToolSuite)) }
            'scan-options' { $results.Add((Invoke-ScanOptionsSuite)) }
            'backup-options' { $results.Add((Invoke-BackupOptionsSuite)) }
            'harness-selfcheck' { $results.Add((Invoke-SelfCheckSuite)) }
            'java-junit' { $results.Add((Invoke-JUnitSuite)) }
        }
    } catch {
        $results.Add((New-Result $s $s 'FAIL' ('harness exception: ' + $_.Exception.Message)))
    }
}

$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRun = @($results | Where-Object { $_.Status -eq 'NOT RUN' }).Count
$overall = 'PASS'
if ($fail -gt 0 -or ($Strict -and $notRun -gt 0)) { $overall = 'FAIL' }

$table = ($results | Select-Object Id, Status, Seconds, Detail | Format-Table -AutoSize -Wrap | Out-String -Width 220)
Write-Host $table
Write-Host "OVERALL: $overall ($pass pass, $fail fail, $notRun not run)"

$report = [pscustomobject]@{
    generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    runId        = $runId
    workRoot     = $work
    injectFailure = [bool]$InjectFailure
    strict       = [bool]$Strict
    tools        = [pscustomobject]@{
        powershell = $PSVersionTable.PSVersion.ToString()
        javac      = (Get-ToolVersion 'javac' @('-version'))
        gpp        = (Get-ToolVersion 'g++' @('--version'))
        node       = (Get-ToolVersion 'node' @('--version'))
    }
    overall      = $overall
    counts       = [pscustomobject]@{ pass = $pass; fail = $fail; notRun = $notRun }
    results      = $results.ToArray()
}
[System.IO.File]::WriteAllText((Join-Path $ReportDir 'test-results.json'), (ConvertTo-Json -InputObject $report -Depth 5))
[System.IO.File]::WriteAllText((Join-Path $ReportDir 'test-results.txt'), ("OVERALL: $overall ($pass pass, $fail fail, $notRun not run)`r`n`r`n" + $table))
if ($overall -eq 'FAIL') { exit 1 }
exit 0
