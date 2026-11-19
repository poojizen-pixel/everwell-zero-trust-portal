<#
.SYNOPSIS
  Builds the Java and C++ components into build/ without touching the existing out/ folders or binaries.
.DESCRIPTION
  Components: tools (DbTool), pdp, protected_app (javac) and pep_proxy, agent (g++).
  The built programs are NEVER started here (the PEP and the agent open network connections).
  Nothing is downloaded. Exit code: 0 = every selected component built, 1 = a component failed, 2 = a tool is missing.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'tools', 'pdp', 'protected_app', 'pep_proxy', 'agent')][string[]]$Component = @('all'),
    [string]$OutDir,
    [string]$CppStd = 'c++17'
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
$root = Get-RepoRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'build' }
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
if ((Test-PathInside $OutDir $root) -and -not (Test-PathInside $OutDir (Join-Path $root 'build'))) {
    throw "Refusing: the output folder must be <repo>\build or a folder outside the repository."
}
$selected = @($Component)
if ($Component -contains 'all') { $selected = @('tools', 'pdp', 'protected_app', 'pep_proxy', 'agent') }

$javac = Find-Tool 'javac'
$gpp = Find-Tool 'g++'
$needJava = @($selected | Where-Object { $_ -in @('tools', 'pdp', 'protected_app') }).Count -gt 0
$needCpp = @($selected | Where-Object { $_ -in @('pep_proxy', 'agent') }).Count -gt 0
if ($needJava -and -not $javac) { Write-Host 'javac was not found on PATH'; exit 2 }
if ($needCpp -and -not $gpp) { Write-Host 'g++ was not found on PATH'; exit 2 }

New-Item -ItemType Directory -Force -Path (Join-Path $OutDir 'reports') | Out-Null
$cp = Get-JavaClasspath
$results = New-Object System.Collections.Generic.List[object]

function Add-BuildResult([string]$Name, [bool]$Ok, [double]$Seconds, [string]$Detail) {
    $verdict = 'FAIL'
    if ($Ok) { $verdict = 'PASS' }
    $results.Add([pscustomobject]@{ Component = $Name; Status = $verdict; Seconds = [math]::Round($Seconds, 1); Detail = $Detail })
}

function Build-Java([string]$Name, [string]$SrcDir, [string]$MainClass, [string]$ExistingOut, [string]$ListedIn) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $classesDir = Join-Path $OutDir "java\$Name"
    New-Item -ItemType Directory -Force -Path $classesDir | Out-Null
    $files = @(Get-ChildItem -LiteralPath $SrcDir -Recurse -Filter '*.java' -File | Sort-Object FullName | ForEach-Object { $_.FullName })
    $argFile = Join-Path $OutDir "java\$Name.sources.txt"
    $lines = @($files | ForEach-Object { '"' + ($_ -replace '\\', '/') + '"' })
    [System.IO.File]::WriteAllLines($argFile, [string[]]$lines)
    $javacArgs = @('-encoding', 'UTF-8', '-Xlint:all', '-d', $classesDir, '-cp', $cp, ('@' + $argFile))
    $r = Invoke-Native -File $javac -Arguments $javacArgs -WorkingDirectory $root -TimeoutSec 300
    $sw.Stop()
    $log = Join-Path $OutDir "reports\build-$Name.log"
    [System.IO.File]::WriteAllText($log, ($r.StdOut + $r.StdErr))
    if ($r.ExitCode -ne 0) {
        Add-BuildResult $Name $false $sw.Elapsed.TotalSeconds ("javac exit code " + $r.ExitCode + "; see " + $log)
        return
    }
    $warn = ([regex]::Matches($r.StdErr, 'warning:')).Count
    $classes = @(Get-ChildItem -LiteralPath $classesDir -Recurse -Filter '*.class' -File)
    $mainOk = Test-Path -LiteralPath (Join-Path $classesDir $MainClass)
    $detail = "$($files.Count) sources -> $($classes.Count) classes; main class present: $mainOk; javac warnings: $warn"
    # Informational cross-checks against what the project already contains.
    $listFile = Join-Path (Join-Path $root $Name) $ListedIn
    if (Test-Path -LiteralPath $listFile) {
        $listed = @(Get-Content -LiteralPath $listFile | Where-Object { $_.Trim() } | ForEach-Object { (Join-Path (Join-Path $root $Name) $_.Trim()).Replace('/', '\') } | Sort-Object)
        $actual = @($files | Sort-Object)
        $detail += "; sources match $Name/$ListedIn : " + ((($listed -join '|') -eq ($actual -join '|')))
    }
    if ($ExistingOut -and (Test-Path -LiteralPath $ExistingOut)) {
        $a = @($classes | ForEach-Object { $_.FullName.Substring($classesDir.Length + 1).Replace('\', '/') } | Sort-Object)
        $b = @(Get-ChildItem -LiteralPath $ExistingOut -Recurse -Filter '*.class' -File | ForEach-Object { $_.FullName.Substring($ExistingOut.Length + 1).Replace('\', '/') } | Sort-Object)
        $detail += "; same class names as the existing out/ folder: " + (($a -join '|') -eq ($b -join '|')) + " ($($b.Count) there)"
    }
    Add-BuildResult $Name $mainOk $sw.Elapsed.TotalSeconds $detail
}

function Build-Cpp([string]$Name, [string[]]$Sources, [string[]]$Libs) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $dest = Join-Path $OutDir 'cpp'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $exe = Join-Path $dest ($Name + '.exe')
    $cppArgs = @("-std=$CppStd", '-O2', '-Wall', '-Wextra', '-pthread', '-o', $exe) + $Sources + $Libs
    $r = Invoke-Native -File $gpp -Arguments $cppArgs -WorkingDirectory $root -TimeoutSec 600
    $sw.Stop()
    $log = Join-Path $OutDir "reports\build-$Name.log"
    [System.IO.File]::WriteAllText($log, ($r.StdOut + $r.StdErr))
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $exe)) {
        Add-BuildResult $Name $false $sw.Elapsed.TotalSeconds ("g++ exit code " + $r.ExitCode + "; see " + $log)
        return
    }
    $warn = ([regex]::Matches($r.StdErr, 'warning:')).Count
    $dlls = ''
    $objdump = Find-Tool 'objdump'
    if ($objdump) {
        $o = Invoke-Native -File $objdump -Arguments @('-p', $exe) -TimeoutSec 60
        $names = @([regex]::Matches($o.StdOut, 'DLL Name:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $dlls = '; imports: ' + ($names -join ', ')
    }
    Add-BuildResult $Name $true $sw.Elapsed.TotalSeconds ("$($Sources.Count) sources -> $((Get-Item -LiteralPath $exe).Length) bytes; g++ warnings: $warn$dlls")
}

if ($selected -contains 'tools') {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $dest = Join-Path $OutDir 'tools'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $r = Invoke-Native -File $javac -Arguments @('-encoding', 'UTF-8', '-Xlint:all', '-d', $dest, (Join-Path $PSScriptRoot 'tools\DbTool.java')) -WorkingDirectory $root -TimeoutSec 120
    $sw.Stop()
    $ok = ($r.ExitCode -eq 0) -and (Test-Path -LiteralPath (Join-Path $dest 'DbTool.class'))
    $why = 'DbTool.class built'
    if (-not $ok) { $why = 'javac exit code ' + $r.ExitCode + ': ' + $r.StdErr.Trim() }
    Add-BuildResult 'tools' $ok $sw.Elapsed.TotalSeconds $why
}
if ($selected -contains 'pdp') {
    Build-Java 'pdp' (Join-Path $root 'pdp\src') 'pdp\Main.class' (Join-Path $root 'pdp\out') 'sources.txt'
}
if ($selected -contains 'protected_app') {
    Build-Java 'protected_app' (Join-Path $root 'protected_app\src') 'app\Main.class' (Join-Path $root 'protected_app\out') 'sources.txt'
}
if ($selected -contains 'pep_proxy') {
    Build-Cpp 'pep_proxy' @(
        (Join-Path $root 'pep_proxy\src\main.cpp'),
        (Join-Path $root 'pep_proxy\src\HttpServer.cpp'),
        (Join-Path $root 'shared\net\WinHttpClient.cpp')) @('-lws2_32', '-lwinhttp')
}
if ($selected -contains 'agent') {
    Build-Cpp 'agent' @(
        (Join-Path $root 'agent\src\main.cpp'),
        (Join-Path $root 'agent\src\PostureCheck.cpp'),
        (Join-Path $root 'shared\net\WinHttpClient.cpp')) @('-lwinhttp', '-lole32', '-loleaut32', '-lwbemuuid', '-luuid', '-lws2_32')
}

$table = ($results | Format-Table -AutoSize -Wrap | Out-String -Width 240)
Write-Host $table
$versions = @(
    ('javac : ' + (Get-ToolVersion 'javac' @('-version'))),
    ('g++   : ' + (Get-ToolVersion 'g++' @('--version'))),
    ('std   : ' + $CppStd)
)
[System.IO.File]::WriteAllText((Join-Path $OutDir 'reports\build-report.txt'), (($versions -join "`r`n") + "`r`n`r`n" + $table))
[System.IO.File]::WriteAllText((Join-Path $OutDir 'reports\build-report.json'), (ConvertTo-Json -InputObject $results.ToArray() -Depth 3))
$failed = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
if ($failed -gt 0) { Write-Host "BUILD: FAIL ($failed component(s) failed)"; exit 1 }
Write-Host "BUILD: PASS ($($results.Count) component(s))"
exit 0
