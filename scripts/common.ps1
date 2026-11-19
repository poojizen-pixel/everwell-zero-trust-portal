# Shared helpers for the build and test scripts.  Dot-source it:  . "$PSScriptRoot\common.ps1"
# Written for Windows PowerShell 5.1 (no ternary operator, no ??, no &&). Keep this file ASCII-only.
Set-StrictMode -Version 2.0

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path.TrimEnd('\')

function Get-RepoRoot { return $script:RepoRoot }

function Find-Tool([string]$Name) {
    $c = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    return $null
}

# Builds a Windows command line from separate arguments (CommandLineToArgvW quoting rules).
function ConvertTo-ArgString([string[]]$Arguments) {
    $parts = foreach ($a in $Arguments) {
        if ($a.Length -gt 0 -and $a -notmatch '[\s"]') { $a }
        else {
            $s = $a -replace '(\\*)"', '$1$1\"'
            $s = $s -replace '(\\+)$', '$1$1'
            '"' + $s + '"'
        }
    }
    return ($parts -join ' ')
}

# Runs a native program without PowerShell turning stderr lines into error records.
# Returns ExitCode, TimedOut, StdOut, StdErr and Seconds. A timeout kills the process and reports ExitCode -1.
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = (Get-Location).Path,
        [int]$TimeoutSec = 300
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = ConvertTo-ArgString $Arguments
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    [void]$p.Start()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        $timedOut = $true
        try { $p.Kill() } catch { }
        [void]$p.WaitForExit(5000)
    }
    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)
    $sw.Stop()
    $code = -1
    if (-not $timedOut) { $code = $p.ExitCode }
    return [pscustomobject]@{
        ExitCode = $code
        TimedOut = $timedOut
        StdOut   = $outTask.Result
        StdErr   = $errTask.Result
        Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

function Get-ToolVersion([string]$Tool, [string[]]$VersionArgs) {
    $p = Find-Tool $Tool
    if (-not $p) { return 'not found' }
    $r = Invoke-Native -File $p -Arguments $VersionArgs -TimeoutSec 30
    $t = ($r.StdOut + $r.StdErr).Trim()
    if (-not $t) { return 'no output' }
    return ($t -split "`r?`n")[0]
}

# Test verdicts are exactly one of: PASS, FAIL, NOT RUN. Nothing else is accepted.
function New-Result([string]$Id, [string]$Name, [string]$Status, [string]$Detail, [double]$Seconds = 0) {
    if ($Status -notin @('PASS', 'FAIL', 'NOT RUN')) { throw "invalid verdict '$Status'" }
    return [pscustomobject]@{ Id = $Id; Name = $Name; Status = $Status; Seconds = [math]::Round($Seconds, 1); Detail = $Detail }
}

function Get-Sha256Hex([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() }

function Test-PathInside([string]$Path, [string]$Parent) {
    $p = [System.IO.Path]::GetFullPath($Path).TrimEnd('\') + '\'
    $q = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    return $p.StartsWith($q, [System.StringComparison]::OrdinalIgnoreCase)
}

# The live database folder of the project is never a source or target for tests and backups.
function Assert-NotProjectDb([string]$Path) {
    $live = Join-Path (Get-RepoRoot) 'db'
    if (Test-PathInside $Path $live) {
        throw "Refusing: '$Path' is inside the project's live db folder. Use a verified copy (scripts\new-disposable-db.ps1)."
    }
}

# Disposable databases and other test scratch files live OUTSIDE the repository by default.
function Get-WorkRoot([string]$Override) {
    if ($Override) { return [System.IO.Path]::GetFullPath($Override) }
    if ($env:ZT_WORK_ROOT) { return [System.IO.Path]::GetFullPath($env:ZT_WORK_ROOT) }
    return (Join-Path ([System.IO.Path]::GetTempPath()) 'zt-his-work')
}

function Assert-WorkRootSafe([string]$Work) {
    $root = Get-RepoRoot
    if ((Test-PathInside $Work $root) -and -not (Test-PathInside $Work (Join-Path $root 'build'))) {
        throw "Refusing: the work folder '$Work' is inside the repository. Use a folder outside it, or <repo>\build."
    }
}

function New-RunId { return ((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + (Get-Random -Maximum 10000).ToString('0000')) }

# Existing third-party jars (sqlite-jdbc, gson) already in lib/. No download is ever done by these scripts.
function Get-JavaClasspath {
    $lib = Join-Path (Get-RepoRoot) 'lib'
    $jars = @(Get-ChildItem -LiteralPath $lib -Filter '*.jar' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.FullName })
    return ($jars -join ';')
}
