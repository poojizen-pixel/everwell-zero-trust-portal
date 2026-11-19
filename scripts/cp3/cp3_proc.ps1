# cp3_proc.ps1 - process control, Job Object and loopback listener audit for the CP3 baseline.
# Dot-source it AFTER cp3_lib.ps1.  Windows PowerShell 5.1, ASCII only.
# Starting a legacy program (kind 'java' or 'cpp') is refused unless $script:Cp3AllowLegacyLaunch is $true.
# Only Run-Cp3.ps1 -Phase B -ConfirmStartListeners ever sets it. Phase A never does.

$script:Cp3AllowLegacyLaunch = $false
$script:Cp3ProcObjects = @{}
$script:Cp3ProcStart = @{}

# ---------------------------------------------------------------- Job Object (kill-on-close safety net)
function Initialize-Cp3JobType {
    if ('Cp3JobNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Cp3JobNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public UInt32 LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public UInt32 ActiveProcessLimit;
        public UIntPtr Affinity;
        public UInt32 PriorityClass;
        public UInt32 SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public UInt64 ReadOperationCount;
        public UInt64 WriteOperationCount;
        public UInt64 OtherOperationCount;
        public UInt64 ReadTransferCount;
        public UInt64 WriteTransferCount;
        public UInt64 OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int infoType, IntPtr lpInfo, uint cbInfo);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, uint cbInfo, IntPtr lpReturnLength);

    public static IntPtr CreateKillOnClose() {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr p = Marshal.AllocHGlobal(len);
        try {
            Marshal.StructureToPtr(info, p, false);
            if (!SetInformationJobObject(job, 9, p, (uint)len)) {
                int e = Marshal.GetLastWin32Error();
                CloseHandle(job);
                throw new System.ComponentModel.Win32Exception(e);
            }
        } finally { Marshal.FreeHGlobal(p); }
        return job;
    }
    public static void Assign(IntPtr job, IntPtr process) {
        if (!AssignProcessToJobObject(job, process)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void Close(IntPtr job) { CloseHandle(job); }
    // JobObjectBasicProcessIdList (3): header = two DWORDs, then ULONG_PTR ProcessIdList[]
    public static long[] GetProcessIds(IntPtr job) {
        int capacity = 512;
        int size = 8 + capacity * IntPtr.Size;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try {
            if (!QueryInformationJobObject(job, 3, buf, (uint)size, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            int n = Marshal.ReadInt32(buf, 4);
            long[] ids = new long[n];
            for (int i = 0; i < n; i++) ids[i] = Marshal.ReadIntPtr(buf, 8 + i * IntPtr.Size).ToInt64();
            return ids;
        } finally { Marshal.FreeHGlobal(buf); }
    }
}
'@
}

function New-Cp3Job { Initialize-Cp3JobType; return [Cp3JobNative]::CreateKillOnClose() }
function Add-Cp3JobProcess([IntPtr]$Job, [System.Diagnostics.Process]$Process) { [Cp3JobNative]::Assign($Job, $Process.Handle) }
function Close-Cp3Job([IntPtr]$Job) { [Cp3JobNative]::Close($Job) }

# Every process that is in the job right now, whoever started it (authoritative: no guessing by parent/child relations).
function Get-Cp3JobPids([IntPtr]$Job) {
    $ids = [Cp3JobNative]::GetProcessIds($Job)
    $out = New-Object System.Collections.Generic.List[int]
    foreach ($i in $ids) { $out.Add([int]$i) }
    return $out.ToArray()
}

# The "java.exe" found on PATH here is Oracle's launcher shim (C:\Program Files\Common Files\Oracle\Java\javapath): it starts the real JVM as a CHILD
# process, so the pid of the shim would not own the listener. The real java.exe is found through java.home and is the only java the launch guard accepts.
$script:Cp3RealJava = $null
function Get-Cp3RealJavaExe {
    if ($script:Cp3RealJava) { return $script:Cp3RealJava }
    $j = Find-Tool 'java'
    if (-not $j) { throw 'java was not found on PATH' }
    Add-Cp3LaunchLog 'tool' $j @('-XshowSettings:properties', '-version')
    $r = Invoke-Native -File $j -Arguments @('-XshowSettings:properties', '-version') -TimeoutSec 60
    $m = [regex]::Match(($r.StdOut + "`n" + $r.StdErr), '(?m)^\s*java\.home\s*=\s*(.+?)\s*$')
    if (-not $m.Success) { throw 'could not read java.home from the JVM' }
    $exe = Join-Path $m.Groups[1].Value.Trim() 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "java.exe not found under java.home: $exe" }
    $script:Cp3RealJava = $exe
    return $exe
}

# ---------------------------------------------------------------- launch guard
# kind 'harmless' : the PowerShell self-test sleeper only (never a legacy program, never a listener)
# kind 'java'     : java.exe + a classpath that lives entirely inside the scratch tree + app.Main or pdp.Main
# kind 'cpp'      : exactly <tree>\build\cpp\pep_proxy.exe or agent.exe, with no arguments
function Assert-Cp3LaunchAllowed {
    param([string]$Kind, [string]$File, [string[]]$Arguments, [string]$TreeRoot, [switch]$DryCheck)
    if ($null -eq $Arguments) { $Arguments = @() }
    switch ($Kind) {
        'harmless' {
            $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if ($File -ine $ps) { throw "launch refused: the harmless self-test may only start Windows PowerShell ($File)" }
            if ($Arguments.Count -ne 3 -or $Arguments[0] -ne '-NoProfile' -or $Arguments[1] -ne '-Command' -or $Arguments[2] -notmatch '^Start-Sleep -Seconds \d{1,4}$') {
                throw 'launch refused: the harmless self-test may only run Start-Sleep'
            }
        }
        'java' {
            if (-not $script:Cp3AllowLegacyLaunch -and -not $DryCheck) { throw 'launch refused: starting legacy programs is not enabled (Phase B with -ConfirmStartListeners only)' }
            if ([string]::IsNullOrEmpty($TreeRoot)) { throw 'launch refused: no scratch tree given' }
            $java = Get-Cp3RealJavaExe
            if (-not $java -or $File -ine $java) { throw "launch refused: '$File' is not the real java.exe (java.home\bin\java.exe)" }
            if ($Arguments.Count -lt 3) { throw 'launch refused: unexpected java arguments' }
            $mainClass = $Arguments[$Arguments.Count - 1]
            if ($mainClass -notin @('app.Main', 'pdp.Main')) { throw "launch refused: main class '$mainClass' is not allowed" }
            $cpIndex = [Array]::IndexOf($Arguments, '-cp')
            if ($cpIndex -lt 0 -or $cpIndex + 1 -ge $Arguments.Count - 1) { throw 'launch refused: no -cp given' }
            $allowedFlags = @('--enable-native-access=ALL-UNNAMED')
            for ($i = 0; $i -lt $Arguments.Count - 1; $i++) {
                if ($i -eq $cpIndex -or $i -eq $cpIndex + 1) { continue }
                if ($Arguments[$i] -notin $allowedFlags) { throw "launch refused: java argument '$($Arguments[$i])' is not allowed" }
            }
            $classes = Join-Path $TreeRoot 'build\java'
            $lib = Join-Path $TreeRoot 'lib'
            foreach ($entry in ($Arguments[$cpIndex + 1] -split ';')) {
                if (-not $entry) { continue }
                $full = [System.IO.Path]::GetFullPath($entry)
                $ok = (Test-PathInside $full $classes) -or ((Test-PathInside $full $lib) -and $full.EndsWith('.jar', [System.StringComparison]::OrdinalIgnoreCase))
                if (-not $ok) { throw "launch refused: classpath entry '$entry' is outside the scratch tree" }
            }
        }
        'cpp' {
            if (-not $script:Cp3AllowLegacyLaunch -and -not $DryCheck) { throw 'launch refused: starting legacy programs is not enabled (Phase B with -ConfirmStartListeners only)' }
            if ([string]::IsNullOrEmpty($TreeRoot)) { throw 'launch refused: no scratch tree given' }
            $allowed = @((Join-Path $TreeRoot 'build\cpp\pep_proxy.exe'), (Join-Path $TreeRoot 'build\cpp\agent.exe'))
            $full = [System.IO.Path]::GetFullPath($File)
            if (-not (@($allowed | Where-Object { $_ -ieq $full }).Count -eq 1)) { throw "launch refused: '$File' is not a scratch-tree executable" }
            if ($Arguments.Count -ne 0) { throw 'launch refused: the scratch programs are started without arguments' }
        }
        default { throw "launch refused: unknown kind '$Kind'" }
    }
}

# The main module of a process that has just been created can be unreadable for a short while (seen with a harmless sleeper in H13:
# the image path came back empty). Retry, fall back to WMI, and never return a guess.
function Get-Cp3ImagePath([System.Diagnostics.Process]$Process) {
    for ($i = 0; $i -lt 50; $i++) {
        try { $Process.Refresh(); $f = [string]$Process.MainModule.FileName; if ($f) { return $f } } catch { }
        try {
            $c = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $Process.Id) -ErrorAction Stop
            if ($null -ne $c -and $c.ExecutablePath) { return [string]$c.ExecutablePath }
        } catch { }
        if ($Process.HasExited) { break }
        Start-Sleep -Milliseconds 100
    }
    return ''
}

# The exact programs and command lines Phase B starts. Phase A prints and validates them (guard -DryCheck) but never starts them.
function Get-Cp3LaunchPlan {
    param([string]$Tree, [string]$JavaExe, [string[]]$JavaFlags)
    $jars = @(Get-ChildItem -LiteralPath (Join-Path $Tree 'lib') -Filter '*.jar' -File | Sort-Object Name | ForEach-Object { $_.FullName })
    $cpApi = (@((Join-Path $Tree 'build\java\protected_app')) + $jars) -join ';'
    $cpPdp = (@((Join-Path $Tree 'build\java\pdp')) + $jars) -join ';'
    $flags = @()
    if ($JavaFlags) { $flags = @($JavaFlags) }
    return @(
        [pscustomobject]@{ Role = 'api'; Kind = 'java'; File = $JavaExe; Arguments = ($flags + @('-cp', $cpApi, 'app.Main')); Port = 19000 },
        [pscustomobject]@{ Role = 'pdp'; Kind = 'java'; File = $JavaExe; Arguments = ($flags + @('-cp', $cpPdp, 'pdp.Main')); Port = 18443 },
        [pscustomobject]@{ Role = 'pep'; Kind = 'cpp'; File = (Join-Path $Tree 'build\cpp\pep_proxy.exe'); Arguments = @(); Port = 15000 },
        [pscustomobject]@{ Role = 'agent'; Kind = 'cpp'; File = (Join-Path $Tree 'build\cpp\agent.exe'); Arguments = @(); Port = 0 }
    )
}
# ---------------------------------------------------------------- start / record / stop
function Start-Cp3Process {
    param(
        [string]$Role, [string]$Kind, [string]$File, [string[]]$Arguments, [string]$WorkingDirectory,
        [string]$StdOutPath, [string]$StdErrPath, [IntPtr]$Job, [string]$PidFile, [string]$TreeRoot
    )
    Assert-Cp3LaunchAllowed -Kind $Kind -File $File -Arguments $Arguments -TreeRoot $TreeRoot
    Add-Cp3LaunchLog $Kind $File $Arguments
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $StdOutPath), $WorkingDirectory | Out-Null
    $argString = ConvertTo-ArgString $Arguments
    if ($argString.Length -gt 0) {
        $p = Start-Process -FilePath $File -ArgumentList $argString -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $StdOutPath -RedirectStandardError $StdErrPath -WindowStyle Hidden -PassThru
    } else {
        $p = Start-Process -FilePath $File -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $StdOutPath -RedirectStandardError $StdErrPath -WindowStyle Hidden -PassThru
    }
    try { Add-Cp3JobProcess $Job $p } catch { try { $p.Kill() } catch { } ; throw "could not assign the new process to the Job Object: $($_.Exception.Message)" }
    $img = Get-Cp3ImagePath $p
    if (-not $img) { try { $p.Kill() } catch { } ; throw 'could not determine the image path of the new process; it was stopped' }
    $rec = [pscustomobject]@{
        Role = $Role; Pid = [int]$p.Id; StartUtcTicks = [long]$p.StartTime.ToUniversalTime().Ticks
        ImagePath = $img; StdOut = $StdOutPath; StdErr = $StdErrPath
    }
    $script:Cp3ProcObjects[[int]$p.Id] = $p
    $script:Cp3ProcStart[[int]$p.Id] = [long]$rec.StartUtcTicks
    Add-Cp3PidRecord $PidFile $rec
    return $rec
}

# A function (not a variable access inside a closure) so that it always sees the script-scope table.
function Get-Cp3ProcObject([int]$ProcessId) {
    if ($script:Cp3ProcObjects.ContainsKey($ProcessId)) { return $script:Cp3ProcObjects[$ProcessId] }
    return $null
}

# The pid file is plain text, one record per line, six TAB-separated fields:
#   role, pid, start time (UTC ticks), image path, stdout log, stderr log
# (a JSON file was used first; Windows PowerShell 5.1 wraps the first element wrongly when a read-back array is serialized again,
#  which the multi-record check H13 caught)
function Read-Cp3PidFile([string]$PidFile) {
    $out = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $PidFile) {
        foreach ($line in [System.IO.File]::ReadAllLines($PidFile)) {
            if (-not $line.Trim()) { continue }
            $f = $line.Split([char]9)
            if ($f.Count -ne 6) { throw "malformed line in the pid file $PidFile" }
            $out.Add([pscustomobject]@{ Role = $f[0]; Pid = [int]$f[1]; StartUtcTicks = [long]$f[2]; ImagePath = $f[3]; StdOut = $f[4]; StdErr = $f[5] })
        }
    }
    return $out.ToArray()
}

function Add-Cp3PidRecord([string]$PidFile, $Record) {
    foreach ($v in @($Record.Role, $Record.ImagePath, $Record.StdOut, $Record.StdErr)) {
        if (([string]$v).IndexOfAny([char[]]@([char]9, [char]13, [char]10)) -ge 0) { throw 'a tab or line break in a pid-file field' }
    }
    $line = [string]::Join([string][char]9, @([string]$Record.Role, [string]$Record.Pid, [string]$Record.StartUtcTicks, [string]$Record.ImagePath, [string]$Record.StdOut, [string]$Record.StdErr))
    [System.IO.File]::AppendAllText($PidFile, $line + "`r`n", $script:Cp3Utf8)
}
# Returns 'stopped', 'already-gone' or 'REFUSED (...)'. A pid is only ever stopped when its start time and image path match the record.
function Stop-Cp3Recorded($Record) {
    $p = Get-Process -Id ([int]$Record.Pid) -ErrorAction SilentlyContinue
    if ($null -eq $p) { return 'already-gone' }
    $ticks = $null
    $path = $null
    try { $ticks = [long]$p.StartTime.ToUniversalTime().Ticks; $path = Get-Cp3ImagePath $p } catch { return 'REFUSED (cannot read the process start time or path)' }
    if ($ticks -ne [long]$Record.StartUtcTicks) { return 'REFUSED (start time differs from the record: the pid was reused)' }
    if ($path -ine [string]$Record.ImagePath) { return 'REFUSED (image path differs from the record)' }
    Stop-Process -Id $p.Id -Force
    [void]$p.WaitForExit(5000)
    return 'stopped'
}

# ---------------------------------------------------------------- listener and connection audit (loopback only)
function Get-Cp3Listeners {
    $rows = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
    foreach ($r in $rows) { [pscustomobject]@{ Pid = [int]$r.OwningProcess; Address = [string]$r.LocalAddress; Port = [int]$r.LocalPort } }
}

function Get-Cp3Connections([int[]]$Pids) {
    $rows = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $Pids -contains [int]$_.OwningProcess })
    foreach ($r in $rows) {
        [pscustomobject]@{ Pid = [int]$r.OwningProcess; LocalAddress = [string]$r.LocalAddress; LocalPort = [int]$r.LocalPort; RemoteAddress = [string]$r.RemoteAddress; RemotePort = [int]$r.RemotePort; State = [string]$r.State }
    }
}

# Pure classifier (also tested on synthetic records). Violations stop the run; warnings are only reported.
function Get-Cp3AuditFindings {
    param($Listeners, $Connections, [int[]]$Pids, [int[]]$ExpectedPorts)
    $violations = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    foreach ($l in @($Listeners)) {
        if ($null -eq $l) { continue }
        if ($Pids -notcontains [int]$l.Pid) { continue }
        if ($l.Address -cne '127.0.0.1') { $violations.Add(('pid {0} listens on {1}:{2} (not 127.0.0.1)' -f $l.Pid, $l.Address, $l.Port)); continue }
        if ($ExpectedPorts -notcontains [int]$l.Port) { $warnings.Add(('pid {0} listens on 127.0.0.1:{1} (not one of the expected ports)' -f $l.Pid, $l.Port)) }
    }
    foreach ($c in @($Connections)) {
        if ($null -eq $c) { continue }
        if ($Pids -notcontains [int]$c.Pid) { continue }
        if ($c.State -in @('Listen', 'Bound')) { continue }
        if ($c.RemoteAddress -cne '127.0.0.1') { $violations.Add(('pid {0} has a {1} connection to {2}:{3} (not 127.0.0.1)' -f $c.Pid, $c.State, $c.RemoteAddress, $c.RemotePort)) }
    }
    return [pscustomobject]@{ Violations = $violations.ToArray(); Warnings = $warnings.ToArray() }
}

function Format-Cp3Audit($Listeners, $Connections, [int[]]$Pids) {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('listeners owned by the recorded processes:')
    $mine = @($Listeners | Where-Object { $null -ne $_ -and $Pids -contains [int]$_.Pid })
    if ($mine.Count -eq 0) { $out.Add('  (none)') }
    foreach ($l in $mine) { $out.Add(('  pid {0,6}  {1}:{2}' -f $l.Pid, $l.Address, $l.Port)) }
    $out.Add('connections owned by the recorded processes (excluding Listen/Bound):')
    $conn = @($Connections | Where-Object { $null -ne $_ -and $_.State -notin @('Listen', 'Bound') })
    if ($conn.Count -eq 0) { $out.Add('  (none)') }
    foreach ($c in $conn) { $out.Add(('  pid {0,6}  {1}:{2} -> {3}:{4}  {5}' -f $c.Pid, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State)) }
    return $out.ToArray()
}

function Wait-Cp3Listener {
    param([int]$Port, [int]$ExpectedPid, [int]$TimeoutSec = 30, [scriptblock]$Tick)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($null -ne $Tick) { & $Tick }
        $mine = @(Get-Cp3Listeners | Where-Object { $_.Port -eq $Port -and $_.Pid -eq $ExpectedPid })
        if ($mine.Count -gt 0) { return $mine[0] }
        Start-Sleep -Milliseconds 250
    }
    return $null
}

# ---------------------------------------------------------------- helpers used by the Phase B controls (named functions, so closures never depend on script-scope variables)
function Get-Cp3LatestRecord([string]$PidFile, [string]$Role) {
    $all = @(Read-Cp3PidFile $PidFile | Where-Object { $_.Role -eq $Role })
    if ($all.Count -eq 0) { return $null }
    return $all[$all.Count - 1]
}

# Stops the most recent recorded process of a role. Throws if the record does not match the live process (never stops anything else).
function Stop-Cp3Role([string]$PidFile, [string]$Role) {
    $rec = Get-Cp3LatestRecord $PidFile $Role
    if ($null -eq $rec) { throw "no recorded process with the role '$Role'" }
    $r = Stop-Cp3Recorded $rec
    if ($r.StartsWith('REFUSED')) { throw ("the '$Role' process could not be stopped safely: " + $r) }
    return $r
}

# Exited / ExitCode of the most recent recorded process of a role (the exit code is only known for processes this script started).
function Get-Cp3RoleExitInfo([string]$PidFile, [string]$Role) {
    $rec = Get-Cp3LatestRecord $PidFile $Role
    if ($null -eq $rec) { return [pscustomobject]@{ Exited = $true; ExitCode = $null } }
    $p = Get-Cp3ProcObject ([int]$rec.Pid)
    if ($null -ne $p) {
        if ($p.HasExited) { return [pscustomobject]@{ Exited = $true; ExitCode = [int]$p.ExitCode } }
        return [pscustomobject]@{ Exited = $false; ExitCode = $null }
    }
    $alive = $null -ne (Get-Process -Id ([int]$rec.Pid) -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Exited = (-not $alive); ExitCode = $null }
}

function Get-Cp3PortStatus {
    $l = @(Get-Cp3Listeners)
    return [pscustomobject]@{
        Api = (@($l | Where-Object { $_.Port -eq 19000 }).Count -gt 0)
        Pdp = (@($l | Where-Object { $_.Port -eq 18443 }).Count -gt 0)
        Pep = (@($l | Where-Object { $_.Port -eq 15000 }).Count -gt 0)
    }
}

# Reads a text file that another process may still be writing (shared read/write open).
function Read-Cp3SharedText([string]$Path) {
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $sr = New-Object System.IO.StreamReader($fs, $script:Cp3Utf8)
        try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
    } finally { $fs.Dispose() }
}

function Wait-Cp3LogMatch([string]$Path, [string]$Pattern, [int]$TimeoutSec = 30, [scriptblock]$Tick) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($null -ne $Tick) { & $Tick }
        if (Test-Path -LiteralPath $Path) {
            $t = ''
            try { $t = Read-Cp3SharedText $Path } catch { $t = '' }
            if ($t -match $Pattern) { return $true }
        }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

# ================================================================ run-state monitor (C1, C2, C3)
# One expectation per role says what the run may look like at this moment:
#   NOT_STARTED   nothing may be recorded for the role yet
#   ALIVE         the most recent recorded process of the role must be running and must be a member of the Job Object
#   PLANNED_DOWN  the role may be down or restarted - only between Enter-Cp3PlannedExit and Exit-Cp3PlannedExit, and only at the exact steps below
# Every other exit of a recorded process, every process in the Job Object that this run did not start and record, and every recorded process
# that is running outside the Job Object is a violation that stops the run. Nothing here restarts, repairs or hides anything.
$script:Cp3Roles = @('api', 'pdp', 'pep', 'agent')
$script:Cp3ConhostOk = @{}

# The scenario steps at which a role is allowed to be down: the agent is stopped on purpose in T13 (to test stale-heartbeat handling),
# the PEP is expected to die in the two crash probes P1 and P2. Nothing else.
function Get-Cp3PlannedExitSteps([string]$Role) {
    if ($Role -ceq 'agent') { return @('T13') }
    if ($Role -ceq 'pep') { return @('P1', 'P2') }
    return @()
}
function Test-Cp3PlannedExitAllowed([string]$Role, [string]$Step) { return (@(Get-Cp3PlannedExitSteps $Role) -ccontains $Step) }
# The scratch terminate handler (decision D2) ends the PEP with ExitProcess(99); any other exit code of the PEP is unexplained.
function Get-Cp3PepPlannedExitCodes { return @(99) }

function New-Cp3Expect {
    $e = @{}
    foreach ($r in $script:Cp3Roles) { $e[$r] = 'NOT_STARTED' }
    $e['_window'] = ''
    return $e
}

# Call right after Start-Cp3Process for the first start of a role.
function Set-Cp3RoleStarted($Expect, [string]$Role) {
    if ([string]$Expect[$Role] -cne 'NOT_STARTED') { throw ("RUN STATE VIOLATION: the role '$Role' is started a second time outside a planned restart (state " + [string]$Expect[$Role] + ')') }
    $Expect[$Role] = 'ALIVE'
}

# A running process or $null (never an exited one).
function Get-Cp3ProcessOrNull([int]$ProcessId) {
    try {
        $p = [System.Diagnostics.Process]::GetProcessById($ProcessId)
        if ($p.HasExited) { return $null }
        return $p
    } catch { return $null }
}

# The Process object this script holds for a record, but only when it is certainly the same process (start time equal to the record).
function Get-Cp3ProcObjectFor($Record) {
    $id = [int]$Record.Pid
    if (-not $script:Cp3ProcObjects.ContainsKey($id)) { return $null }
    if (-not $script:Cp3ProcStart.ContainsKey($id) -or [long]$script:Cp3ProcStart[$id] -ne [long]$Record.StartUtcTicks) { return $null }
    return $script:Cp3ProcObjects[$id]
}

# Is the process of a pid-file record still running?  Uses the handle this script holds (it cannot be confused with a recycled pid and it
# knows the exit code); without a handle the pid, the start time AND the image path must all match the record.
function Get-Cp3RecordState($Record) {
    $p = Get-Cp3ProcObjectFor $Record
    if ($null -ne $p) {
        $known = $false
        $exited = $false
        $code = $null
        try { $exited = [bool]$p.HasExited; if ($exited) { $code = [int]$p.ExitCode }; $known = $true } catch { $known = $false }
        if ($known) { return [pscustomobject]@{ Running = (-not $exited); ExitCode = $code; Source = 'process handle' } }
    }
    $q = Get-Cp3ProcessOrNull ([int]$Record.Pid)
    if ($null -eq $q) { return [pscustomobject]@{ Running = $false; ExitCode = $null; Source = 'pid lookup (no such process)' } }
    $same = $false
    try { $same = ([long]$q.StartTime.ToUniversalTime().Ticks -eq [long]$Record.StartUtcTicks) -and ((Get-Cp3ImagePath $q) -ieq [string]$Record.ImagePath) } catch { $same = $false }
    return [pscustomobject]@{ Running = $same; ExitCode = $null; Source = 'pid lookup (start time and image path)' }
}

function Format-Cp3ExitCode($Code) {
    if ($null -eq $Code) { return 'unknown' }
    return ('{0} (0x{1:X8})' -f [int]$Code, [int]$Code)
}

# Windows creates a console host (conhost.exe) for every hidden console program, and it joins the Job Object when it is created after
# the program was assigned to the job. That is the only unrecorded job member this run tolerates, and only when it is the system's own
# conhost.exe whose parent is a process this run recorded. Returns '' when the member is acceptable, otherwise a description.
function Get-Cp3UnrecordedMemberProblem([int]$ProcessId, [int[]]$RecordedPids) {
    $p = Get-Cp3ProcessOrNull $ProcessId
    if ($null -eq $p) { return '' }
    $name = ''
    $ticks = 0L
    try { $name = [string]$p.ProcessName; $ticks = [long]$p.StartTime.ToUniversalTime().Ticks } catch { if ($null -eq (Get-Cp3ProcessOrNull $ProcessId)) { return '' }; return ('pid {0} is in the Job Object but is not a recorded process (its details could not be read)' -f $ProcessId) }
    if ($name -cne 'conhost') { return ('pid {0} ({1}) is in the Job Object but was not started and recorded by this run' -f $ProcessId, $name) }
    $key = [string]$ProcessId + '|' + [string]$ticks
    if ($script:Cp3ConhostOk.ContainsKey($key)) { return '' }
    $sys = Join-Path $env:SystemRoot 'System32\conhost.exe'
    $img = Get-Cp3ImagePath $p
    if (-not $img) { if ($null -eq (Get-Cp3ProcessOrNull $ProcessId)) { return '' }; return ('pid {0} (conhost) is in the Job Object and its image path could not be read' -f $ProcessId) }
    if ($img -ine $sys) { return ('pid {0} is named conhost but its image is {1}, not {2}' -f $ProcessId, $img, $sys) }
    $parent = -1
    try { $c = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $ProcessId) -ErrorAction Stop; if ($null -ne $c) { $parent = [int]$c.ParentProcessId } } catch { $parent = -1 }
    if ($parent -lt 0) { if ($null -eq (Get-Cp3ProcessOrNull $ProcessId)) { return '' }; return ('pid {0} (conhost) is in the Job Object and its parent process could not be determined' -f $ProcessId) }
    if ($RecordedPids -notcontains $parent) { return ('pid {0} (conhost) is in the Job Object but its parent pid {1} is not a recorded process' -f $ProcessId, $parent) }
    $script:Cp3ConhostOk[$key] = $true
    return ''
}

# The whole run state against the expectations. Returns a list of problems (empty = everything as expected).
function Get-Cp3RunStateProblems {
    param([string]$PidFile, [IntPtr]$Job, $Expect)
    $problems = New-Object System.Collections.Generic.List[string]
    $records = @(Read-Cp3PidFile $PidFile)
    $jobPids = @(Get-Cp3JobPids $Job)
    $recordedPids = @($records | ForEach-Object { [int]$_.Pid })
    $states = New-Object System.Collections.Generic.List[object]
    foreach ($r in $records) { $states.Add((Get-Cp3RecordState $r)) }
    foreach ($role in $script:Cp3Roles) {
        $want = [string]$Expect[$role]
        $idx = New-Object System.Collections.Generic.List[int]
        for ($i = 0; $i -lt $records.Count; $i++) { if ($records[$i].Role -ceq $role) { $idx.Add($i) } }
        if ($want -ceq 'NOT_STARTED') {
            if ($idx.Count -gt 0) { $problems.Add("the role '$role' has a recorded process although it was not supposed to be started yet") }
            continue
        }
        if ($idx.Count -eq 0) { $problems.Add("the role '$role' is expected to be started but no process is recorded"); continue }
        for ($k = 0; $k -lt $idx.Count - 1; $k++) {
            if ($states[$idx[$k]].Running) { $problems.Add(("an older '{0}' process (pid {1}) is still running although a newer one was started" -f $role, $records[$idx[$k]].Pid)) }
        }
        $last = $idx[$idx.Count - 1]
        if ($want -ceq 'ALIVE' -and -not $states[$last].Running) {
            $problems.Add(("the '{0}' process (pid {1}) has exited unexpectedly, exit code {2}" -f $role, $records[$last].Pid, (Format-Cp3ExitCode $states[$last].ExitCode)))
        }
    }
    for ($i = 0; $i -lt $records.Count; $i++) {
        if ($states[$i].Running -and ($jobPids -notcontains [int]$records[$i].Pid)) { $problems.Add(("the recorded '{0}' process (pid {1}) is running but is not in the Job Object" -f $records[$i].Role, $records[$i].Pid)) }
    }
    foreach ($jp in $jobPids) {
        if ($recordedPids -contains $jp) { continue }
        $why = Get-Cp3UnrecordedMemberProblem $jp $recordedPids
        if ($why) { $problems.Add('unexpected process in the Job Object: ' + $why) }
    }
    return $problems.ToArray()
}

function Assert-Cp3RunState {
    param([string]$PidFile, [IntPtr]$Job, $Expect)
    $p = @(Get-Cp3RunStateProblems -PidFile $PidFile -Job $Job -Expect $Expect)
    if ($p.Count -gt 0) { throw ('RUN STATE VIOLATION: ' + ($p -join '; ')) }
}

# A planned-exit window: opened right before the scenario step that stops or crashes a role, closed right after the step has restored it.
function Enter-Cp3PlannedExit {
    param($Expect, [string]$PidFile, [IntPtr]$Job, [string]$Role, [string]$Step)
    if (-not (Test-Cp3PlannedExitAllowed $Role $Step)) { throw ("RUN STATE VIOLATION: a planned exit of '$Role' is not permitted at step '$Step'") }
    if ([string]$Expect['_window'] -ne '') { throw ("RUN STATE VIOLATION: the planned-exit window '" + [string]$Expect['_window'] + "' is still open") }
    if ([string]$Expect[$Role] -cne 'ALIVE') { throw ("RUN STATE VIOLATION: cannot plan an exit of '$Role': it is not in the ALIVE state (" + [string]$Expect[$Role] + ')') }
    Assert-Cp3RunState -PidFile $PidFile -Job $Job -Expect $Expect
    $Expect[$Role] = 'PLANNED_DOWN'
    $Expect['_window'] = $Role + '@' + $Step
}

# $ExitInfo: what the step observed about the role's exit (Exited, ExitCode) or $null. For the PEP an exit must carry the planned exit code.
function Exit-Cp3PlannedExit {
    param($Expect, [string]$PidFile, [IntPtr]$Job, [string]$Role, [string]$Step, $ExitInfo)
    $w = $Role + '@' + $Step
    if ([string]$Expect['_window'] -cne $w) { throw ("RUN STATE VIOLATION: cannot close the planned-exit window '$w' (open window: '" + [string]$Expect['_window'] + "')") }
    if ($Role -ceq 'pep' -and $null -ne $ExitInfo -and [bool]$ExitInfo.Exited) {
        if ($null -eq $ExitInfo.ExitCode -or (Get-Cp3PepPlannedExitCodes) -notcontains [int]$ExitInfo.ExitCode) {
            throw ("RUN STATE VIOLATION: unexplained exit of the PEP at $Step - exit code " + (Format-Cp3ExitCode $ExitInfo.ExitCode) + ', planned exit code ' + ((Get-Cp3PepPlannedExitCodes) -join ','))
        }
    }
    $Expect[$Role] = 'ALIVE'
    $Expect['_window'] = ''
    Assert-Cp3RunState -PidFile $PidFile -Job $Job -Expect $Expect
}

# ---------------------------------------------------------------- socket checks (C3)
# Pure classifier for the quick check (also tested on synthetic records): anything on a test port that is not 127.0.0.1 on both ends.
function Get-Cp3QuickSocketFindings {
    param($Listeners, $Connections, [int[]]$Ports)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in @($Listeners)) {
        if ($null -eq $l) { continue }
        if ($Ports -contains [int]$l.Port -and [string]$l.Address -cne '127.0.0.1') { $out.Add(('a listener on port {0} is bound to {1}, not 127.0.0.1' -f $l.Port, $l.Address)) }
    }
    foreach ($c in @($Connections)) {
        if ($null -eq $c) { continue }
        if ($Ports -contains [int]$c.LocalPort -and ([string]$c.LocalAddress -cne '127.0.0.1' -or [string]$c.RemoteAddress -cne '127.0.0.1')) {
            $out.Add(('a connection to test port {0} runs between {1} and {2} (not both 127.0.0.1)' -f $c.LocalPort, $c.LocalAddress, $c.RemoteAddress))
        }
    }
    return $out.ToArray()
}

# Cheap (milliseconds): looks at the whole machine's TCP table through .NET, but only at entries on the test ports. It cannot say which
# process owns an entry; the pid-attributed audit (Invoke-Cp3MonitorAudit) does that.
function Get-Cp3QuickSocketProblems([int[]]$Ports) {
    $ipp = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $ls = New-Object System.Collections.Generic.List[object]
    foreach ($ep in $ipp.GetActiveTcpListeners()) {
        if ($Ports -contains [int]$ep.Port) { $ls.Add([pscustomobject]@{ Address = $ep.Address.ToString(); Port = [int]$ep.Port }) }
    }
    $cs = New-Object System.Collections.Generic.List[object]
    foreach ($c in $ipp.GetActiveTcpConnections()) {
        if ($Ports -contains [int]$c.LocalEndPoint.Port) {
            $cs.Add([pscustomobject]@{ LocalAddress = $c.LocalEndPoint.Address.ToString(); LocalPort = [int]$c.LocalEndPoint.Port; RemoteAddress = $c.RemoteEndPoint.Address.ToString(); RemotePort = [int]$c.RemoteEndPoint.Port })
        }
    }
    return (Get-Cp3QuickSocketFindings -Listeners $ls.ToArray() -Connections $cs.ToArray() -Ports $Ports)
}

# Positive check, so that the audit cannot pass because it is blind: every server role that is ALIVE must be seen listening on
# 127.0.0.1:<its port> with the pid of its most recent record. $ExpectedListeners maps role -> port.
function Get-Cp3ListenerCoverageProblems {
    param($Listeners, $Records, $Expect, $ExpectedListeners)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($role in @($ExpectedListeners.Keys | Sort-Object)) {
        if ([string]$Expect[$role] -cne 'ALIVE') { continue }
        $port = [int]$ExpectedListeners[$role]
        $mine = @($Records | Where-Object { $_.Role -ceq $role })
        if ($mine.Count -eq 0) { continue }
        $pid1 = [int]$mine[$mine.Count - 1].Pid
        $hit = @($Listeners | Where-Object { $null -ne $_ -and [int]$_.Port -eq $port -and [int]$_.Pid -eq $pid1 -and [string]$_.Address -ceq '127.0.0.1' })
        if ($hit.Count -eq 0) { $out.Add(("the '{0}' process (pid {1}) is not seen listening on 127.0.0.1:{2}" -f $role, $pid1, $port)) }
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------- the monitor object and its entry points
# $ExpectedListeners: role -> port (Phase B: api 19000, pdp 18443, pep 15000). Violations always THROW; the caller must not catch and continue.
function New-Cp3Monitor {
    param([string]$PidFile, [IntPtr]$Job, $Expect, [string[]]$LivePaths, $LiveStamps, [string]$AuditFile, [int[]]$Ports, $ExpectedListeners, [int]$WatchdogSec = 900, [double]$AuditEverySec = 5)
    return [pscustomobject]@{
        PidFile = $PidFile; Job = $Job; Expect = $Expect; LivePaths = $LivePaths; LiveStamps = $LiveStamps; AuditFile = $AuditFile
        Ports = $Ports; ExpectedListeners = $ExpectedListeners; WatchdogSec = $WatchdogSec; AuditEverySec = $AuditEverySec
        Started = [System.Diagnostics.Stopwatch]::StartNew(); LastAudit = $null
        Ticks = 0; Audits = 0; Requests = 0; StageAudits = (New-Object System.Collections.Generic.List[string])
    }
}

# The startup phase and the scenario phase have their own time limits: the limit is replaced and the clock restarts.
function Set-Cp3WatchdogLimit($Mon, [int]$Seconds) { $Mon.WatchdogSec = $Seconds; $Mon.Started.Restart() }

# C1/C2: cheap and complete. Process exits, job members, live-database tripwire, quick socket check, watchdog.
function Invoke-Cp3MonitorTick($Mon) {
    $Mon.Ticks++
    if ($Mon.Started.Elapsed.TotalSeconds -gt $Mon.WatchdogSec) { throw ('WATCHDOG: the run exceeded ' + $Mon.WatchdogSec + ' seconds') }
    Assert-Cp3RunState -PidFile $Mon.PidFile -Job $Mon.Job -Expect $Mon.Expect
    $ch = @(Compare-Cp3FileStamps $Mon.LiveStamps (Get-Cp3FileStamps $Mon.LivePaths))
    if ($ch.Count -gt 0) { throw ('LIVE DATABASE TRIPWIRE: ' + ($ch -join ', ')) }
    $q = @(Get-Cp3QuickSocketProblems $Mon.Ports)
    if ($q.Count -gt 0) { throw ('NON-LOOPBACK SOCKET: ' + ($q -join '; ')) }
}

# One read of the machine's TCP table (about a second): every listener on the machine, and the connections owned by $Pids.
# It fails closed: a table that cannot be read, or that is empty, is an error and never an empty (clean) audit.
function Read-Cp3TcpSnapshot([int[]]$Pids) {
    $rows = @()
    try { $rows = @(Get-NetTCPConnection -ErrorAction Stop) } catch { throw ('AUDIT SOURCE FAILED: ' + $_.Exception.Message) }
    if ($rows.Count -eq 0) { throw 'AUDIT SOURCE FAILED: Get-NetTCPConnection returned no rows' }
    $ls = New-Object System.Collections.Generic.List[object]
    $cs = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        if ([string]$r.State -ceq 'Listen') { $ls.Add([pscustomobject]@{ Pid = [int]$r.OwningProcess; Address = [string]$r.LocalAddress; Port = [int]$r.LocalPort }) }
        if ($Pids -contains [int]$r.OwningProcess) {
            $cs.Add([pscustomobject]@{ Pid = [int]$r.OwningProcess; LocalAddress = [string]$r.LocalAddress; LocalPort = [int]$r.LocalPort; RemoteAddress = [string]$r.RemoteAddress; RemotePort = [int]$r.RemotePort; State = [string]$r.State })
        }
    }
    return [pscustomobject]@{ Listeners = $ls.ToArray(); Connections = $cs.ToArray(); Rows = $rows.Count }
}

# C3: the full audit. One read of the machine's TCP table, attributed to process ids: every process in the Job Object plus every recorded
# process that is still running. Any listener not on 127.0.0.1 and any connection whose remote end is not 127.0.0.1 throws.
function Invoke-Cp3MonitorAudit {
    param($Mon, [string]$Stage)
    $records = @(Read-Cp3PidFile $Mon.PidFile)
    $pids = New-Object System.Collections.Generic.List[int]
    foreach ($j in @(Get-Cp3JobPids $Mon.Job)) { $pids.Add([int]$j) }
    foreach ($r in $records) { if ((Get-Cp3RecordState $r).Running -and -not $pids.Contains([int]$r.Pid)) { $pids.Add([int]$r.Pid) } }
    $alive = @($pids.ToArray() | Sort-Object -Unique)
    $snap = $null
    try { $snap = Read-Cp3TcpSnapshot $alive } catch { throw ($_.Exception.Message + ' (at ' + $Stage + ')') }
    $ls = $snap.Listeners
    $cs = $snap.Connections
    $f = Get-Cp3AuditFindings -Listeners $ls -Connections $cs -Pids $alive -ExpectedPorts $Mon.Ports
    $cov = @(Get-Cp3ListenerCoverageProblems -Listeners $ls -Records $records -Expect $Mon.Expect -ExpectedListeners $Mon.ExpectedListeners)
    $Mon.Audits++
    $text = New-Object System.Collections.Generic.List[string]
    $text.Add(('--- audit #{0}: {1}  {2}  (job members + recorded running processes: {3}; TCP table rows read: {4})' -f $Mon.Audits, $Stage, (Get-Date -Format 'HH:mm:ss'), $alive.Count, $snap.Rows))
    foreach ($l in (Format-Cp3Audit $ls $cs $alive)) { $text.Add($l) }
    foreach ($w in $f.Warnings) { $text.Add('  WARNING ' + $w) }
    foreach ($x in $f.Violations) { $text.Add('  VIOLATION ' + $x) }
    foreach ($x in $cov) { $text.Add('  VIOLATION ' + $x) }
    if ($Mon.AuditFile) { [System.IO.File]::AppendAllText($Mon.AuditFile, ([string]::Join("`r`n", $text.ToArray()) + "`r`n"), $script:Cp3Utf8) }
    $Mon.StageAudits.Add($Stage + ': ' + $(if (@($f.Violations).Count + $cov.Count -eq 0) { 'clean' } else { 'VIOLATION' }))
    $Mon.LastAudit = [System.Diagnostics.Stopwatch]::StartNew()
    if (@($f.Violations).Count -gt 0 -or $cov.Count -gt 0) { throw ('LOOPBACK AUDIT VIOLATION at ' + $Stage + ': ' + ((@($f.Violations) + $cov) -join '; ')) }
}

# Tick, then a full audit when one is due: the first call, then every AuditEverySec seconds, and (-Force) whenever the caller insists.
function Invoke-Cp3MonitorStep($Mon, [string]$Why, [bool]$Force = $false) {
    Invoke-Cp3MonitorTick $Mon
    if ($Force -or $null -eq $Mon.LastAudit -or $Mon.LastAudit.Elapsed.TotalSeconds -ge $Mon.AuditEverySec) { Invoke-Cp3MonitorAudit $Mon $Why }
}
# Before a request: a tick every time, a full audit when one is due and in any case before every 10th request (the rule of the first version of this guard).
function Invoke-Cp3MonitorGuard($Mon) {
    $Mon.Requests++
    Invoke-Cp3MonitorStep $Mon ('periodic, before request ' + $Mon.Requests) (($Mon.Requests % 10) -eq 0)
}
function Invoke-Cp3MonitorWait($Mon) { Invoke-Cp3MonitorStep $Mon 'periodic, during a wait' }

# Before shutdown: every window closed, every role ALIVE, one more tick and one more full audit.
function Invoke-Cp3MonitorFinal($Mon) {
    if ([string]$Mon.Expect['_window'] -ne '') { throw ("RUN STATE VIOLATION: the planned-exit window '" + [string]$Mon.Expect['_window'] + "' is still open at the end of the run") }
    foreach ($role in $script:Cp3Roles) { if ([string]$Mon.Expect[$role] -cne 'ALIVE') { throw ("RUN STATE VIOLATION: at the end of the run the role '$role' is in the state " + [string]$Mon.Expect[$role] + ', not ALIVE') } }
    Invoke-Cp3MonitorTick $Mon
    Invoke-Cp3MonitorAudit $Mon 'before shutdown'
}

# ---------------------------------------------------------------- the controls the scenario engine uses (C1, C2, C3)
# $StartAgent / $StartPep: scriptblocks that start the program (recorded in the pid file), wait until it is ready and return $true or $false.
# After each restart the full audit runs. In the window opened by BeginPlannedExit the role may be down; every other role stays monitored.
function New-Cp3Controls {
    param($Mon, [scriptblock]$StartAgent, [scriptblock]$StartPep)
    $pf = $Mon.PidFile
    return @{
        StopAgent = { return (Stop-Cp3Role $pf 'agent') }.GetNewClosure()
        StartAgentAndWait = { $ok = & $StartAgent; Invoke-Cp3MonitorAudit $Mon 'after the agent restarted'; return $ok }.GetNewClosure()
        PepExitInfo = { return (Get-Cp3RoleExitInfo $pf 'pep') }.GetNewClosure()
        RestartPep = { $ok = & $StartPep; Invoke-Cp3MonitorAudit $Mon 'after the PEP restarted'; return $ok }.GetNewClosure()
        PortsListening = { return (Get-Cp3PortStatus) }
        BeginPlannedExit = { param($role, $step) Enter-Cp3PlannedExit $Mon.Expect $Mon.PidFile $Mon.Job $role $step }.GetNewClosure()
        EndPlannedExit = { param($role, $step, $exitInfo) Exit-Cp3PlannedExit $Mon.Expect $Mon.PidFile $Mon.Job $role $step $exitInfo }.GetNewClosure()
    }
}

# ---------------------------------------------------------------- shutdown verification (C4)
# The stop results are lines like '<role> pid <n>: <result>'. Only 'stopped' and 'already-gone' count as a successful cleanup:
# 'REFUSED (...)' (the record did not match the live process) and anything else is a failure, as is any error in a shutdown step.
function Get-Cp3CleanupProblems($StopResults, $ShutdownErrors) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($StopResults)) { if ([string]$r -notmatch ': (stopped|already-gone)$') { $out.Add('cleanup did not succeed: ' + [string]$r) } }
    foreach ($e in @($ShutdownErrors)) { $out.Add('a shutdown step failed: ' + [string]$e) }
    return $out.ToArray()
}

# One row per recorded process: has it exited?  A process is only counted as gone when it can be shown to be gone.
function Get-Cp3RecordExitTable([string]$PidFile) {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Read-Cp3PidFile $PidFile)) {
        $s = Get-Cp3RecordState $r
        $rows.Add([pscustomobject]@{ Role = [string]$r.Role; Pid = [int]$r.Pid; Exited = (-not $s.Running); ExitCode = $s.ExitCode; Source = [string]$s.Source })
    }
    return $rows.ToArray()
}

# Job members that are neither recorded processes nor an acceptable console host (see Get-Cp3UnrecordedMemberProblem), plus recorded
# processes that are still members. Used after the stop loop; processes that are on their way out are given a few seconds by the caller.
function Get-Cp3JobLeftovers([IntPtr]$Job, [string]$PidFile) {
    $recordedPids = @(Read-Cp3PidFile $PidFile | ForEach-Object { [int]$_.Pid })
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($jp in @(Get-Cp3JobPids $Job)) {
        if ($recordedPids -contains $jp) { $out.Add(('recorded process pid {0} is still a member of the Job Object' -f $jp)); continue }
        $why = Get-Cp3UnrecordedMemberProblem $jp $recordedPids
        if ($why) { $out.Add($why) }
    }
    return $out.ToArray()
}

# Pid + start time of every job member right now (best effort), so that after the job is closed each one can be shown to be gone.
function Get-Cp3JobSnapshot([IntPtr]$Job) {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($jp in @(Get-Cp3JobPids $Job)) {
        $ticks = 0L
        $p = Get-Cp3ProcessOrNull $jp
        if ($null -ne $p) { try { $ticks = [long]$p.StartTime.ToUniversalTime().Ticks } catch { $ticks = 0L } }
        $rows.Add([pscustomobject]@{ Pid = [int]$jp; StartUtcTicks = $ticks })
    }
    return $rows.ToArray()
}

# Members of a snapshot that are still running (same pid and, when it was known, same start time).
function Get-Cp3SnapshotSurvivors($Snapshot) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Snapshot)) {
        $p = Get-Cp3ProcessOrNull ([int]$s.Pid)
        if ($null -eq $p) { continue }
        $same = $true
        if ([long]$s.StartUtcTicks -ne 0L) { try { $same = ([long]$p.StartTime.ToUniversalTime().Ticks -eq [long]$s.StartUtcTicks) } catch { $same = $true } }
        if ($same) { $out.Add(('pid {0} (a former Job Object member) is still running' -f $s.Pid)) }
    }
    return $out.ToArray()
}
