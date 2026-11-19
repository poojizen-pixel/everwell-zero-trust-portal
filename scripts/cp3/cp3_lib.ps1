# cp3_lib.ps1 - helpers for the CP3 baseline scripts.  Dot-source it:  . "$PSScriptRoot\cp3_lib.ps1"
# Windows PowerShell 5.1, ASCII only (a non-ASCII character here would be read with the wrong code page).
# Nothing in this file downloads anything, starts a listener, or changes a system setting.
. "$PSScriptRoot\..\common.ps1"

$script:Cp3PepHost = '127.0.0.1'
$script:Cp3PepPort = 15000
$script:Cp3TestPorts = @(15000, 18443, 19000)
$script:Cp3Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Cp3Latin1 = [System.Text.Encoding]::GetEncoding(28591)
$script:Cp3Virtual = $false
$script:Cp3VirtualNow = 0.0

# ---------------------------------------------------------------- hashing, text, manifests
function Get-Cp3BytesSha256([byte[]]$Bytes) {
    if ($null -eq $Bytes) { $Bytes = New-Object byte[] 0 }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $h) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

function Get-Cp3TextSha256([string]$Text) { return (Get-Cp3BytesSha256 ($script:Cp3Utf8.GetBytes($Text))) }

function Test-Cp3BytesEqual([byte[]]$A, [byte[]]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
    return $true
}

function ConvertTo-Cp3Fwd([string]$Path) { return ($Path -replace '\\', '/') }

function Write-Cp3Text([string]$Path, [string[]]$Lines) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $text = ''
    if ($Lines.Count -gt 0) { $text = ([string]::Join("`r`n", $Lines)) + "`r`n" }
    [System.IO.File]::WriteAllText($Path, $text, $script:Cp3Utf8)
}

# Manifest line format (same as the earlier checkpoints): <sha256> <size> <relative/path>
function Read-Cp3Manifest([string]$Path) {
    $h = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        if ($line -match '^([0-9a-f]{64})\s+(\d+)\s+(.+)$') { $h[$Matches[3]] = [pscustomobject]@{ Hash = $Matches[1]; Size = [long]$Matches[2] } }
    }
    return $h
}

function Get-Cp3TreeManifest([string]$Root) {
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in (Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force)) {
        $rel = $f.FullName.Substring($rootFull.Length + 1).Replace('\', '/')
        $rows.Add([pscustomobject]@{ Path = $rel; Hash = (Get-Sha256Hex $f.FullName); Size = [long]$f.Length })
    }
    return @($rows.ToArray() | Sort-Object -Property Path)
}

function Format-Cp3Manifest($Entries) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($e in $Entries) { $out.Add(('{0} {1,12}  {2}' -f $e.Hash, $e.Size, $e.Path)) }
    return $out.ToArray()
}

function Get-Cp3ManifestDigest($Entries) {
    $lines = @(Format-Cp3Manifest $Entries)
    return (Get-Cp3TextSha256 ([string]::Join("`n", $lines)))
}

# ---------------------------------------------------------------- LF line handling and the exact-line patch tool
function Split-Cp3Lines([string]$Text) {
    if ($Text.IndexOf([char]13) -ge 0) { throw 'the file contains a carriage return; the patch tool only handles LF files' }
    $ends = $Text.EndsWith("`n")
    $body = $Text
    if ($ends) { $body = $Text.Substring(0, $Text.Length - 1) }
    return [pscustomobject]@{ Lines = [string[]]$body.Split([char]10); EndsWithNewline = $ends }
}

function Join-Cp3Lines([string[]]$Lines, [bool]$EndsWithNewline) {
    $t = [string]::Join("`n", $Lines)
    if ($EndsWithNewline) { $t += "`n" }
    return $t
}

function Read-Cp3Utf8File([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { throw "BOM found in $Path" }
    $text = $script:Cp3Utf8.GetString($bytes)
    if (-not (Test-Cp3BytesEqual ($script:Cp3Utf8.GetBytes($text)) $bytes)) { throw "not a lossless UTF-8 file: $Path" }
    return $text
}

# Implementation 1: applies the edits (original line numbers) bottom to top and writes the patched file.
function Invoke-Cp3PatchFile {
    param([string]$SourcePath, [string]$DestPath, $Edits, [string]$RunFwd, [string]$RunPlaceholder)
    $text = Read-Cp3Utf8File $SourcePath
    $parts = Split-Cp3Lines $text
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.AddRange($parts.Lines)
    $sorted = @($Edits | Sort-Object -Property line -Descending)
    foreach ($e in $sorted) {
        $n = [int]$e.line
        if ($n -lt 1 -or $n -gt $lines.Count) { throw "edit $($e.id): line $n is outside the file ($($lines.Count) lines)" }
        $cur = $lines[$n - 1]
        if ($e.op -eq 'replace') {
            if ($cur -cne [string]$e.original) { throw "edit $($e.id): line $n does not match the expected original text" }
            $lines[$n - 1] = ([string]$e.replacement).Replace($RunPlaceholder, $RunFwd)
        } elseif ($e.op -eq 'insert-after') {
            if ($cur -cne [string]$e.anchor) { throw "edit $($e.id): line $n does not match the expected anchor text" }
            $lines.Insert($n, ([string]$e.text).Replace($RunPlaceholder, $RunFwd))
        } else {
            throw "edit $($e.id): unknown operation '$($e.op)'"
        }
    }
    $newText = Join-Cp3Lines ($lines.ToArray()) $parts.EndsWithNewline
    [System.IO.File]::WriteAllBytes($DestPath, $script:Cp3Utf8.GetBytes($newText))
}

# Implementation 2 (independent of the patcher): builds the expected patched lines straight from the ORIGINAL file and the spec,
# plus the list of changed lines with their new line numbers. The checks compare this with the file on disk.
function Get-Cp3ExpectedPatched {
    param([string[]]$OrigLines, $Edits, [string]$RunFwd, [string]$RunPlaceholder)
    $repl = @{}
    $ins = @{}
    foreach ($e in $Edits) {
        if ($e.op -eq 'replace') { $repl[[int]$e.line] = ([string]$e.replacement).Replace($RunPlaceholder, $RunFwd) }
        elseif ($e.op -eq 'insert-after') { $ins[[int]$e.line] = ([string]$e.text).Replace($RunPlaceholder, $RunFwd) }
    }
    $out = New-Object System.Collections.Generic.List[string]
    $changes = New-Object System.Collections.Generic.List[object]
    for ($i = 1; $i -le $OrigLines.Count; $i++) {
        if ($repl.ContainsKey($i)) {
            $out.Add($repl[$i])
            $changes.Add([pscustomobject]@{ Kind = 'replace'; OldLine = $i; NewLine = $out.Count; OldText = $OrigLines[$i - 1]; NewText = $repl[$i] })
        } else {
            $out.Add($OrigLines[$i - 1])
        }
        if ($ins.ContainsKey($i)) {
            $out.Add($ins[$i])
            $changes.Add([pscustomobject]@{ Kind = 'insert'; OldLine = 0; NewLine = $out.Count; OldText = $null; NewText = $ins[$i] })
        }
    }
    return [pscustomobject]@{ Lines = $out.ToArray(); Changes = $changes.ToArray() }
}

# Implementation 3: a plain longest-common-subsequence line diff of two files (no knowledge of the spec).
function Get-Cp3LineDiff {
    param([string[]]$A, [string[]]$B)
    $n = $A.Count
    $m = $B.Count
    $dp = New-Object 'int[,]' ($n + 1), ($m + 1)
    for ($i = $n - 1; $i -ge 0; $i--) {
        $i1 = $i + 1
        for ($j = $m - 1; $j -ge 0; $j--) {
            $j1 = $j + 1
            if ($A[$i] -ceq $B[$j]) {
                $diag = $dp[$i1, $j1]
                $dp[$i, $j] = $diag + 1
            } else {
                $down = $dp[$i1, $j]
                $right = $dp[$i, $j1]
                if ($down -ge $right) { $dp[$i, $j] = $down } else { $dp[$i, $j] = $right }
            }
        }
    }
    $ops = New-Object System.Collections.Generic.List[object]
    $i = 0
    $j = 0
    while ($i -lt $n -and $j -lt $m) {
        if ($A[$i] -ceq $B[$j]) { $i++; $j++; continue }
        $i1 = $i + 1
        $j1 = $j + 1
        $down = $dp[$i1, $j]
        $right = $dp[$i, $j1]
        if ($down -ge $right) { $ops.Add([pscustomobject]@{ Op = '-'; Line = ($i + 1); Text = $A[$i] }); $i++ }
        else { $ops.Add([pscustomobject]@{ Op = '+'; Line = ($j + 1); Text = $B[$j] }); $j++ }
    }
    while ($i -lt $n) { $ops.Add([pscustomobject]@{ Op = '-'; Line = ($i + 1); Text = $A[$i] }); $i++ }
    while ($j -lt $m) { $ops.Add([pscustomobject]@{ Op = '+'; Line = ($j + 1); Text = $B[$j] }); $j++ }
    return $ops.ToArray()
}

function Format-Cp3Diff([string]$RelPath, $Ops) {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("--- a/$RelPath   (verified backup; '-' lines carry the ORIGINAL line numbers)")
    $out.Add("+++ b/$RelPath   (scratch copy; '+' lines carry the NEW line numbers)")
    foreach ($o in $Ops) { $out.Add(('{0}{1,4}| {2}' -f $o.Op, $o.Line, $o.Text)) }
    return $out.ToArray()
}

# Compares the LCS diff with the spec-derived change list. Returns a list of problems (empty = identical).
function Compare-Cp3DiffToSpec {
    param($Ops, $Changes)
    $problems = New-Object System.Collections.Generic.List[string]
    $removed = @($Ops | Where-Object { $_.Op -eq '-' })
    $added = @($Ops | Where-Object { $_.Op -eq '+' })
    $expRemoved = @($Changes | Where-Object { $_.Kind -eq 'replace' })
    if ($removed.Count -ne $expRemoved.Count) { $problems.Add("removed lines: diff has $($removed.Count), spec expects $($expRemoved.Count)") }
    if ($added.Count -ne $Changes.Count) { $problems.Add("added lines: diff has $($added.Count), spec expects $($Changes.Count)") }
    foreach ($c in $expRemoved) {
        $hit = @($removed | Where-Object { $_.Line -eq $c.OldLine -and $_.Text -ceq $c.OldText })
        if ($hit.Count -ne 1) { $problems.Add("original line $($c.OldLine) is not reported as removed with the expected text") }
    }
    foreach ($c in $Changes) {
        $hit = @($added | Where-Object { $_.Line -eq $c.NewLine -and $_.Text -ceq $c.NewText })
        if ($hit.Count -ne 1) { $problems.Add("new line $($c.NewLine) is not reported as added with the expected text") }
    }
    return $problems.ToArray()
}

# ---------------------------------------------------------------- static gates
function Find-Cp3Needles {
    param([string]$Root, [string[]]$Needles)
    $hits = New-Object System.Collections.Generic.List[object]
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    foreach ($f in (Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force)) {
        $s = $script:Cp3Latin1.GetString([System.IO.File]::ReadAllBytes($f.FullName))
        foreach ($n in $Needles) {
            $wide = [string]::Join('', @($n.ToCharArray() | ForEach-Object { [string]$_ + [string][char]0 }))
            $rel = $f.FullName.Substring($rootFull.Length + 1).Replace('\', '/')
            if ($s.IndexOf($n, [System.StringComparison]::Ordinal) -ge 0) { $hits.Add([pscustomobject]@{ File = $rel; Needle = $n; Form = 'ascii' }) }
            if ($s.IndexOf($wide, [System.StringComparison]::Ordinal) -ge 0) { $hits.Add([pscustomobject]@{ File = $rel; Needle = $n; Form = 'utf-16le' }) }
        }
    }
    return $hits.ToArray()
}

function Get-Cp3SourceHits {
    param([string]$Root, [string]$Regex)
    $hits = New-Object System.Collections.Generic.List[object]
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $files = @(Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force | Where-Object { $_.Extension -in @('.java', '.cpp', '.h', '.hpp') })
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($rootFull.Length + 1).Replace('\', '/')
        if ($rel.StartsWith('build/')) { continue }
        $n = 0
        foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
            $n++
            if ($line -cmatch $Regex) { $hits.Add([pscustomobject]@{ File = $rel; Line = $n; Text = $line.Trim() }) }
        }
    }
    return $hits.ToArray()
}

# Compares the binding-site hits with the expected list (both directions, as multisets of "file|text").
function Compare-Cp3BindSites {
    param($Hits, $Expected)
    $problems = New-Object System.Collections.Generic.List[string]
    $have = @{}
    foreach ($h in $Hits) { $k = $h.File + '|' + $h.Text; if ($have.ContainsKey($k)) { $have[$k]++ } else { $have[$k] = 1 } }
    $want = @{}
    foreach ($e in $Expected) { $k = [string]$e.file + '|' + [string]$e.text; if ($want.ContainsKey($k)) { $want[$k]++ } else { $want[$k] = 1 } }
    foreach ($k in $have.Keys) { if (-not $want.ContainsKey($k) -or $want[$k] -ne $have[$k]) { $problems.Add("unexpected binding-related line: $k") } }
    foreach ($k in $want.Keys) { if (-not $have.ContainsKey($k) -or $have[$k] -ne $want[$k]) { $problems.Add("expected binding-related line not found: $k") } }
    return $problems.ToArray()
}

function Test-Cp3ForbiddenPatterns {
    param([string]$Root, [string[]]$Patterns)
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Patterns) {
        foreach ($h in @(Get-Cp3SourceHits -Root $Root -Regex $p)) { $found.Add("forbidden pattern '$p' at $($h.File):$($h.Line)") }
    }
    return $found.ToArray()
}

# ---------------------------------------------------------------- clock (virtual in dry runs)
function Get-Cp3Now {
    if ($script:Cp3Virtual) { return [double]$script:Cp3VirtualNow }
    return ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0)
}

# C2: a hook (a scriptblock) runs at the START of every slice of at most one second of every wait, so that the run monitor keeps watching while
# a scenario waits. The hook runs BEFORE the sleep and the sleep only covers what is left of the requested time, so a slow hook does not
# stretch a wait. An exception thrown by the hook ends the wait and propagates: that is how a violation stops a run.
$script:Cp3WaitHook = $null
function Set-Cp3WaitHook([scriptblock]$Hook) { $script:Cp3WaitHook = $Hook }
function Clear-Cp3WaitHook { $script:Cp3WaitHook = $null }

function Wait-Cp3Seconds([double]$Seconds) {
    if ($Seconds -le 0) { return }
    if ($script:Cp3Virtual) {
        $left = $Seconds
        while ($left -gt 0.000000001) {
            if ($null -ne $script:Cp3WaitHook) { & $script:Cp3WaitHook }
            $slice = [Math]::Min(1.0, $left)
            $script:Cp3VirtualNow += $slice
            $left -= $slice
        }
        return
    }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($Seconds * 1000.0)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($null -ne $script:Cp3WaitHook) { & $script:Cp3WaitHook }
        $remainingMs = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remainingMs -le 0) { break }
        Start-Sleep -Milliseconds ([int][Math]::Ceiling([Math]::Min(1000.0, $remainingMs)))
    }
}

# ---------------------------------------------------------------- random secrets (kept in memory only)
function New-Cp3RandomString([int]$Length, [string]$Alphabet) {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 4
    $alen = [long]$Alphabet.Length
    $limit = [long]4294967296 - ([long]4294967296 % $alen)
    $sb = New-Object System.Text.StringBuilder
    try {
        for ($i = 0; $i -lt $Length; $i++) {
            do {
                $rng.GetBytes($buf)
                $v = [long][BitConverter]::ToUInt32($buf, 0)
            } while ($v -ge $limit)
            [void]$sb.Append($Alphabet[[int]($v % $alen)])
        }
    } finally { $rng.Dispose() }
    return $sb.ToString()
}

# 57 characters: a-z without l, A-Z without I and O, digits 2-9 (built from character codes, not written as a literal)
function Get-Cp3PasswordAlphabet {
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($code in (97..122 + 65..90 + 50..57)) {
        $c = [char]$code
        if (@('l', 'I', 'O') -cnotcontains [string]$c) { $chars.Add($c) }
    }
    return (-join $chars.ToArray())
}
function New-Cp3Password { return (New-Cp3RandomString 24 (Get-Cp3PasswordAlphabet)) }
function New-Cp3Pin { return (New-Cp3RandomString 8 '0123456789') }

# ---------------------------------------------------------------- redaction (keyed fingerprints, never plain hash prefixes)
function New-Cp3Redactor {
    $key = New-Object byte[] 32
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($key) } finally { $rng.Dispose() }
    return [pscustomobject]@{ Key = $key; Values = (New-Object System.Collections.Generic.List[object]) }
}

function Get-Cp3Fingerprint($Redactor, [string]$Value) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (, $Redactor.Key)
    try { $d = $h.ComputeHash($script:Cp3Utf8.GetBytes($Value)) } finally { $h.Dispose() }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt 4; $i++) { [void]$sb.Append($d[$i].ToString('x2')) }
    return $sb.ToString()
}

function Add-Cp3Secret($Redactor, [string]$Value, [string]$Label) {
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -lt 4) { return }
    foreach ($v in $Redactor.Values) { if ($v.Value -ceq $Value) { return } }
    $Redactor.Values.Add([pscustomobject]@{ Value = $Value; Label = $Label; Fp = (Get-Cp3Fingerprint $Redactor $Value) })
}

function Protect-Cp3Text($Redactor, [string]$Text) {
    if ($null -eq $Text) { return $null }
    $t = $Text
    foreach ($v in @($Redactor.Values | Sort-Object { $_.Value.Length } -Descending)) {
        $t = $t.Replace($v.Value, ('<' + $v.Label + ':' + $v.Fp + '>'))
    }
    $t = [regex]::Replace($t, '(?i)(authorization:\s*bearer\s+)\S+', '${1}<redacted>')
    $t = [regex]::Replace($t, '(?i)(bearer\s+)[A-Za-z0-9_\-\.=+/]{12,}', '${1}<redacted>')
    $t = [regex]::Replace($t, '(?i)(x-stepup-pin:\s*)\S+', '${1}<redacted>')
    $t = [regex]::Replace($t, '(?i)"(token|password|step_up_pin|pin|ssn|billing|password_hash|step_up_pin_hash|signature)"\s*:\s*"[^"]*"', '"$1":"<redacted>"')
    $t = [regex]::Replace($t, '[A-Za-z0-9_\-]{16,}\.[A-Fa-f0-9]{64}', '<token>')
    $t = [regex]::Replace($t, '\b\d{3}-\d{2}-\d{4}\b', '<ssn-shaped>')
    $t = [regex]::Replace($t, '\b[A-Fa-f0-9]{64}\b', '<hex64>')
    return $t
}

# ---------------------------------------------------------------- raw HTTP (bytes in, bytes out; the target is locked to 127.0.0.1:15000)
function New-Cp3RequestBytes {
    param([string]$Method, [string]$Path, [hashtable]$Headers, [byte[]]$Body)
    $head = New-Object System.Text.StringBuilder
    [void]$head.Append($Method + ' ' + $Path + " HTTP/1.1`r`n")
    [void]$head.Append('Host: ' + $script:Cp3PepHost + ':' + $script:Cp3PepPort + "`r`n")
    [void]$head.Append("Connection: close`r`n")
    if ($null -ne $Headers) { foreach ($k in $Headers.Keys) { [void]$head.Append(([string]$k) + ': ' + ([string]$Headers[$k]) + "`r`n") } }
    if ($null -ne $Body -and $Body.Length -gt 0) { [void]$head.Append('Content-Length: ' + $Body.Length + "`r`n") }
    [void]$head.Append("`r`n")
    $hb = $script:Cp3Latin1.GetBytes($head.ToString())
    if ($null -eq $Body -or $Body.Length -eq 0) { return $hb }
    $all = New-Object byte[] ($hb.Length + $Body.Length)
    [Array]::Copy($hb, 0, $all, 0, $hb.Length)
    [Array]::Copy($Body, 0, $all, $hb.Length, $Body.Length)
    return $all
}

# The two crash probes, as exact bytes. Each is ONE request.
function New-Cp3ProbeBytes([string]$Which) {
    $hostLine = 'Host: ' + $script:Cp3PepHost + ':' + $script:Cp3PepPort + "`r`n"
    if ($Which -eq 'P1') {
        return $script:Cp3Latin1.GetBytes("POST /login HTTP/1.1`r`n" + $hostLine + "Content-Length: abc`r`nConnection: close`r`n`r`n")
    }
    if ($Which -eq 'P2') {
        $a = $script:Cp3Latin1.GetBytes("GET /api/public/info HTTP/1.1`r`n" + $hostLine + 'Authorization: Bearer ')
        $b = [byte[]](0xFF, 0xFE)
        $c = $script:Cp3Latin1.GetBytes("`r`nX-Device-Id: probe`r`nConnection: close`r`n`r`n")
        $all = New-Object byte[] ($a.Length + $b.Length + $c.Length)
        [Array]::Copy($a, 0, $all, 0, $a.Length)
        [Array]::Copy($b, 0, $all, $a.Length, $b.Length)
        [Array]::Copy($c, 0, $all, ($a.Length + $b.Length), $c.Length)
        return $all
    }
    throw "unknown probe '$Which'"
}

function Find-Cp3HeaderEnd([byte[]]$Raw) {
    for ($i = 0; $i -le $Raw.Length - 4; $i++) {
        if ($Raw[$i] -eq 13 -and $Raw[$i + 1] -eq 10 -and $Raw[$i + 2] -eq 13 -and $Raw[$i + 3] -eq 10) { return $i }
    }
    return -1
}

function ConvertFrom-Cp3RawResponse([byte[]]$Raw) {
    $r = [pscustomobject]@{ Received = $false; Status = 0; Reason = ''; Headers = @{}; Body = (New-Object byte[] 0); BodyText = '' }
    if ($null -eq $Raw -or $Raw.Length -eq 0) { return $r }
    $end = Find-Cp3HeaderEnd $Raw
    if ($end -lt 0) { return $r }
    $headText = $script:Cp3Latin1.GetString($Raw, 0, $end)
    $lines = $headText -split "`r`n"
    if ($lines[0] -match '^HTTP/1\.[01]\s+(\d{3})\s*(.*)$') { $r.Status = [int]$Matches[1]; $r.Reason = $Matches[2]; $r.Received = $true } else { return $r }
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $c = $lines[$i].IndexOf(':')
        if ($c -gt 0) { $r.Headers[$lines[$i].Substring(0, $c).Trim().ToLowerInvariant()] = $lines[$i].Substring($c + 1).Trim() }
    }
    $start = $end + 4
    $len = $Raw.Length - $start
    if ($r.Headers.ContainsKey('content-length')) {
        $cl = 0
        if ([int]::TryParse($r.Headers['content-length'], [ref]$cl) -and $cl -ge 0 -and $cl -lt $len) { $len = $cl }
    }
    $body = New-Object byte[] $len
    if ($len -gt 0) { [Array]::Copy($Raw, $start, $body, 0, $len) }
    $r.Body = $body
    $r.BodyText = $script:Cp3Utf8.GetString($body)
    return $r
}

# The only function that opens a socket. It has no host or port parameter on purpose.
function Send-Cp3Raw {
    param([byte[]]$RequestBytes, [int]$TimeoutMs = 10000)
    $res = [pscustomobject]@{ Connected = $false; Raw = (New-Object byte[] 0); ClosedBy = ''; Error = '' }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($script:Cp3PepHost, $script:Cp3PepPort, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $res.Error = 'connect timeout'; return $res }
        $client.EndConnect($iar)
        $res.Connected = $true
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $stream = $client.GetStream()
        $stream.Write($RequestBytes, 0, $RequestBytes.Length)
        $stream.Flush()
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 8192
        while ($true) {
            $n = 0
            try { $n = $stream.Read($buf, 0, $buf.Length) }
            catch [System.IO.IOException] {
                if ($_.Exception.InnerException -is [System.Net.Sockets.SocketException] -and $_.Exception.InnerException.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) { $res.ClosedBy = 'timeout' } else { $res.ClosedBy = 'reset' }
                break
            }
            if ($n -le 0) { $res.ClosedBy = 'fin'; break }
            $ms.Write($buf, 0, $n)
        }
        $res.Raw = $ms.ToArray()
    } catch {
        $res.Error = $_.Exception.Message
    } finally {
        $client.Close()
    }
    return $res
}

# ---------------------------------------------------------------- native process with stdin (secrets go over stdin, never on a command line)
$script:Cp3LaunchLog = New-Object System.Collections.Generic.List[string]

function Add-Cp3LaunchLog([string]$Kind, [string]$File, [string[]]$Arguments) {
    $script:Cp3LaunchLog.Add(('{0:yyyy-MM-dd HH:mm:ss}  {1,-9} {2}  {3}' -f (Get-Date), $Kind, $File, ($Arguments -join ' ')))
}

function Invoke-Cp3NativeWithInput {
    param([string]$File, [string[]]$Arguments, [string]$StdIn, [string]$WorkingDirectory, [int]$TimeoutSec = 120, [string]$Kind = 'tool')
    Add-Cp3LaunchLog $Kind $File $Arguments
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = ConvertTo-ArgString $Arguments
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    # write raw UTF-8 bytes to the pipe. NOTE: with a UTF-8 console code page the .NET Process class has already put a byte-order mark
    # at the start of the pipe (seen with a debug program); the Java tool therefore drops a leading BOM. A BOM is never part of a secret.
    if ($null -ne $StdIn -and $StdIn.Length -gt 0) {
        $inBytes = $script:Cp3Utf8.GetBytes($StdIn)
        $p.StandardInput.BaseStream.Write($inBytes, 0, $inBytes.Length)
        $p.StandardInput.BaseStream.Flush()
    }
    $p.StandardInput.Close()
    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { $timedOut = $true; try { $p.Kill() } catch { } ; [void]$p.WaitForExit(5000) }
    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)
    $code = -1
    if (-not $timedOut) { $code = $p.ExitCode }
    return [pscustomobject]@{ ExitCode = $code; TimedOut = $timedOut; StdOut = $outTask.Result; StdErr = $errTask.Result }
}

# ---------------------------------------------------------------- tripwire for files that must not change (size + last-write time; the file is NOT opened)
function Get-Cp3FileStamps([string[]]$Paths) {
    $h = @{}
    foreach ($p in $Paths) {
        if (Test-Path -LiteralPath $p) {
            $i = Get-Item -LiteralPath $p
            $h[$p] = ('{0}|{1}' -f $i.Length, $i.LastWriteTimeUtc.Ticks)
        } else { $h[$p] = 'missing' }
    }
    return $h
}

function Compare-Cp3FileStamps($Before, $After) {
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Before.Keys) { if (-not $After.ContainsKey($k) -or $After[$k] -cne $Before[$k]) { $changed.Add($k) } }
    return $changed.ToArray()
}

# ---------------------------------------------------------------- integrity helpers (C4). They only READ; nothing here deletes, restores or rewrites a file.
# Two sorted line sets (for example the manifest of a folder before and after a run): every line that is in only one of them.
function Compare-Cp3Lines([string[]]$A, [string[]]$B) {
    $sa = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in $A) { [void]$sa.Add($x) }
    $sb = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in $B) { [void]$sb.Add($x) }
    $diff = New-Object System.Collections.Generic.List[string]
    foreach ($x in $A) { if (-not $sb.Contains($x)) { $diff.Add('only before: ' + $x) } }
    foreach ($x in $B) { if (-not $sa.Contains($x)) { $diff.Add('only after : ' + $x) } }
    return $diff.ToArray()
}

# The harness output must show a PASS line for every expected check id, for no other id, once each, and must not be a subset run.
function Get-Cp3HarnessCompletenessProblems([string]$StdOut, [string[]]$Expected) {
    $problems = New-Object System.Collections.Generic.List[string]
    $pass = New-Object System.Collections.Generic.List[string]
    foreach ($ln in ($StdOut -split "`r?`n")) { $m = [regex]::Match($ln, '^PASS\s+(\S+)\s'); if ($m.Success) { $pass.Add($m.Groups[1].Value) } }
    $missing = @($Expected | Where-Object { $pass -notcontains $_ })
    $extra = @($pass | Where-Object { $Expected -notcontains $_ })
    $dups = @($pass | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($missing.Count -gt 0) { $problems.Add('checks without a PASS line: ' + ($missing -join ',')) }
    if ($extra.Count -gt 0) { $problems.Add('PASS lines for unexpected checks: ' + ($extra -join ',')) }
    if ($dups.Count -gt 0) { $problems.Add('checks reported more than once: ' + ($dups -join ',')) }
    # a subset run says so on a line of its own that starts with SUBSET (case-sensitive; the word may appear inside the description of a check)
    if ([regex]::IsMatch($StdOut, '(?m)^SUBSET (RESULT|RUN) \(')) { $problems.Add('the harness reported a subset run') }
    return $problems.ToArray()
}

# Files named in a manifest (relative path -> @{ Hash; Size }, as Read-Cp3Manifest returns it) that are missing or differ under Root.
function Get-Cp3ManifestMismatches([string]$Root, $Manifest) {
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Manifest.Keys | Sort-Object)) {
        $p = Join-Path $Root ($k -replace '/', '\')
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { $bad.Add("missing: $k"); continue }
        if ((Get-Sha256Hex $p) -ne $Manifest[$k].Hash) { $bad.Add("differs: $k") }
    }
    return $bad.ToArray()
}

# ---------------------------------------------------------------- canary / leak scan of written files
function Find-Cp3Leaks {
    param([string[]]$Directories, [string[]]$Canaries)
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($d in $Directories) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $s = $script:Cp3Latin1.GetString([System.IO.File]::ReadAllBytes($f.FullName))
            foreach ($c in $Canaries) {
                if ([string]::IsNullOrEmpty($c)) { continue }
                $wide = [string]::Join('', @($c.ToCharArray() | ForEach-Object { [string]$_ + [string][char]0 }))
                if ($s.IndexOf($c, [System.StringComparison]::Ordinal) -ge 0 -or $s.IndexOf($wide, [System.StringComparison]::Ordinal) -ge 0) { $hits.Add($f.FullName) }
            }
        }
    }
    return $hits.ToArray()
}

# ---------------------------------------------------------------- sensitive-data scan (C5)
# Looks in evidence, test results and program logs for synthetic patient data and for the SHAPES of credentials. A finding carries ONLY a category,
# a location (target label + relative path) and a line number: the matched text and the line are never kept, returned or printed, so a report
# cannot leak what it reports.

# The synthetic patient values, read at run time from the four insertPatient(...) calls of the seeder (nothing is typed in here).
function Get-Cp3PatientMarkers([string]$SeederPath) {
    $text = $script:Cp3Utf8.GetString([System.IO.File]::ReadAllBytes($SeederPath))
    $q = '\s*"([^"]*)"\s*'
    $rx = 'insertPatient\(\s*db\s*,\s*cipher\s*,\s*(\d+)\s*,' + $q + ',' + $q + ',' + $q + ',' + $q + ',' + $q + ',' + $q + '\)\s*;'
    $ms = [regex]::Matches($text, $rx)
    if ($ms.Count -ne 4) { throw ('expected exactly 4 insertPatient(...) calls in the patient seeder, found ' + $ms.Count) }
    $cats = @('patient-name', 'patient-dob', 'patient-diagnosis', 'patient-medication', 'patient-ssn', 'patient-billing')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in $ms) {
        for ($i = 0; $i -lt 6; $i++) {
            $v = $m.Groups[$i + 2].Value
            if ($v.Length -lt 4) { throw ('a patient marker of category ' + $cats[$i] + ' is shorter than 4 characters') }
            $out.Add([pscustomobject]@{ Category = $cats[$i]; Value = $v })
        }
    }
    return $out.ToArray()
}

$script:Cp3Shapes = $null
function Get-Cp3SensitiveShapes {
    if ($null -ne $script:Cp3Shapes) { return $script:Cp3Shapes }
    $defs = @(
        @{ Category = 'ssn-shaped (nnn-nn-nnnn)'; Regex = '\b\d{3}-\d{2}-\d{4}\b'; ResultOnly = $false },
        @{ Category = 'token-shaped (payload.signature)'; Regex = '[A-Za-z0-9_\-]{16,}\.[0-9a-fA-F]{64}'; ResultOnly = $false },
        @{ Category = 'bearer-credential'; Regex = '(?i)bearer\s+(?=[A-Za-z0-9_\-\.=+/]*\d)[A-Za-z0-9_\-\.=+/]{16,}'; ResultOnly = $false },
        @{ Category = 'credential-field-value (json)'; Regex = '(?i)"(password|step_up_pin|pin|token|session_id|ssn|billing|password_hash|step_up_pin_hash|signature)"\s*:\s*"[^<"][^"]*"'; ResultOnly = $false },
        @{ Category = 'step-up-pin-header-value'; Regex = '(?i)x-stepup-pin:\s*[^<\s]\S*'; ResultOnly = $false },
        @{ Category = 'hex64 (hash or signature shaped)'; Regex = '\b[0-9a-fA-F]{64}\b'; ResultOnly = $true }
    )
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($d in $defs) { $list.Add([pscustomobject]@{ Category = $d.Category; Regex = (New-Object System.Text.RegularExpressions.Regex($d.Regex)); ResultOnly = $d.ResultOnly }) }
    $script:Cp3Shapes = $list.ToArray()
    return $script:Cp3Shapes
}

# Files that hold scenario results, transcripts or program output. The 64-hex rule applies only to them: manifests and hash lists
# legitimately consist of SHA-256 values.
function Test-Cp3ResultClassPath([string]$RelPath) {
    $r = $RelPath.Replace('\', '/').ToLowerInvariant()
    $leaf = $r.Substring($r.LastIndexOf('/') + 1)
    if ($leaf -match '^(cp3_results|partial_results|results)\.(json|md)$') { return $true }
    if ($leaf.Contains('transcript')) { return $true }
    if ($r -match '(^|/)(logs|dryrun_baseline)/') { return $true }
    return $false
}

# $Targets : objects with Label and Path (a folder, scanned recursively, or one file)
# $Literals: objects with Category and Value (patient markers, issued secrets); matched exactly, ignoring case for patient-* categories
function Find-Cp3SensitiveMatches {
    param([object[]]$Targets, [object[]]$Literals)
    $shapes = Get-Cp3SensitiveShapes
    $counts = @{}
    $scanned = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($t in $Targets) {
        $path = [string]$t.Path
        if (-not (Test-Path -LiteralPath $path)) { $missing.Add([string]$t.Label); continue }
        $item = Get-Item -LiteralPath $path
        if ($item.PSIsContainer) {
            $files = @(Get-ChildItem -LiteralPath $path -Recurse -File -Force)
            $root = $item.FullName.TrimEnd('\')
        } else {
            $files = @($item)
            $root = $item.DirectoryName
        }
        $n = 0
        $nResultClass = 0
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length + 1)
            $loc = [string]$t.Label + '\' + $rel
            if ($f.Length -gt 8MB) { $skipped.Add($loc + ' (larger than 8 MB, not scanned)'); continue }
            $n++
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $views = New-Object System.Collections.Generic.List[string]
            $views.Add($script:Cp3Latin1.GetString($bytes))
            if ([Array]::IndexOf($bytes, [byte]0) -ge 0) { $views.Add([System.Text.Encoding]::Unicode.GetString($bytes)) }
            $resultClass = Test-Cp3ResultClassPath $rel
            if ($resultClass) { $nResultClass++ }
            foreach ($text in $views) {
                $lines = $text.Split([char]10)
                for ($i = 0; $i -lt $lines.Length; $i++) {
                    $line = $lines[$i]
                    if ($line.Length -eq 0) { continue }
                    foreach ($s in $shapes) {
                        if ($s.ResultOnly -and -not $resultClass) { continue }
                        $c = $s.Regex.Matches($line).Count
                        if ($c -gt 0) { $key = $s.Category + '|' + $loc + '|' + ($i + 1); if ($counts.ContainsKey($key)) { $counts[$key] += $c } else { $counts[$key] = $c } }
                    }
                    foreach ($lit in $Literals) {
                        $cmp = [System.StringComparison]::Ordinal
                        if (([string]$lit.Category).StartsWith('patient-')) { $cmp = [System.StringComparison]::OrdinalIgnoreCase }
                        $from = 0
                        $c = 0
                        while ($true) {
                            $at = $line.IndexOf([string]$lit.Value, $from, $cmp)
                            if ($at -lt 0) { break }
                            $c++
                            $from = $at + [Math]::Max(1, ([string]$lit.Value).Length)
                        }
                        if ($c -gt 0) { $key = [string]$lit.Category + '|' + $loc + '|' + ($i + 1); if ($counts.ContainsKey($key)) { $counts[$key] += $c } else { $counts[$key] = $c } }
                    }
                }
            }
        }
        $scanned.Add([pscustomobject]@{ Label = [string]$t.Label; Path = $path; Files = $n; ResultClassFiles = $nResultClass })
    }
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($k in $counts.Keys) {
        $p = $k.Split('|')
        $findings.Add([pscustomobject]@{ Category = $p[0]; Location = $p[1]; Line = [int]$p[2]; Occurrences = [int]$counts[$k] })
    }
    $sorted = @($findings.ToArray() | Sort-Object -Property Location, Line, Category)
    return [pscustomobject]@{ Findings = $sorted; Targets = $scanned.ToArray(); Skipped = $skipped.ToArray(); MissingTargets = $missing.ToArray() }
}

# The text report. It states what was searched (counts and category names only) and where something was found; it never prints a value.
function Format-Cp3SensitiveReport($Result, $Literals, [string]$Title) {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add($Title)
    $out.Add('categories and locations only: matched values and the lines they were found in are never printed or stored by this scan')
    $out.Add('')
    foreach ($t in $Result.Targets) { $out.Add(('scanned  {0,-34} {1,4} file(s), {2} result/log-class  ({3})' -f $t.Label, $t.Files, $t.ResultClassFiles, $t.Path)) }
    foreach ($m in $Result.MissingTargets) { $out.Add(('MISSING  target "{0}" does not exist' -f $m)) }
    foreach ($s in $Result.Skipped) { $out.Add('SKIPPED  ' + $s) }
    $groups = @($Literals | Group-Object -Property Category | Sort-Object Name)
    $out.Add('')
    $out.Add('literal values searched (count per category; the values themselves are not listed):')
    if ($groups.Count -eq 0) { $out.Add('  (none)') }
    foreach ($g in $groups) { $out.Add(('  {0,-26} {1}' -f $g.Name, $g.Count)) }
    $out.Add('shape rules searched:')
    foreach ($s in (Get-Cp3SensitiveShapes)) {
        $scope = 'every scanned file'
        if ($s.ResultOnly) { $scope = 'result, transcript and log files only' }
        $out.Add(('  {0,-34} {1}' -f $s.Category, $scope))
    }
    $out.Add('')
    $out.Add('matches: ' + @($Result.Findings).Count)
    foreach ($f in $Result.Findings) { $out.Add(('MATCH  category={0}  location={1}  line={2}  occurrences={3}' -f $f.Category, $f.Location, $f.Line, $f.Occurrences)) }
    return $out.ToArray()
}

# C5: what the sensitive-data scan searches for. The patient markers are read from the seeder of the frozen scratch tree; $Issued are the
# values this run generated or was handed (objects with Category and Value).
function Get-Cp3SensitiveLiterals([string]$SeederPath, $Issued) {
    $lit = New-Object System.Collections.Generic.List[object]
    foreach ($m in (Get-Cp3PatientMarkers $SeederPath)) { $lit.Add($m) }
    foreach ($i in @($Issued)) { if ($null -ne $i) { $lit.Add($i) } }
    return $lit.ToArray()
}

# Runs the scan, writes the report (categories and locations only) and returns the result. Callers decide what a finding means.
function Invoke-Cp3SensitiveScan {
    param([object[]]$Targets, [object[]]$Literals, [string]$ReportPath, [string]$Title)
    $res = Find-Cp3SensitiveMatches -Targets $Targets -Literals $Literals
    Write-Cp3Text $ReportPath (Format-Cp3SensitiveReport $res $Literals $Title)
    return $res
}

# One line per problem, never a matched value: a scan that found something, could not find a target, or looked at no file at all.
function Get-Cp3SensitiveScanProblems($Res) {
    $p = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Res.Findings)) { $p.Add(('category={0} location={1} line={2} occurrences={3}' -f $f.Category, $f.Location, $f.Line, $f.Occurrences)) }
    foreach ($m in @($Res.MissingTargets)) { $p.Add('scan target missing: ' + $m) }
    foreach ($t in @($Res.Targets)) { if ($t.Files -lt 1) { $p.Add('scan target without files: ' + $t.Label) } }
    return $p.ToArray()
}
