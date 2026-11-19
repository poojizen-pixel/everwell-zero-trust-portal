<#
.SYNOPSIS
  CP3 Phase A: builds the patched scratch tree from the VERIFIED BACKUP (never from the live project) and verifies it.
.DESCRIPTION
  1. Copies the 62 listed legacy files from the backup folder into <RunDir>\tree, each hash-checked against the manifest of the original 116 files.
  2. Copies 3 build-tooling files (my CP2 scripts; they cannot be in a backup made before CP2) and checks them against the CP2b snapshot manifest.
  3. Applies the 18 exact-line edits of patches.json to the COPIES (the edit needs the exact original line, otherwise it aborts).
  4. Verifies the patched files three independent ways (expected text built from the spec, an LCS line diff, an independent hash) and
     checks every file of the tree. Then runs the static gates. ANY failure stops the script; nothing is weakened or skipped.
  Nothing is built, started, downloaded or installed here. The project, the backup and the live database are only read.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\cp3\New-Cp3Tree.ps1 -RunDir <work>\cp3-... -EvidenceDir <evidence>\phaseA
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunDir,
    [Parameter(Mandatory = $true)][string]$EvidenceDir,
    [string]$WorkRoot,
    [string]$BackupDir = 'C:\Ap_project_backup_2026-10-11',
    [string]$OriginalManifest = 'C:\Ap_project_evidence\CP2\manifest_project_before_cp2.txt',
    [string]$ToolingManifest = 'C:\Ap_project_evidence\CP2b\snapshot_scripts_tests\snapshot_manifest.txt',
    [string]$PatchSpec
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\cp3_lib.ps1"
$repo = Get-RepoRoot
if (-not $PatchSpec) { $PatchSpec = Join-Path $PSScriptRoot 'patches.json' }

$log = New-Object System.Collections.Generic.List[string]
function Say([string]$s) { $log.Add($s); Write-Host $s }
function Fail([string]$s) { Say ('GATE FAILED: ' + $s); throw ('GATE FAILED: ' + $s) }

try {
    $work = Get-WorkRoot $WorkRoot
    Assert-WorkRootSafe $work
    $RunDir = [System.IO.Path]::GetFullPath($RunDir).TrimEnd('\')
    if (-not (Test-PathInside $RunDir $work)) { Fail "RunDir '$RunDir' is not inside the work folder '$work'" }
    if (Test-PathInside $RunDir $repo) { Fail 'RunDir is inside the repository' }
    $tree = Join-Path $RunDir 'tree'
    if (Test-Path -LiteralPath $tree) { Fail "the scratch tree already exists: $tree" }
    $runFwd = ConvertTo-Cp3Fwd $RunDir
    $BackupDir = [System.IO.Path]::GetFullPath($BackupDir).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { Fail "backup folder not found: $BackupDir" }
    New-Item -ItemType Directory -Force -Path $EvidenceDir, $tree | Out-Null

    $spec = [System.IO.File]::ReadAllText($PatchSpec, $script:Cp3Utf8) | ConvertFrom-Json
    $specHash = Get-Sha256Hex $PatchSpec
    Say ('patch specification : ' + $PatchSpec + '  sha256 ' + $specHash)
    Say ('backup (sole source for legacy files): ' + $BackupDir)
    Say ('scratch tree        : ' + $tree)
    Say ('run folder token    : ' + $runFwd)

    $orig = Read-Cp3Manifest $OriginalManifest
    $toolMan = Read-Cp3Manifest $ToolingManifest
    Say ('original manifest   : ' + $orig.Count + ' files (' + $OriginalManifest + ')')

    # ------------------------------------------------------------ 1. copy the legacy files from the backup, hash-checked
    $copyRows = New-Object System.Collections.Generic.List[string]
    $copyRows.Add('legacy files copied from the backup (hash of backup file = manifest hash = hash of the copy):')
    $copyList = @($spec.copyList)
    if ($copyList.Count -ne 62) { Fail "the copy list has $($copyList.Count) entries, expected 62" }
    foreach ($rel in $copyList) {
        if (-not $orig.ContainsKey($rel)) { Fail "$rel is not in the original manifest" }
        $src = Join-Path $BackupDir ($rel -replace '/', '\')
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Fail "missing in the backup: $rel" }
        $hSrc = Get-Sha256Hex $src
        if ($hSrc -ne $orig[$rel].Hash) { Fail "backup file differs from the original manifest: $rel" }
        $dst = Join-Path $tree ($rel -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dst
        $hDst = Get-Sha256Hex $dst
        if ($hDst -ne $hSrc) { Fail "copy differs from the source: $rel" }
        $copyRows.Add(('  OK  {0}  {1,10}  {2}' -f $hDst, $orig[$rel].Size, $rel))
    }
    Say ('copied and verified : ' + $copyList.Count + ' legacy files')

    # ------------------------------------------------------------ 2. build tooling (not legacy code; copied from the accepted CP2 scripts)
    $copyRows.Add('')
    $copyRows.Add('build tooling copied from the project scripts folder (hash = CP2b snapshot manifest):')
    foreach ($rel in @($spec.toolingFiles)) {
        if (-not $toolMan.ContainsKey($rel)) { Fail "$rel is not in the CP2b snapshot manifest" }
        $src = Join-Path $repo ($rel -replace '/', '\')
        if ((Get-Sha256Hex $src) -ne $toolMan[$rel].Hash) { Fail "project file differs from the CP2b snapshot manifest: $rel" }
        $dst = Join-Path $tree ($rel -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dst
        if ((Get-Sha256Hex $dst) -ne $toolMan[$rel].Hash) { Fail "tooling copy differs: $rel" }
        $copyRows.Add(('  OK  {0}  {1,10}  {2}' -f $toolMan[$rel].Hash, $toolMan[$rel].Size, $rel))
    }
    Say ('tooling files       : ' + @($spec.toolingFiles).Count + ' (checked against the CP2b snapshot manifest)')
    Write-Cp3Text (Join-Path $EvidenceDir '02_tree_copy_verification.txt') $copyRows.ToArray()

    # ------------------------------------------------------------ 3. patch + 4. verify, file by file
    $recordRows = New-Object System.Collections.Generic.List[string]
    $diffRows = New-Object System.Collections.Generic.List[string]
    $fcRows = New-Object System.Collections.Generic.List[string]
    $hashRows = New-Object System.Collections.Generic.List[string]
    $expectedHashes = @{}
    $totalEdits = 0
    $recordRows.Add('exact edits (line numbers refer to the ORIGINAL files; {RUN} = ' + $runFwd + ')')
    $hashRows.Add('patched files: SHA-256 before (backup) and after (scratch copy)')
    foreach ($pf in @($spec.patchedFiles)) {
        $rel = [string]$pf.path
        $edits = @($pf.edits)
        $src = Join-Path $BackupDir ($rel -replace '/', '\')
        $dst = Join-Path $tree ($rel -replace '/', '\')
        $origText = Read-Cp3Utf8File $src
        $origParts = Split-Cp3Lines $origText
        # the spec's original text must equal the real line of the BACKUP file (checked here, independent of the patcher)
        foreach ($e in $edits) {
            $n = [int]$e.line
            if ($e.op -eq 'insert-after') { $expectLine = [string]$e.anchor } else { $expectLine = [string]$e.original }
            if ($n -gt $origParts.Lines.Count -or $origParts.Lines[$n - 1] -cne $expectLine) { Fail "$rel line ${n}: the backup line does not match the specification" }
        }
        Invoke-Cp3PatchFile -SourcePath $src -DestPath $dst -Edits $edits -RunFwd $runFwd -RunPlaceholder ([string]$spec.runPlaceholder)
        $newText = Read-Cp3Utf8File $dst
        $newParts = Split-Cp3Lines $newText
        $exp = Get-Cp3ExpectedPatched -OrigLines $origParts.Lines -Edits $edits -RunFwd $runFwd -RunPlaceholder ([string]$spec.runPlaceholder)
        # check A: the patched file equals the expected text, line by line and in length
        if ($newParts.Lines.Count -ne $exp.Lines.Count) { Fail "$rel has $($newParts.Lines.Count) lines after patching, expected $($exp.Lines.Count)" }
        for ($i = 0; $i -lt $exp.Lines.Count; $i++) {
            if ($newParts.Lines[$i] -cne $exp.Lines[$i]) { Fail "$rel line $($i + 1) differs from the expected patched text" }
        }
        if ($newParts.EndsWithNewline -ne $origParts.EndsWithNewline) { Fail "${rel}: trailing newline changed" }
        # check B: an independent line diff must list exactly the spec's changes
        $ops = Get-Cp3LineDiff $origParts.Lines $newParts.Lines
        $problems = @(Compare-Cp3DiffToSpec $ops $exp.Changes)
        if ($problems.Count -gt 0) { Fail ("$rel diff does not match the specification: " + ($problems -join '; ')) }
        # check C: independent hash of the expected file
        $expHash = Get-Cp3TextSha256 (Join-Cp3Lines $exp.Lines $origParts.EndsWithNewline)
        $actHash = Get-Sha256Hex $dst
        if ($expHash -ne $actHash) { Fail "$rel hash $actHash differs from the expected $expHash" }
        $expectedHashes[$rel] = $expHash
        $totalEdits += $edits.Count
        foreach ($e in $edits) {
            if ($e.op -eq 'replace') {
                $recordRows.Add(('edit {0,2} [{1}] {2}:{3} replace' -f $e.id, $e.kind, $rel, $e.line))
                $recordRows.Add('      was : ' + [string]$e.original)
                $recordRows.Add('      now : ' + ([string]$e.replacement).Replace([string]$spec.runPlaceholder, $runFwd))
            } else {
                $recordRows.Add(('edit {0,2} [{1}] {2}: insert after original line {3} (anchor: {4})' -f $e.id, $e.kind, $rel, $e.line, [string]$e.anchor))
                $recordRows.Add('      new : ' + ([string]$e.text).Replace([string]$spec.runPlaceholder, $runFwd))
            }
        }
        foreach ($d in (Format-Cp3Diff $rel $ops)) { $diffRows.Add($d) }
        $diffRows.Add('')
        $fcRows.Add('=== fc.exe /N  ' + $rel)
        $fc = Invoke-Native -File (Join-Path $env:SystemRoot 'System32\fc.exe') -Arguments @('/N', $src, $dst) -WorkingDirectory $RunDir -TimeoutSec 60
        foreach ($l in @($fc.StdOut -split "`r?`n")) { $fcRows.Add($l) }
        $hashRows.Add(('{0}  before {1}' -f $rel, (Get-Sha256Hex $src)))
        $hashRows.Add(('{0}  after  {1}' -f (' ' * $rel.Length), $actHash))
        Say ('patched and verified: ' + $rel + ' (' + $edits.Count + ' edit(s)); three independent checks agree')
    }
    if ($totalEdits -ne [int]$spec.expectedChangedLines) { Fail "$totalEdits edits applied, the specification expects $($spec.expectedChangedLines)" }
    if (@($spec.patchedFiles).Count -ne [int]$spec.expectedFilesChanged) { Fail 'unexpected number of patched files' }
    Write-Cp3Text (Join-Path $EvidenceDir '03_patch_records.txt') $recordRows.ToArray()
    Write-Cp3Text (Join-Path $EvidenceDir '04_patch_diff.txt') $diffRows.ToArray()
    Write-Cp3Text (Join-Path $EvidenceDir '04_patch_fc_output.txt') $fcRows.ToArray()
    Write-Cp3Text (Join-Path $EvidenceDir '05_patched_file_hashes.txt') $hashRows.ToArray()

    # ------------------------------------------------------------ 5. every file of the tree
    $manifest = @(Get-Cp3TreeManifest $tree)
    $expectedPaths = @($copyList) + @($spec.toolingFiles)
    $gateRows = New-Object System.Collections.Generic.List[string]
    $gateRows.Add('G-S1  whole-tree check')
    if ($manifest.Count -ne $expectedPaths.Count) { Fail "the tree has $($manifest.Count) files, expected $($expectedPaths.Count)" }
    $unpatchedChecked = 0
    foreach ($m in $manifest) {
        if ($expectedPaths -cnotcontains $m.Path) { Fail "unexpected file in the tree: $($m.Path)" }
        if ($expectedHashes.ContainsKey($m.Path)) {
            if ($m.Hash -ne $expectedHashes[$m.Path]) { Fail "patched file hash mismatch: $($m.Path)" }
        } elseif ($orig.ContainsKey($m.Path)) {
            if ($m.Hash -ne $orig[$m.Path].Hash) { Fail "unpatched legacy file differs from the original manifest: $($m.Path)" }
            $unpatchedChecked++
        } elseif ($toolMan.ContainsKey($m.Path)) {
            if ($m.Hash -ne $toolMan[$m.Path].Hash) { Fail "tooling file differs from the snapshot manifest: $($m.Path)" }
        } else { Fail "file without a reference hash: $($m.Path)" }
    }
    $gateRows.Add(('  PASS  {0} files; {1} unpatched legacy files byte-identical to the originals; {2} patched files equal the independently computed expectation; 3 tooling files equal the snapshot' -f $manifest.Count, $unpatchedChecked, $expectedHashes.Count))
    if (@($manifest | Where-Object { $_.Path -match '(?i)\.db(-wal|-shm)?$' }).Count -ne 0) { Fail 'a database file is present in the tree' }
    $gateRows.Add('  PASS  no database file (.db, .db-wal, .db-shm) in the tree')

    # ------------------------------------------------------------ 6. static gates G-S2 and G-S3
    $gateRows.Add('G-S2  no path into the live project or the backups survives in any file of the tree')
    $needles = @($spec.forbiddenTreeStrings)
    $hits = @(Find-Cp3Needles -Root $tree -Needles $needles)
    if ($hits.Count -gt 0) { foreach ($h in $hits) { $gateRows.Add(('  FOUND {0} ({1}) in {2}' -f $h.Needle, $h.Form, $h.File)) } ; Write-Cp3Text (Join-Path $EvidenceDir '06_static_gates.txt') $gateRows.ToArray(); Fail ("forbidden string found in the tree: " + (($hits | ForEach-Object { $_.File }) -join ', ')) }
    $gateRows.Add(('  PASS  searched all {0} files (ASCII and UTF-16LE) for: {1}' -f $manifest.Count, ($needles -join ' | ')))
    $gateRows.Add('G-S3  binding sites')
    $bad = @(Test-Cp3ForbiddenPatterns -Root $tree -Patterns @($spec.forbiddenSourcePatterns))
    if ($bad.Count -gt 0) { foreach ($b in $bad) { $gateRows.Add('  FOUND ' + $b) } ; Write-Cp3Text (Join-Path $EvidenceDir '06_static_gates.txt') $gateRows.ToArray(); Fail ($bad -join '; ') }
    $gateRows.Add('  PASS  no INADDR_ANY and no "new InetSocketAddress(port)" in any .java/.cpp/.h/.hpp file')
    $siteHits = @(Get-Cp3SourceHits -Root $tree -Regex ([string]$spec.bindSiteRegex))
    $sitePro = @(Compare-Cp3BindSites -Hits $siteHits -Expected @($spec.bindSitesAfterPatch))
    if ($sitePro.Count -gt 0) { foreach ($p in $sitePro) { $gateRows.Add('  PROBLEM ' + $p) } ; Write-Cp3Text (Join-Path $EvidenceDir '06_static_gates.txt') $gateRows.ToArray(); Fail ('binding sites differ from the expected list: ' + ($sitePro -join '; ')) }
    $gateRows.Add(('  PASS  the {0} binding-related lines equal the expected list exactly:' -f $siteHits.Count))
    foreach ($s in $siteHits) { $gateRows.Add(('        {0}:{1}  {2}' -f $s.File, $s.Line, $s.Text)) }
    Write-Cp3Text (Join-Path $EvidenceDir '06_static_gates.txt') $gateRows.ToArray()
    Say 'static gates G-S1, G-S2, G-S3: PASS'

    # ------------------------------------------------------------ 7. manifest of the patched tree
    $digest = Get-Cp3ManifestDigest $manifest
    Write-Cp3Text (Join-Path $EvidenceDir '07_tree_manifest_after_patch.txt') (@(Format-Cp3Manifest $manifest) + @('', ('tree digest (sha256 of the sorted manifest lines): ' + $digest)))
    Say ('tree manifest       : ' + $manifest.Count + ' files, digest ' + $digest)
    Write-Cp3Text (Join-Path $EvidenceDir '01_tree_creation_log.txt') $log.ToArray()
    return [pscustomobject]@{ TreeRoot = $tree; RunFwd = $runFwd; Manifest = $manifest; Digest = $digest; SpecHash = $specHash; PatchedHashes = $expectedHashes }
} catch {
    Say ('tree creation stopped: ' + $_.Exception.Message)
    try { Write-Cp3Text (Join-Path $EvidenceDir '01_tree_creation_log.txt') $log.ToArray() } catch { }
    throw
}
