<#
.SYNOPSIS
  Draws the Everwell Hospital icons (a white medical cross inside a teal ring on deep navy; original artwork) into web\icons and web\favicon.png
  using System.Drawing.
.DESCRIPTION
  Needs nothing from the internet and changes nothing outside the web folder. Re-run it only if the artwork should change.
    icon-192.png, icon-512.png            : "any" icons (rounded square)
    icon-maskable-512.png                 : full-bleed square with the symbol inside the safe zone (Android adaptive icon)
    favicon.png                           : 32 x 32
  Colours: deep navy #0b2545 (the interface's navigation colour) and teal #27b5a6 (the interface's accent family), white cross.
#>
[CmdletBinding()]
param([string]$WebDir)
$ErrorActionPreference = 'Stop'
if (-not $WebDir) { $WebDir = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path 'web' }
Add-Type -AssemblyName System.Drawing

function New-RoundRectPath([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return , $p
}

# One medical cross (two rounded bars) centred on (cx, cy): arm length = $len, bar thickness = $thick
function New-CrossPath([double]$cx, [double]$cy, [double]$len, [double]$thick) {
    $r = [single]($thick * 0.30)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $v = New-RoundRectPath ([single]($cx - $thick / 2)) ([single]($cy - $len / 2)) ([single]$thick) ([single]$len) $r
    $h = New-RoundRectPath ([single]($cx - $len / 2)) ([single]($cy - $thick / 2)) ([single]$len) ([single]$thick) $r
    $path.AddPath($v, $false)
    $path.AddPath($h, $false)
    $v.Dispose(); $h.Dispose()
    # both bars overlap in the middle: winding fill mode makes the union solid
    $path.FillMode = [System.Drawing.Drawing2D.FillMode]::Winding
    return , $path
}

function Save-Icon([int]$size, [bool]$maskable, [string]$file) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $navy = [System.Drawing.ColorTranslator]::FromHtml('#0b2545')
        $teal = [System.Drawing.ColorTranslator]::FromHtml('#27b5a6')
        $bg = New-Object System.Drawing.SolidBrush($navy)                      # flat deep navy, no gradient
        if ($maskable) { $g.FillRectangle($bg, 0, 0, $size, $size) }
        else {
            $path = New-RoundRectPath 0 0 $size $size ($size * 0.22)
            $g.FillPath($bg, $path)
            $path.Dispose()
        }
        $bg.Dispose()

        # symbol: teal ring (outer diameter D) with a white medical cross inside, centred
        $cx = $size / 2.0; $cy = $size / 2.0
        $D = $size * $(if ($size -le 48) { 0.78 } elseif ($maskable) { 0.50 } else { 0.62 })
        $stroke = [math]::Max(2.0, $D * 0.095)
        $pen = New-Object System.Drawing.Pen($teal, [single]$stroke)
        $g.DrawEllipse($pen, [single]($cx - $D / 2 + $stroke / 2), [single]($cy - $D / 2 + $stroke / 2), [single]($D - $stroke), [single]($D - $stroke))
        $pen.Dispose()
        $inner = $D - 2 * $stroke
        $cross = New-CrossPath $cx $cy ($inner * 0.62) ($inner * 0.215)
        $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $g.FillPath($white, $cross)
        $white.Dispose(); $cross.Dispose()
    } finally { $g.Dispose() }
    $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("wrote {0} ({1} x {1}, {2} bytes)" -f $file, $size, (Get-Item -LiteralPath $file).Length)
}

$icons = Join-Path $WebDir 'icons'
$null = New-Item -ItemType Directory -Force -Path $icons
Save-Icon 192 $false (Join-Path $icons 'icon-192.png')
Save-Icon 512 $false (Join-Path $icons 'icon-512.png')
Save-Icon 512 $true  (Join-Path $icons 'icon-maskable-512.png')
Save-Icon 32  $false (Join-Path $WebDir 'favicon.png')
