<#
.SYNOPSIS
  Downloads the pinned EasyTier release, verifies it, and lays out the files Moon Remote ships.

.DESCRIPTION
  Pinned: EasyTier v2.7.1 (tag commit 0d9c52b1, 2026-11-16). Checksums come from the
  release's SHA256SUMS (see spikes/easytier/REPORT.md).

  Only easytier-core and easytier-cli are kept. On Windows, Npcap's Packet.dll from the zip
  is NOT shipped (not redistributable); our no-op stub (core/crates/packet-stub) is built and
  copied instead. wintun.dll, WinDivert and easytier-web are not needed (no TUN mode).

  Output: third_party/easytier/<platform>/  (git-ignored)

.EXAMPLE
  ./scripts/fetch-easytier.ps1                      # windows-x86_64
  ./scripts/fetch-easytier.ps1 -Platform linux-x86_64   # server binaries
#>
[CmdletBinding()]
param(
    [ValidateSet('windows-x86_64', 'linux-x86_64')]
    [string]$Platform = 'windows-x86_64'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$Version = 'v2.7.1'
$Pinned = @{
    'windows-x86_64' = '6279ce18906f345345780b2f0c507125fcae861a54c45cc62efe58d5312de46b'
    'linux-x86_64'   = '8dc4f8576c7a4978c1f000630014b75ec88d172f6cb10935e72092ddd5ec7a9a'
}

$zipName = "easytier-$Platform-$Version.zip"
$url = "https://github.com/EasyTier/EasyTier/releases/download/$Version/$zipName"
$cache = Join-Path $root "third_party/easytier/.cache"
$out = Join-Path $root "third_party/easytier/$Platform"
New-Item -ItemType Directory -Force $cache, $out | Out-Null

$zip = Join-Path $cache $zipName
if (-not (Test-Path $zip)) {
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile "$zip.part" -UseBasicParsing
    Move-Item -Force "$zip.part" $zip
}
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
if ($hash -ne $Pinned[$Platform]) {
    Remove-Item -Force $zip
    throw "Checksum mismatch for $zipName`n  expected $($Pinned[$Platform])`n  got      $hash"
}
Write-Host "Checksum OK: $hash"

# Extract into a fresh, empty directory (downloaded content is untrusted until checked).
$tmp = Join-Path $cache "x-$Platform"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
Expand-Archive -Path $zip -DestinationPath $tmp

$exe = if ($Platform -like 'windows-*') { '.exe' } else { '' }
foreach ($name in "easytier-core$exe", "easytier-cli$exe") {
    $src = Get-ChildItem -Path $tmp -Recurse -File -Filter $name | Select-Object -First 1
    if (-not $src) { throw "$name not found in $zipName" }
    Copy-Item -Force $src.FullName (Join-Path $out $name)
}

if ($Platform -like 'windows-*') {
    Write-Host 'Building Packet.dll stub (replaces Npcap, which may not be redistributed)'
    Push-Location (Join-Path $root 'core')
    try {
        $ErrorActionPreference = 'Continue'
        cargo build --release -p packet-stub
        if ($LASTEXITCODE -ne 0) { throw 'packet-stub build failed' }
    }
    finally { $ErrorActionPreference = 'Stop'; Pop-Location }
    Copy-Item -Force (Join-Path $root 'core/target/release/packet.dll') (Join-Path $out 'Packet.dll')

    # Guard: the shipped Packet.dll must be ours, never the one from the zip.
    $npcap = Get-ChildItem -Path $tmp -Recurse -File -Filter 'Packet.dll' | Select-Object -First 1
    if ($npcap -and (Get-FileHash $npcap.FullName).Hash -eq (Get-FileHash (Join-Path $out 'Packet.dll')).Hash) {
        throw 'Refusing to ship Npcap Packet.dll'
    }
}
Remove-Item -Recurse -Force $tmp

# Smoke test the copied binaries where they can run.
if ($Platform -like 'windows-*' -and $IsWindows -ne $false) {
    $v = & (Join-Path $out 'easytier-core.exe') --version
    if ($LASTEXITCODE -ne 0 -or $v -notmatch '2\.7\.1') { throw "easytier-core --version failed: $v" }
    Write-Host "easytier-core: $v"
}

Get-ChildItem $out | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "EasyTier $Version ($Platform) ready in $out"
