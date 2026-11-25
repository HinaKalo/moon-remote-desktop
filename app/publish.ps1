<#
.SYNOPSIS
  Package MoonRemote for distribution and report the output size.

.EXAMPLE
  ./publish.ps1                         # trimmed self-contained single .exe (default)
  ./publish.ps1 -Mode aot               # Native AOT
  ./publish.ps1 -Mode all -Zip          # every mode, plus a .zip of each
  ./publish.ps1 -Mode trimmed -Runtime linux-x64
#>
[CmdletBinding()]
param(
    # fd      = framework-dependent single .exe (needs .NET 10 runtime installed, smallest)
    # trimmed = self-contained, trimmed, compressed single .exe (runs anywhere)
    # aot     = Native AOT (fastest start-up; needs the C++ toolchain, same OS only)
    [ValidateSet('fd', 'trimmed', 'aot', 'all')]
    [string]$Mode = 'trimmed',

    # Target runtime, e.g. win-x64, win-arm64, linux-x64, osx-arm64. Empty = this machine.
    [string]$Runtime = '',

    # Also create artifacts/publish/<mode>.zip
    [switch]$Zip
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'src/MoonRemote/MoonRemote.csproj'
$profiles = [ordered]@{ fd = 'FrameworkDependent'; trimmed = 'SelfContained'; aot = 'NativeAot' }
$modes = if ($Mode -eq 'all') { @($profiles.Keys) } else { @($Mode) }
$results = @()

# Native AOT on Windows locates MSVC through vswhere.exe on PATH; the VS installer does not add it.
if ($modes -contains 'aot' -and $env:OS -eq 'Windows_NT') {
    $installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
    if ((Test-Path (Join-Path $installer 'vswhere.exe')) -and -not (Get-Command vswhere.exe -ErrorAction SilentlyContinue)) {
        $env:PATH = "$installer;$env:PATH"
    }
}

foreach ($m in $modes) {
    $out = Join-Path $PSScriptRoot "artifacts/publish/$m"
    if (Test-Path $out) { Remove-Item -Recurse -Force $out }

    $publishArgs = @('publish', $project, '-c', 'Release', "-p:PublishProfile=$($profiles[$m])", '-o', $out, '-nologo')
    if ($Runtime) { $publishArgs += @('-r', $Runtime) }

    Write-Host "==> $m ($($profiles[$m]))" -ForegroundColor Cyan
    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for mode '$m'." }

    $files = Get-ChildItem $out -File -Recurse
    $bytes = ($files | Measure-Object Length -Sum).Sum
    $row = [pscustomobject]@{
        Mode   = $m
        Files  = $files.Count
        SizeMB = [math]::Round($bytes / 1MB, 1)
        ZipMB  = $null
        Output = $out
    }

    if ($Zip) {
        $zipPath = "$out.zip"
        if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
        Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zipPath -CompressionLevel Optimal
        $row.ZipMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    }

    $results += $row
}

$results | Format-Table -AutoSize
