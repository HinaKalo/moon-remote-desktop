<#
.SYNOPSIS
  Builds and tests every part of Moon Remote: Rust core, Go server, C# app.

.EXAMPLE
  ./scripts/build.ps1            # build + test all
  ./scripts/build.ps1 -Only core # one part: core | server | app
  ./scripts/build.ps1 -NoTest
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'core', 'server', 'web', 'app')]
    [string]$Only = 'all',
    [switch]$NoTest,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Invoke-Step([string]$Name, [string]$Dir, [scriptblock]$Body) {
    Write-Host "==> $Name" -ForegroundColor Cyan
    Push-Location (Join-Path $root $Dir)
    try {
        # Native tools (cargo, go, dotnet) write progress to stderr; Windows PowerShell 5.1
        # turns that into errors under 'Stop'. Success is judged by the exit code instead.
        $ErrorActionPreference = 'Continue'
        & $Body
        if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit $LASTEXITCODE)" }
    }
    finally { Pop-Location }
}

if ($Only -in 'all', 'core') {
    $cargoProfile = if ($Configuration -eq 'Release') { @('--release') } else { @() }
    Invoke-Step 'core: clippy' 'core' { cargo clippy --all-targets @cargoProfile -- -D warnings }
    if (-not $NoTest) { Invoke-Step 'core: test' 'core' { cargo test @cargoProfile } }
}

if ($Only -in 'all', 'server') {
    # sso.moonl.cloud/sdk/go comes from the SSO's own module proxy, not proxy.golang.org.
    if (-not $env:GOPRIVATE) { $env:GOPRIVATE = 'sso.moonl.cloud' }
    # Real-EasyTier integration tests run when the pinned binaries were fetched.
    $etDir = Join-Path $root 'third_party/easytier/windows-x86_64'
    if (-not $env:MRD_TEST_ET_DIR -and (Test-Path (Join-Path $etDir 'easytier-core.exe'))) { $env:MRD_TEST_ET_DIR = $etDir }
    Invoke-Step 'server: gofmt' 'server' {
        $unformatted = gofmt -l .
        if ($unformatted) { Write-Host "gofmt needed: $unformatted"; $global:LASTEXITCODE = 1 }
    }
    Invoke-Step 'server: vet' 'server' { go vet ./... }
    if (-not $NoTest) { Invoke-Step 'server: test' 'server' { go test ./... } }
    Invoke-Step 'server: build' 'server' { go build -o bin/moon-remote-server.exe ./cmd/moon-remote-server }
}

if ($Only -in 'all', 'web') {
    if (-not $NoTest) { Invoke-Step 'web: test (SPAKE2 vectors)' 'server/web' { npm test } }
    Invoke-Step 'web: build' 'server/web' { npm run build }
}

if ($Only -in 'all', 'app') {
    Invoke-Step 'app: build' 'app' { dotnet build MoonRemote.slnx -c $Configuration -nologo -warnaserror }
    if (-not $NoTest) { Invoke-Step 'app: test' 'app' { dotnet test MoonRemote.slnx -c $Configuration --no-build -nologo } }
}

Write-Host 'All steps succeeded.' -ForegroundColor Green
