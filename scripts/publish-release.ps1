<#
.SYNOPSIS
  Builds and publishes Moon Remote Desktop and/or the standalone Core host to relhub on Moon.
#>
[CmdletBinding()]
param(
    [string]$Notes = "Release update",
    [ValidateSet('all', 'desktop', 'host')]
    [string]$Scope = 'all',
    [int[]]$AdditionalDeltaBases = @(),
    [switch]$SkipRustBuild,
    [switch]$BuildOnly,
    [switch]$PublishBuilt
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$previousHostBuild = $env:MOONRD_HOST_BUILD
Push-Location $root
try {
    $code = [int](git rev-list --count HEAD)
    $ver = "0.1.$code"
    $desktop = $Scope -ne 'host'
    $hostPackage = $Scope -ne 'desktop'
    $env:MOONRD_HOST_BUILD = "$code"
    Write-Host "==> Moon Remote v$ver ($Scope, versionCode=$code)" -ForegroundColor Cyan

    $setupName = "MoonRemote-Setup-$ver-x64.exe"
    $deltaBases = @(($AdditionalDeltaBases + ($code - 1)) | Sort-Object -Unique)
    foreach ($baseCode in $deltaBases) {
        if ($baseCode -lt 1 -or $baseCode -ge $code) { throw "Invalid delta base versionCode: $baseCode" }
    }
    $patchZip = "artifacts/moon-remote-$ver-windows-x64-patch.zip"
    $fullZip = "artifacts/moon-remote-$ver-windows-x64.zip"
    $hostZip = "artifacts/moon-remote-$ver-windows-x64-host.zip"
    if (-not $PublishBuilt) {
        if (-not $SkipRustBuild) {
            $crates = @('-p', 'moonrd-agent', '-p', 'moonrd-host', '-p', 'packet-stub')
            if ($desktop) { $crates += @('-p', 'moonrd-ffi', '-p', 'moonrd-service') }
            cargo build --locked --manifest-path core/Cargo.toml --release @crates
            if ($LASTEXITCODE -ne 0) { throw "cargo release build failed" }
        }

        $appStage = if ($desktop) { 'artifacts/release-win-x64' } else { 'artifacts/core-stage' }
        New-Item -ItemType Directory -Force -Path $appStage | Out-Null
        if ($desktop) {
            dotnet publish app/src/MoonRemote/MoonRemote.csproj -c Release -r win-x64 --self-contained true -p:Version=$ver -p:DebugType=none -o $appStage -nologo -v minimal
            if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
            Copy-Item "core/target/release/moonrd_ffi.dll" "$appStage/" -Force
            Copy-Item "core/target/release/moonrd-service.exe" "$appStage/" -Force
        }
        Copy-Item "core/target/release/moonrd-agent.exe" "$appStage/" -Force
        Copy-Item "core/target/release/moonrd-host.exe" "$appStage/" -Force
        New-Item -ItemType Directory -Force -Path "$appStage/easytier" | Out-Null
        foreach ($name in @('easytier-core.exe', 'easytier-cli.exe')) {
            $binary = Get-Item -LiteralPath "third_party/easytier/windows-x86_64/$name"
            if ($binary.Length -lt 1MB) { throw "Run scripts/fetch-easytier.ps1 before building a release." }
            Copy-Item -LiteralPath $binary.FullName -Destination "$appStage/easytier/" -Force
        }
        Copy-Item "core/target/release/packet.dll" "$appStage/easytier/Packet.dll" -Force
        Copy-Item "docs/THIRD_PARTY_NOTICES.md" "$appStage/" -Force

        if ($desktop) {
            $compiler = @(
                (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
                "$env:LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe"
                "${env:ProgramFiles(x86)}/Inno Setup 6/ISCC.exe"
            ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
            if (-not $compiler) { throw "Inno Setup 6 compiler (ISCC.exe) is required." }
            & $compiler /Qp "/DAppVersion=$ver" installer/MoonRemote.iss
            if ($LASTEXITCODE -ne 0) { throw "Windows installer compilation failed" }
            foreach ($baseCode in $deltaBases) {
                $baseVersion = "0.1.$baseCode"
                $baseArchive = "artifacts/moon-remote-$baseVersion-windows-x64.zip"
                $deltaSetup = "artifacts/installer/MoonRemote-Setup-$ver-from-$baseVersion-x64.exe"
                if (Test-Path -LiteralPath $deltaSetup) { Remove-Item -LiteralPath $deltaSetup -Force }
                if (!(Test-Path -LiteralPath $baseArchive)) {
                    if ($baseCode -in $AdditionalDeltaBases) { throw "Missing requested base archive: $baseArchive" }
                    continue
                }
                $deltaIncludes = New-Item -ItemType Directory -Force "artifacts/installer/delta-$baseVersion-to-$ver"
                & "$PSScriptRoot/new-setup-delta.ps1" -BaseArchive $baseArchive -AppDirectory $appStage -OutputDirectory $deltaIncludes.FullName
                & $compiler /Qp "/DAppVersion=$ver" "/DBaseVersion=$baseVersion" "/DDeltaFiles=$($deltaIncludes.FullName)\delta-files.iss" "/DDeltaChecks=$($deltaIncludes.FullName)\delta-checks.iss" installer/MoonRemote.iss
                if ($LASTEXITCODE -ne 0) { throw "Windows delta installer compilation failed" }
            }

            # Legacy clients expect zip packages on these two channels.
            $patchFiles = foreach ($f in @("MoonRemote.exe", "MoonRemote.dll", "MoonRemote.deps.json", "MoonRemote.runtimeconfig.json", "System.Security.Cryptography.ProtectedData.dll", "moonrd_ffi.dll", "moonrd-service.exe", "moonrd-agent.exe", "moonrd-host.exe")) {
                (Get-Item -LiteralPath (Join-Path $appStage $f)).FullName
            }
            if (Test-Path $patchZip) { Remove-Item $patchZip -Force }
            Compress-Archive -LiteralPath $patchFiles -DestinationPath $patchZip -CompressionLevel Optimal

            # 2. Full zip
            if (Test-Path $fullZip) { Remove-Item $fullZip -Force }
            Compress-Archive -Path "$appStage/*" -DestinationPath $fullZip -CompressionLevel Optimal
        }
        if ($hostPackage) {
            $hostFiles = @("moonrd-host.exe", "moonrd-agent.exe", "easytier", "THIRD_PARTY_NOTICES.md") | ForEach-Object { Join-Path $appStage $_ }
            Compress-Archive -LiteralPath $hostFiles -DestinationPath $hostZip -CompressionLevel Optimal -Force
        }
    }
    $packages = [ordered]@{}
    if ($desktop) {
        $packages['windows-x64-setup'] = "artifacts/installer/$setupName"
        foreach ($baseCode in $deltaBases) {
            $deltaSetup = "artifacts/installer/MoonRemote-Setup-$ver-from-0.1.$baseCode-x64.exe"
            if (Test-Path -LiteralPath $deltaSetup) { $packages["windows-x64-setup-$baseCode"] = $deltaSetup }
            elseif ($baseCode -in $AdditionalDeltaBases) { throw "Missing requested delta installer: $deltaSetup" }
        }
        $packages['windows-x64'] = $fullZip
        $packages['windows-x64-patch'] = $patchZip
    }
    if ($hostPackage) { $packages['windows-x64-host'] = $hostZip }
    $files = @(foreach ($path in $packages.Values) { Get-Item -LiteralPath $path })
    $files | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,2)}}

    if ($BuildOnly) { return }
    $paths = @($files.FullName)
    scp -o ConnectTimeout=10 @paths moon:/tmp/
    if ($LASTEXITCODE -ne 0) { throw "scp failed" }

    $quotedNotes = "'" + $Notes.Replace("'", ("'" + '"' + "'" + '"' + "'")) + "'"
    $publish = foreach ($platform in $packages.Keys) {
        $name = Split-Path $packages[$platform] -Leaf
        "relhub publish -app moon-remote -platform $platform -file /tmp/$name -version $ver -code $code -notes $quotedNotes; "
    }
    $cleanup = ($files | ForEach-Object { "/tmp/$($_.Name)" }) -join ' '
    $remoteCmd = "set -e; export RELHUB_DATA=/var/lib/release-publish; " + ($publish -join '') + "rm -f $cleanup; relhub list"
    ssh -o ConnectTimeout=10 -o BatchMode=yes moon $remoteCmd
    if ($LASTEXITCODE -ne 0) { throw "relhub publish failed" }
}
finally { $env:MOONRD_HOST_BUILD = $previousHostBuild; Pop-Location }
