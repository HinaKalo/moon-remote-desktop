[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaseArchive,
    [Parameter(Mandatory)][string]$AppDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$base = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $BaseArchive).Path)
try {
    $entries = @{}
    foreach ($entry in $base.Entries) {
        if ($entry.Name) { $entries[$entry.FullName.Replace('\', '/')] = $entry }
    }

    $directory = (Resolve-Path -LiteralPath $AppDirectory).Path
    $files = [Collections.Generic.List[string]]::new()
    $checks = [Collections.Generic.List[string]]::new()
    $checks.Add('procedure VerifyUpdateBase;')
    $checks.Add('begin')
    $reused = 0
    foreach ($file in Get-ChildItem -LiteralPath $directory -File -Recurse | Sort-Object FullName) {
        $relative = [IO.Path]::GetRelativePath($directory, $file.FullName)
        if ($relative -notmatch '^[A-Za-z0-9_.\\-]+$') { throw "Unexpected installer payload path: $relative" }
        $parent = Split-Path -Path $relative -Parent
        $dest = if ($parent) { '{#Bin}\' + $parent } else { '{#Bin}' }
        $entry = $entries[$relative.Replace('\', '/')]
        if ($entry -and $entry.Length -eq $file.Length) {
            $stream = $entry.Open()
            try { $baseHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)) }
            finally { $stream.Dispose() }
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            if ($hash -eq $baseHash) {
                $files.Add(('Source: "{{#BaseBin}}\{0}"; DestDir: "{1}"; ExternalSize: {2}; Flags: external ignoreversion; AfterInstall: VerifyDeltaFile(''{0}'', ''{3}'')' -f $relative, $dest, $file.Length, $hash))
                $checks.Add(("  VerifyBaseFile('{0}', '{1}');" -f $relative, $hash))
                $reused++
                continue
            }
        }
        $files.Add(('Source: "{0}"; DestDir: "{1}"; Flags: ignoreversion' -f $file.FullName, $dest))
    }
    if (!$reused -or $reused -eq $files.Count) { throw 'Expected both changed and reusable installer files.' }
    $checks.Add('end;')
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'delta-files.iss') -Value $files -Encoding utf8
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'delta-checks.iss') -Value $checks -Encoding utf8
    Write-Host "Delta installer embeds $($files.Count - $reused) files and reuses $reused verified base files."
}
finally { $base.Dispose() }
