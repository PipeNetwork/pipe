#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Install')][string]$Version,
    [Parameter(ParameterSetName = 'Install')][string]$Archive,
    [Parameter(ParameterSetName = 'Install')][string]$Sha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')][switch]$Rollback,
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Pipe')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [System.IO.Path]::IsPathRooted($Prefix)) { throw 'Installation prefix must be absolute.' }
if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'This installer requires Windows x86-64.' }
$bin = Join-Path $Prefix 'bin'
$state = Join-Path $Prefix 'installer'
$backups = Join-Path $state 'backups'
New-Item -ItemType Directory -Force -Path $bin, $backups | Out-Null
$lockPath = Join-Path $state 'lock'
$lock = [System.IO.File]::Open($lockPath, 'CreateNew', 'ReadWrite', 'None')
$work = Join-Path $state ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$destination = Join-Path $bin 'pipe.exe'
$previous = Join-Path $state 'previous.json'
$temporary = $null
function Hash([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
try {
    if ($Rollback) {
        $record = Get-Content -Raw -LiteralPath $previous | ConvertFrom-Json
        if ($record.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Invalid rollback record.' }
        $source = Join-Path $backups $record.sha256
        if ((Hash $source) -ne $record.sha256) { throw 'Previous binary checksum changed.' }
    } else {
        $Version = $Version -replace '^v', ''
        if ($Version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$') { throw 'An explicit semantic version is required.' }
        $name = "pipe-v$Version-x86_64-pc-windows-msvc.zip"
        $download = Join-Path $work $name
        if ($Archive) {
            if ($Sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Offline installation requires an independently verified SHA256.' }
            Copy-Item -LiteralPath $Archive -Destination $download
        } else {
            if ($Sha256) { throw '-Sha256 is only accepted with -Archive.' }
            if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'Install GitHub CLI to verify signed provenance, or use a verified offline archive.' }
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $url = "https://github.com/PipeNetwork/pipe/releases/download/v$Version"
            Invoke-WebRequest -UseBasicParsing -Uri "$url/$name" -OutFile $download
            $checksums = (Invoke-WebRequest -UseBasicParsing -Uri "$url/SHA256SUMS").Content
            $checksumEntries = @($checksums -split "`n" | Where-Object { $_ -cmatch ('^[a-f0-9]{64}  ' + [Regex]::Escape($name) + '\r?$') })
            if ($checksumEntries.Count -ne 1) { throw 'Archive is missing from release checksums.' }
            $Sha256 = $checksumEntries[0].Substring(0, 64)
            & gh attestation verify $download --repo PipeNetwork/pipe --source-ref "refs/tags/v$Version"
            if ($LASTEXITCODE -ne 0) { throw 'Signed provenance verification failed.' }
        }
        if ((Hash $download) -ne $Sha256) { throw 'Archive checksum mismatch; existing installation was preserved.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($download)
        try {
            $entries = @($zip.Entries | Where-Object { $_.FullName -ceq 'pipe.exe' })
            if ($entries.Count -ne 1 -or $entries[0].Length -gt 268435456) { throw 'Archive must contain exactly one bounded pipe.exe binary.' }
            $source = Join-Path $work 'pipe.exe'
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $source, $false)
        } finally { $zip.Dispose() }
        $reported = & $source --version
        if ($LASTEXITCODE -ne 0 -or $reported -cne "pipe $Version") { throw 'Binary version differs from the requested release.' }
    }
    $temporary = Join-Path $bin ('.pipe-installing-' + [Guid]::NewGuid().ToString('N') + '.exe')
    Copy-Item -LiteralPath $source -Destination $temporary
    if (Test-Path -LiteralPath $destination) {
        $oldHash = Hash $destination
        $backup = Join-Path $backups $oldHash
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $destination -Destination $backup }
        if ((Hash $backup) -ne $oldHash) { throw 'Backup checksum differs.' }
        # Atomic same-volume replacement; failure (including an in-use executable) preserves the old file.
        [IO.File]::Replace($temporary, $destination, $null)
        @{ sha256 = $oldHash } | ConvertTo-Json | Set-Content -LiteralPath $previous -Encoding UTF8
    } else { [IO.File]::Move($temporary, $destination) }
    Write-Host "Installed $(& $destination --version) at $destination"
    Write-Host "Add $bin to PATH if needed. Existing configuration and recovery records are retained."
} finally {
    if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -Force -LiteralPath $temporary }
    Remove-Item -Force -Recurse -LiteralPath $work
    $lock.Dispose()
    Remove-Item -Force -LiteralPath $lockPath
}
