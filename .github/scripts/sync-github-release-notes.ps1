[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $Repository,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $Tag,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $NotesPath,

  [string] $TempDirectory = $env:RUNNER_TEMP,

  [switch] $SkipMissingRelease,

  [switch] $RequireUpdaterManifest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Gh {
  param(
    [Parameter(Mandatory = $true)]
    [string[]] $Arguments
  )

  $output = @(& gh @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) {
    $detail = ($output | ForEach-Object { [string] $_ }) -join [Environment]::NewLine
    throw "gh $($Arguments -join ' ') failed: $detail"
  }
  return $output
}

function Get-Release {
  $output = Invoke-Gh @(
    "api",
    "-H", "Accept: application/vnd.github+json",
    "repos/$Repository/releases/tags/$Tag"
  )
  return (($output | ForEach-Object { [string] $_ }) -join [Environment]::NewLine) |
    ConvertFrom-Json -Depth 100
}

function Rename-ReleaseAsset {
  param(
    [Parameter(Mandatory = $true)]
    [long] $AssetId,

    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $null = Invoke-Gh @(
    "api",
    "--method", "PATCH",
    "-H", "Accept: application/vnd.github+json",
    "repos/$Repository/releases/assets/$AssetId",
    "-f", "name=$Name",
    "--silent"
  )
}

function Remove-ReleaseAsset {
  param(
    [Parameter(Mandatory = $true)]
    [long] $AssetId
  )

  $null = Invoke-Gh @(
    "api",
    "--method", "DELETE",
    "-H", "Accept: application/vnd.github+json",
    "repos/$Repository/releases/assets/$AssetId",
    "--silent"
  )
}

if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
  throw "Invalid GitHub repository name: $Repository"
}
if ($Tag -notmatch '^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
  throw "Invalid release tag: $Tag"
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "GitHub CLI is required."
}

$resolvedNotesPath = (Resolve-Path -LiteralPath $NotesPath).Path
$helperPath = Join-Path $PSScriptRoot "update-updater-manifest-notes.ps1"
if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
  throw "Updater manifest helper is missing: $helperPath"
}
if ([string]::IsNullOrWhiteSpace($TempDirectory)) {
  $TempDirectory = [System.IO.Path]::GetTempPath()
}
if (-not (Test-Path -LiteralPath $TempDirectory -PathType Container)) {
  throw "Temporary directory does not exist: $TempDirectory"
}

$null = & $helperPath `
  -NotesPath $resolvedNotesPath `
  -PreviewOnly

try {
  $release = Get-Release
} catch {
  if ($SkipMissingRelease -and $_.Exception.Message -match '(HTTP 404|Not Found)') {
    Write-Host "::notice title=Release not found::$Tag does not exist yet; skipping."
    return
  }
  throw
}

$null = Invoke-Gh @(
  "release", "edit", $Tag,
  "--repo", $Repository,
  "--notes-file", $resolvedNotesPath
)
Write-Host "Updated GitHub Release $Tag from $(Split-Path $resolvedNotesPath -Leaf)."

$release = Get-Release
$manifestAssets = @($release.assets | Where-Object { $_.name -eq "latest.json" })
if ($manifestAssets.Count -eq 0) {
  if ($RequireUpdaterManifest) {
    throw "GitHub Release $Tag has no latest.json updater manifest."
  }
  Write-Host "::notice title=Updater manifest not found::$Tag has no latest.json; skipping updater notes."
  return
}
if ($manifestAssets.Count -ne 1) {
  throw "GitHub Release $Tag has multiple latest.json assets."
}

$runMarker = if ([string]::IsNullOrWhiteSpace($env:GITHUB_RUN_ID)) {
  "local"
} else {
  $env:GITHUB_RUN_ID
}
$attemptMarker = if ([string]::IsNullOrWhiteSpace($env:GITHUB_RUN_ATTEMPT)) {
  "1"
} else {
  $env:GITHUB_RUN_ATTEMPT
}
$nonce = [guid]::NewGuid().ToString("N")
$safeTag = $Tag -replace '[^0-9A-Za-z.-]', '-'
$workDirectory = Join-Path $TempDirectory "rustforge-release-notes-$safeTag-$nonce"
$null = New-Item -ItemType Directory -Path $workDirectory

$null = Invoke-Gh @(
  "release", "download", $Tag,
  "--repo", $Repository,
  "--pattern", "latest.json",
  "--dir", $workDirectory
)
$manifestPath = Join-Path $workDirectory "latest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
  throw "Failed to download latest.json for $Tag."
}

$expectedVersion = $Tag -replace '^v', ''
$updateResult = & $helperPath `
  -ManifestPath $manifestPath `
  -NotesPath $resolvedNotesPath `
  -ExpectedVersion $expectedVersion
if (-not $updateResult.Changed) {
  Write-Host "Updater manifest for $Tag already contains the expected Chinese notes."
  return
}

$stagedName = "latest.pending-$runMarker-$attemptMarker-$nonce.json"
$stagedPath = Join-Path $workDirectory $stagedName
Copy-Item -LiteralPath $manifestPath -Destination $stagedPath
$null = Invoke-Gh @(
  "release", "upload", $Tag, $stagedPath,
  "--repo", $Repository
)

$release = Get-Release
$stagedAssets = @($release.assets | Where-Object { $_.name -eq $stagedName })
if ($stagedAssets.Count -ne 1) {
  throw "Could not identify staged updater manifest $stagedName."
}
$stagedAsset = $stagedAssets[0]

$verifyDirectory = Join-Path $workDirectory "verify-staged"
$null = New-Item -ItemType Directory -Path $verifyDirectory
$null = Invoke-Gh @(
  "release", "download", $Tag,
  "--repo", $Repository,
  "--pattern", $stagedName,
  "--dir", $verifyDirectory
)
$verifiedStagedPath = Join-Path $verifyDirectory $stagedName
$sourceHash = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash
$stagedHash = (Get-FileHash -LiteralPath $verifiedStagedPath -Algorithm SHA256).Hash
if ($stagedHash -cne $sourceHash) {
  throw "Staged updater manifest failed SHA-256 verification."
}
$null = & $helperPath `
  -ManifestPath $verifiedStagedPath `
  -NotesPath $resolvedNotesPath `
  -ExpectedVersion $expectedVersion `
  -CheckOnly

$currentAsset = $manifestAssets[0]
$backupName = "latest.backup-$runMarker-$attemptMarker-$nonce.json"
$oldRenamed = $false
$newRenamed = $false
try {
  Rename-ReleaseAsset -AssetId $currentAsset.id -Name $backupName
  $oldRenamed = $true

  Rename-ReleaseAsset -AssetId $stagedAsset.id -Name "latest.json"
  $newRenamed = $true

  $liveDirectory = Join-Path $workDirectory "verify-live"
  $null = New-Item -ItemType Directory -Path $liveDirectory
  $null = Invoke-Gh @(
    "release", "download", $Tag,
    "--repo", $Repository,
    "--pattern", "latest.json",
    "--dir", $liveDirectory
  )
  $liveManifestPath = Join-Path $liveDirectory "latest.json"
  $liveHash = (Get-FileHash -LiteralPath $liveManifestPath -Algorithm SHA256).Hash
  if ($liveHash -cne $sourceHash) {
    throw "Live updater manifest failed SHA-256 verification."
  }
  $null = & $helperPath `
    -ManifestPath $liveManifestPath `
    -NotesPath $resolvedNotesPath `
    -ExpectedVersion $expectedVersion `
    -CheckOnly
} catch {
  $swapFailure = $_
  if ($newRenamed) {
    try {
      Rename-ReleaseAsset -AssetId $stagedAsset.id -Name $stagedName
      $newRenamed = $false
    } catch {
      Write-Warning "Failed to move the staged updater manifest out of the live name."
    }
  }
  if ($oldRenamed -and -not $newRenamed) {
    try {
      Rename-ReleaseAsset -AssetId $currentAsset.id -Name "latest.json"
      $oldRenamed = $false
    } catch {
      Write-Warning "Failed to restore the previous updater manifest name."
    }
  }
  throw $swapFailure
}

try {
  Remove-ReleaseAsset -AssetId $currentAsset.id
} catch {
  Write-Warning "The previous updater manifest remains as $backupName and can be removed manually."
}

Write-Host "Updated $Tag latest.json notes without changing version, URLs, or signatures."
