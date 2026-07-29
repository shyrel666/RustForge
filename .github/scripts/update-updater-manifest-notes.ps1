[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, ParameterSetName = "Manifest")]
  [ValidateNotNullOrEmpty()]
  [string] $ManifestPath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $NotesPath,

  [Parameter(Mandatory = $true, ParameterSetName = "Manifest")]
  [ValidateNotNullOrEmpty()]
  [string] $ExpectedVersion,

  [Parameter(ParameterSetName = "Manifest")]
  [switch] $CheckOnly,

  [Parameter(Mandatory = $true, ParameterSetName = "Preview")]
  [switch] $PreviewOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Remove-InlineMarkdown {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Text
  )

  $plain = [regex]::Replace($Text, '!\[([^\]]*)\]\([^)]+\)', '$1')
  $plain = [regex]::Replace($plain, '\[([^\]]+)\]\([^)]+\)', '$1')
  $plain = $plain.Replace("**", "").Replace("__", "").Replace('`', "")
  $plain = [regex]::Replace($plain, '<[^>]+>', '')
  return $plain.Trim()
}

function ConvertTo-UpdaterNotes {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Markdown
  )

  $lines = @($Markdown -split '\r?\n')
  $coreHeadingIndex = -1
  for ($index = 0; $index -lt $lines.Count; $index++) {
    if ($lines[$index] -match '^##\s+核心') {
      $coreHeadingIndex = $index
      break
    }
  }
  if ($coreHeadingIndex -lt 0) {
    throw "Release notes must contain a level-two core features section."
  }

  $heading = Remove-InlineMarkdown ($lines[$coreHeadingIndex] -replace '^##\s+', '')
  $summaries = [System.Collections.Generic.List[string]]::new()

  for ($index = $coreHeadingIndex + 1; $index -lt $lines.Count; $index++) {
    $line = $lines[$index].Trim()
    if ($line -match '^##\s+') {
      break
    }
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }

    if ($line -match '^[-*+]\s+(.+)$') {
      $bullet = $Matches[1].Trim()
      if ($bullet -match '^\*\*(.+?)\*\*(?:[：:].*)?$') {
        $summary = Remove-InlineMarkdown $Matches[1]
      } else {
        $plainBullet = Remove-InlineMarkdown $bullet
        $summary = ($plainBullet -split '[：:]', 2)[0].Trim()
      }
      $summary = $summary.TrimEnd([char[]] "。；")
      if (-not [string]::IsNullOrWhiteSpace($summary)) {
        if ($summary.Length -gt 80) {
          throw "A core feature title exceeds the 80-character updater summary limit."
        }
        $summaries.Add($summary)
      }
    }
  }

  if ($summaries.Count -eq 0) {
    throw "The core features section must contain at least one bullet."
  }

  $updaterNotes = "$heading：$($summaries -join '；')。"
  if ($updaterNotes -notmatch '[\u3400-\u9fff]') {
    throw "Updater notes must contain Chinese text."
  }
  if ($updaterNotes.Length -gt 4000) {
    throw "Updater notes exceed the 4000-character UI limit."
  }
  return $updaterNotes
}

function Get-ManifestInvariant {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject] $Manifest
  )

  $copy = ($Manifest | ConvertTo-Json -Depth 100) | ConvertFrom-Json -Depth 100
  $null = $copy.PSObject.Properties.Remove("notes")
  return $copy | ConvertTo-Json -Depth 100 -Compress
}

$resolvedNotesPath = (Resolve-Path -LiteralPath $NotesPath).Path
$releaseNotes = (Get-Content -LiteralPath $resolvedNotesPath -Raw -Encoding utf8).Trim()
if ([string]::IsNullOrWhiteSpace($releaseNotes)) {
  throw "Release notes must not be empty: $resolvedNotesPath"
}
if ($releaseNotes -notmatch '[\u3400-\u9fff]') {
  throw "Release notes must contain Chinese text: $resolvedNotesPath"
}

$expectedUpdaterNotes = ConvertTo-UpdaterNotes $releaseNotes
if ($PreviewOnly) {
  [pscustomobject] @{
    Changed = $false
    Notes = $expectedUpdaterNotes
  }
  return
}

$resolvedManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifestJson = Get-Content -LiteralPath $resolvedManifestPath -Raw -Encoding utf8
try {
  $manifest = $manifestJson | ConvertFrom-Json -Depth 100
} catch {
  throw "Updater manifest is not valid JSON: $resolvedManifestPath"
}

$manifestVersion = [string] $manifest.version
if ($manifestVersion.TrimStart([char[]] "vV") -ne $ExpectedVersion.TrimStart([char[]] "vV")) {
  throw "Updater manifest version mismatch: expected=$ExpectedVersion actual=$manifestVersion"
}

$platformsProperty = $manifest.PSObject.Properties["platforms"]
if ($null -eq $platformsProperty) {
  throw "Updater manifest has no platforms object."
}
$platforms = @($manifest.platforms.PSObject.Properties)
if ($platforms.Count -eq 0) {
  throw "Updater manifest has no platform entries."
}
foreach ($platform in $platforms) {
  $url = [string] $platform.Value.url
  $signature = [string] $platform.Value.signature
  try {
    $parsedUrl = [uri] $url
  } catch {
    throw "Updater platform $($platform.Name) has an invalid URL."
  }
  if (-not $parsedUrl.IsAbsoluteUri -or $parsedUrl.Scheme -ne "https") {
    throw "Updater platform $($platform.Name) must use an absolute HTTPS URL."
  }
  if ([string]::IsNullOrWhiteSpace($signature)) {
    throw "Updater platform $($platform.Name) has no signature."
  }
}

$notesProperty = $manifest.PSObject.Properties["notes"]
$currentNotes = if ($null -eq $notesProperty) { "" } else { [string] $notesProperty.Value }
if ($CheckOnly) {
  if ($currentNotes -cne $expectedUpdaterNotes) {
    throw "Updater manifest notes do not match the Chinese core release notes."
  }
  [pscustomobject] @{
    Changed = $false
    Notes = $expectedUpdaterNotes
  }
  return
}

if ($currentNotes -ceq $expectedUpdaterNotes) {
  [pscustomobject] @{
    Changed = $false
    Notes = $expectedUpdaterNotes
  }
  return
}

$invariantBefore = Get-ManifestInvariant $manifest
if ($null -eq $notesProperty) {
  $manifest | Add-Member -MemberType NoteProperty -Name "notes" -Value $expectedUpdaterNotes
} else {
  $manifest.notes = $expectedUpdaterNotes
}

$updatedJson = $manifest | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText(
  $resolvedManifestPath,
  "$updatedJson$([Environment]::NewLine)",
  [System.Text.UTF8Encoding]::new($false)
)

$roundTrip = Get-Content -LiteralPath $resolvedManifestPath -Raw -Encoding utf8 |
  ConvertFrom-Json -Depth 100
$invariantAfter = Get-ManifestInvariant $roundTrip
if ($invariantAfter -cne $invariantBefore) {
  throw "Updater manifest fields other than notes changed unexpectedly."
}
if ([string] $roundTrip.notes -cne $expectedUpdaterNotes) {
  throw "Updater manifest notes failed round-trip validation."
}

[pscustomobject] @{
  Changed = $true
  Notes = $expectedUpdaterNotes
}
