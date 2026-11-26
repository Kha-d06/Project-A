<#
  Checks the Windows installers' Authenticode signatures (docs/code-signing.md).
    $env:SIGNED   = 'true'  signing was configured: every installer must be validly signed,
                            timestamped, and by $env:WIN_PUBLISHER_NAME.
    $env:REQUIRED = 'true'  an unsigned build is an error.
#>
param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = 'Stop'
$files = Get-ChildItem -Path $Dir -Filter *.exe -File
if (-not $files) { Write-Output "::error::No installers in $Dir"; exit 1 }

if ($env:SIGNED -ne 'true') {
  if ($env:REQUIRED -eq 'true') { Write-Output "::error::REQUIRE_SIGNED_RELEASES is on, but no Windows signing is configured."; exit 1 }
  Write-Output "::warning::Windows installers are unsigned: SmartScreen will warn."
  exit 0
}

$failed = $false
foreach ($file in $files) {
  $sig = Get-AuthenticodeSignature -FilePath $file.FullName
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
  if ($sig.Status -ne 'Valid') { Write-Output "::error::$($file.Name): signature $($sig.Status)"; $failed = $true; continue }
  if (-not $sig.TimeStamperCertificate) { Write-Output "::error::$($file.Name): not timestamped (it would stop verifying when the certificate expires)"; $failed = $true }
  if ($env:WIN_PUBLISHER_NAME -and $subject -notlike "*CN=$($env:WIN_PUBLISHER_NAME)*") {
    Write-Output "::error::$($file.Name): signed by '$subject', expected CN=$($env:WIN_PUBLISHER_NAME)"; $failed = $true
  }
  Write-Output "$($file.Name): $($sig.Status), $subject"
}
if ($failed) { exit 1 }
Write-Output "Windows signatures verified."
