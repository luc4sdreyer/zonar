# Download, verify, and install the latest zonar release on Windows.
#
# zonar signs its releases; this installer verifies that signature (when minisign
# is available) before installing. The trust root is minisign.pub committed to the
# repository; its fingerprint is in the README. Read this script before running it:
#
#   irm https://raw.githubusercontent.com/luc4sdreyer/zonar/main/tasks/install.ps1 | iex
#
# Env:
#   ZONAR_BIN   install directory (default: $env:LOCALAPPDATA\zonar\bin)
$ErrorActionPreference = "Stop"

$repo = "luc4sdreyer/zonar"
$base = "https://github.com/$repo/releases/latest/download"
$pubkeyUrl = "https://raw.githubusercontent.com/$repo/main/minisign.pub"

$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
  "AMD64" { $target = "x86_64-windows" }
  "ARM64" { $target = "aarch64-windows" }
  default { Write-Error "zonar: unsupported architecture: $arch"; exit 1 }
}

$archive = "zonar-$target.zip"
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.Guid]::NewGuid()))
try {
  Write-Host "zonar: downloading $archive"
  Invoke-WebRequest -Uri "$base/$archive" -OutFile "$tmp\$archive"
  Invoke-WebRequest -Uri "$base/$archive.minisig" -OutFile "$tmp\$archive.minisig"
  Invoke-WebRequest -Uri $pubkeyUrl -OutFile "$tmp\minisign.pub"

  if (Get-Command minisign -ErrorAction SilentlyContinue) {
    Write-Host "zonar: verifying signature"
    minisign -Vm "$tmp\$archive" -p "$tmp\minisign.pub"
  } else {
    Write-Warning "zonar: minisign not installed; cannot verify the signature. Verify manually before trusting this binary."
  }

  Expand-Archive -Path "$tmp\$archive" -DestinationPath $tmp -Force
  $dest = if ($env:ZONAR_BIN) { $env:ZONAR_BIN } else { "$env:LOCALAPPDATA\zonar\bin" }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item -Force "$tmp\zonar.exe" "$dest\zonar.exe"
  Write-Host "zonar: installed to $dest\zonar.exe"
} finally {
  Remove-Item -Recurse -Force $tmp
}
