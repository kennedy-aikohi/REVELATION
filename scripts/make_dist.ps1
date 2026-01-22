param(
  [string]$Root = (Resolve-Path ".").Path
)

$dist = Join-Path $Root "dist"
$bin  = Join-Path $Root "target\release"

New-Item -ItemType Directory -Force $dist | Out-Null
New-Item -ItemType Directory -Force (Join-Path $dist "rules") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $dist "rules\compiled") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $dist "rules\sigma") | Out-Null

Copy-Item (Join-Path $bin "revelation-gui.exe") $dist -Force

# Copy OpenSSL DLLs if present (required by your YARA/OpenSSL setup)
$vp = "C:\vcpkg\installed\x64-windows\bin"
$crypto = Join-Path $vp "libcrypto-3-x64.dll"
$ssl    = Join-Path $vp "libssl-3-x64.dll"

if (Test-Path $crypto) { Copy-Item $crypto $dist -Force }
if (Test-Path $ssl)    { Copy-Item $ssl $dist -Force }

# Copy compiled YARA rules if present
$yar = Join-Path $Root "rules\compiled\community_combined.yar"
if (Test-Path $yar) {
  Copy-Item $yar (Join-Path $dist "rules\compiled") -Force
}

Write-Host "Dist created at: $dist"
Write-Host "Ship these files: revelation-gui.exe + libcrypto/libssl (if present) + rules\compiled\community_combined.yar"
