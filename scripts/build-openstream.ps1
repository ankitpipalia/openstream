# Build project-owned OpenStream host/client artifacts for one target.
# Native SDKs, linkers, and hardware runtimes remain the caller's responsibility.
$ErrorActionPreference = "Stop"

$repoDir = Split-Path -Parent $PSScriptRoot
$engineDir = Join-Path $repoDir "engine\lowlat"
$target = if ($env:OPENSTREAM_TARGET) { $env:OPENSTREAM_TARGET } else { "" }
$profile = if ($env:OPENSTREAM_PROFILE) { $env:OPENSTREAM_PROFILE } else { "release" }

if ($profile -ne "release" -and $profile -ne "debug") {
    throw "OPENSTREAM_PROFILE must be release or debug"
}

$packages = @(
    "-p", "openstream-signal-server",
    "-p", "openstream-ffmpeg-host",
    "-p", "openstream-client",
    "-p", "openstream-desktop-client"
)
if ($target -match "android|apple-ios") {
    $packages = @("-p", "openstream-mobile-ffi")
} elseif (-not $target -or $target -match "linux") {
    $packages += @("-p", "openstream-linux-host")
}

Push-Location $engineDir
try {
    $cargoArgs = @("build", "--locked")
    if ($profile -eq "release") { $cargoArgs += "--release" }
    if ($target) { $cargoArgs += @("--target", $target) }
    $cargoArgs += $packages
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    $outputDir = if ($target) { Join-Path $engineDir "target\$target" } else { Join-Path $engineDir "target" }
    Write-Output "OpenStream build passed; artifacts are under $outputDir"
} finally {
    Pop-Location
}
