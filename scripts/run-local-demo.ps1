# Start the self-hosted signal service, a real FFmpeg test-pattern host, and a
# headless OpenStream client on native Windows. Pairing JSON stays in the
# process environment and diagnostic logs do not contain it.
$ErrorActionPreference = "Stop"

$repoDir = Split-Path -Parent $PSScriptRoot
$engineDir = Join-Path $repoDir "engine\lowlat"
$port = if ($env:OPENSTREAM_DEMO_PORT) { $env:OPENSTREAM_DEMO_PORT } else { "18084" }
$seconds = if ($env:OPENSTREAM_DEMO_SECONDS) { $env:OPENSTREAM_DEMO_SECONDS } else { "8" }
$output = if ($env:OPENSTREAM_DEMO_OUTPUT) {
    $env:OPENSTREAM_DEMO_OUTPUT
} else {
    Join-Path $repoDir "openstream-demo.h264"
}

if (-not (Get-Command ffmpeg.exe -ErrorAction SilentlyContinue)) {
    throw "ffmpeg.exe is required for the local demo"
}
[int]$secondsValue = 0
if (-not [int]::TryParse($seconds, [ref]$secondsValue) -or $secondsValue -lt 1) {
    throw "OPENSTREAM_DEMO_SECONDS must be a positive integer"
}

$tempDir = Join-Path ([IO.Path]::GetTempPath()) "openstream-demo-$PID"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$serverLog = Join-Path $tempDir "signal.log"
$serverError = Join-Path $tempDir "signal-error.log"
$hostLog = Join-Path $tempDir "host.log"
$hostError = Join-Path $tempDir "host-error.log"
$clientLog = Join-Path $tempDir "client.log"
$clientError = Join-Path $tempDir "client-error.log"
$serverProcess = $null
$hostProcess = $null
$clientProcess = $null
$locationPushed = $false

$trackedEnvironment = @(
    "OPENSTREAM_SIGNAL_BIND",
    "OPENSTREAM_ALLOW_NO_AUTH",
    "OPENSTREAM_SIGNAL_ORIGIN",
    "OPENSTREAM_PAIRING_JSON",
    "OPENSTREAM_UDP_BIND",
    "OPENSTREAM_HOST_SECONDS",
    "OPENSTREAM_CLIENT_SECONDS",
    "OPENSTREAM_FFMPEG_ARGS",
    "OPENSTREAM_OUTPUT"
)
$originalEnvironment = @{}
foreach ($name in $trackedEnvironment) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    Push-Location $engineDir
    $locationPushed = $true
    cargo build --locked -p openstream-signal-server -p openstream-ffmpeg-host -p openstream-client

    $env:OPENSTREAM_SIGNAL_BIND = "127.0.0.1:$port"
    # The demo is intentionally loopback-only, so it may opt into the
    # signal service's development mode without weakening production defaults.
    $env:OPENSTREAM_ALLOW_NO_AUTH = "1"
    $serverProcess = Start-Process -FilePath (Join-Path $engineDir "target\debug\openstream-signal-server.exe") `
        -WorkingDirectory $engineDir -RedirectStandardOutput $serverLog `
        -RedirectStandardError $serverError -PassThru
    $ready = $false
    foreach ($attempt in 1..80) {
        try {
            Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$port/healthz" | Out-Null
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not $ready) {
        throw "signal server did not become ready"
    }

    $pairing = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/v1/session" `
        -ContentType "application/json" -Body '{"ttl_seconds":120}'
    $env:OPENSTREAM_SIGNAL_ORIGIN = "http://127.0.0.1:$port"
    $env:OPENSTREAM_PAIRING_JSON = $pairing | ConvertTo-Json -Compress
    $env:OPENSTREAM_HOST_SECONDS = $secondsValue.ToString()
    $env:OPENSTREAM_CLIENT_SECONDS = $secondsValue.ToString()
    $env:OPENSTREAM_UDP_BIND = "127.0.0.1:0"
    $env:OPENSTREAM_FFMPEG_ARGS = if ($env:OPENSTREAM_FFMPEG_ARGS) {
        $env:OPENSTREAM_FFMPEG_ARGS
    } else {
        "-f lavfi -i testsrc2=size=1280x720:rate=30"
    }
    $env:OPENSTREAM_OUTPUT = $output

    $hostProcess = Start-Process -FilePath (Join-Path $engineDir "target\debug\openstream-ffmpeg-host.exe") `
        -WorkingDirectory $engineDir -RedirectStandardOutput $hostLog `
        -RedirectStandardError $hostError -PassThru
    $clientProcess = Start-Process -FilePath (Join-Path $engineDir "target\debug\openstream-client.exe") `
        -WorkingDirectory $engineDir -RedirectStandardOutput $clientLog `
        -RedirectStandardError $clientError -PassThru -Wait
    $hostProcess.WaitForExit()

    if ($clientProcess.ExitCode -ne 0 -or $hostProcess.ExitCode -ne 0 -or -not (Test-Path $output) -or
        (Get-Item $output).Length -eq 0) {
        throw "host/client demo failed; inspect temporary diagnostic logs"
    }
    Write-Output "OpenStream local demo passed; H.264 output: $output"
} catch {
    Write-Error "OpenStream local demo failed; diagnostic logs follow"
    foreach ($log in @($serverLog, $serverError, $hostLog, $hostError, $clientLog, $clientError)) {
        if (Test-Path $log) {
            Write-Error ("--- " + [IO.Path]::GetFileName($log) + " ---")
            Get-Content -LiteralPath $log -TotalCount 160 | ForEach-Object { Write-Error $_ }
        }
    }
    throw
} finally {
    if ($clientProcess -and -not $clientProcess.HasExited) {
        Stop-Process -Id $clientProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($hostProcess -and -not $hostProcess.HasExited) {
        Stop-Process -Id $hostProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($locationPushed) {
        Pop-Location
    }
    foreach ($name in $trackedEnvironment) {
        $value = $originalEnvironment[$name]
        if ($null -eq $value) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            Set-Item "Env:$name" $value
        }
    }
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
