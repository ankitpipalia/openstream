# Create one OpenStream host/client pairing from the self-hosted service.
# The JSON response contains bearer capabilities; protect the terminal/log
# that captures it.
$ErrorActionPreference = "Stop"

$origin = if ($env:OPENSTREAM_SIGNAL_ORIGIN) {
    $env:OPENSTREAM_SIGNAL_ORIGIN
} else {
    "http://127.0.0.1:8080"
}
$ttlText = if ($env:OPENSTREAM_SESSION_TTL) {
    $env:OPENSTREAM_SESSION_TTL
} else {
    "3600"
}
[uint64]$ttl = 0
if (-not [uint64]::TryParse($ttlText, [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture, [ref]$ttl) -or $ttl -lt 1) {
    throw "OPENSTREAM_SESSION_TTL must be a positive integer"
}

$headers = @{}
if ($env:OPENSTREAM_ADMIN_TOKEN) {
    $headers["Authorization"] = "Bearer $($env:OPENSTREAM_ADMIN_TOKEN)"
}
$body = @{ ttl_seconds = $ttl } | ConvertTo-Json -Compress
$pairing = Invoke-RestMethod -Method Post -Uri "$($origin.TrimEnd('/'))/v1/session" `
    -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 20

# Embed role-specific session-scoped TURN credentials when the service mints
# them. A shared host credential is not valid for the client role at coturn.
# A service without TURN configured answers 503; that is not an error here.
if ($env:OPENSTREAM_FETCH_TURN -ne "0") {
    $hostTurn = $null
    $clientTurn = $null
    try {
        $hostTurn = Invoke-RestMethod -Method Get `
            -TimeoutSec 20 -Uri "$($origin.TrimEnd('/'))/v1/session/$($pairing.session_id)/turn" `
            -Headers @{ Authorization = "Bearer $($pairing.host_token)" }
    } catch {
        if (-not $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 503) { throw }
    }
    try {
        $clientTurn = Invoke-RestMethod -Method Get `
            -TimeoutSec 20 -Uri "$($origin.TrimEnd('/'))/v1/session/$($pairing.session_id)/turn" `
            -Headers @{ Authorization = "Bearer $($pairing.client_token)" }
    } catch {
        if (-not $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 503) { throw }
    }
    if ($hostTurn) {
        $pairing | Add-Member -NotePropertyName "turn_host" -NotePropertyValue $hostTurn -Force
        $pairing | Add-Member -NotePropertyName "turn" -NotePropertyValue $hostTurn -Force
    }
    if ($clientTurn) {
        $pairing | Add-Member -NotePropertyName "turn_client" -NotePropertyValue $clientTurn -Force
    }
}
$pairing | ConvertTo-Json -Compress
