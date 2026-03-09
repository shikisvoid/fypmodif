# verify-sdp.ps1
$ErrorActionPreference = "Stop"

$composeFile = "docker-compose.sdp.yml"
$adminEmail  = "admin@hospital.com"
$adminPass   = "Admin@123"
$adminMfaSecret = "PVSU22Z3OBIWIZKXF52GWNDHLJJUMMSJKJJFI7L2IVAS44CJF42Q"

function Wait-Http200 {
    param(
        [string]$Url,
        [int]$TimeoutSec = 180
    )
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        try {
            $r = Invoke-WebRequest -Uri $Url -Method GET -UseBasicParsing -TimeoutSec 5
            if ($r.StatusCode -eq 200) { return $true }
        } catch {}
        Start-Sleep -Seconds 2
    }
    throw "Timeout waiting for $Url"
}

function Get-HttpCode {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [string]$Body = "",
        [hashtable]$Headers = @{}
    )
    $headerArgs = @()
    foreach ($k in $Headers.Keys) { $headerArgs += @("-H", "${k}: $($Headers[$k])") }

    if ($Method -eq "GET") {
        $code = & curl.exe -s -o NUL -w "%{http_code}" @headerArgs $Url
    } else {
        $code = & curl.exe -s -o NUL -w "%{http_code}" -X $Method @headerArgs -d $Body $Url
    }
    return [int]$code
}

Write-Host "`n[1/8] Starting SDP stack..." -ForegroundColor Cyan
docker compose -f $composeFile down | Out-Null
docker compose -f $composeFile up -d

Write-Host "[2/8] Waiting for services..." -ForegroundColor Cyan
Wait-Http200 "http://localhost:8088/health" 240
Wait-Http200 "http://localhost:4000/" 240
Wait-Http200 "http://localhost:3000/api/monitoring/health" 240
Write-Host "Services are up." -ForegroundColor Green

Write-Host "[3/8] SDP check: protected endpoint without token should be denied..." -ForegroundColor Cyan
$codeNoToken = Get-HttpCode -Url "http://localhost:8088/api/patients"
if ($codeNoToken -ne 401 -and $codeNoToken -ne 403) {
    throw "Expected 401/403 for unauthenticated /api/patients, got $codeNoToken"
}
Write-Host "PASS: unauthenticated request denied ($codeNoToken)." -ForegroundColor Green

Write-Host "[4/8] Login + MFA..." -ForegroundColor Cyan
$loginBody = @{ email = $adminEmail; password = $adminPass } | ConvertTo-Json -Compress
$loginResp = Invoke-RestMethod -Uri "http://localhost:8088/api/login" -Method POST -ContentType "application/json" -Body $loginBody
if (-not $loginResp.success) { throw "Login failed: $($loginResp.error)" }

$token = $null
if ($loginResp.mfaRequired -eq $true) {
    $mfaCode = docker exec hospital-iam node -e "const s=require('speakeasy'); console.log(s.totp({secret:'$adminMfaSecret',encoding:'base32'}));"
    $mfaCode = ($mfaCode | Select-Object -Last 1).Trim()

    $mfaBody = @{ email = $adminEmail; code = $mfaCode } | ConvertTo-Json -Compress
    $mfaResp = Invoke-RestMethod -Uri "http://localhost:8088/api/mfa/verify" -Method POST -ContentType "application/json" -Body $mfaBody
    if (-not $mfaResp.success) { throw "MFA failed: $($mfaResp.error)" }
    $token = $mfaResp.token
} else {
    $token = $loginResp.token
}
if (-not $token) { throw "No token returned after auth." }
Write-Host "PASS: authenticated and received token." -ForegroundColor Green

Write-Host "[5/8] SDP check: authenticated SDP access should succeed..." -ForegroundColor Cyan
$authHeaders = @{ Authorization = "Bearer $token" }
$codeWithToken = Get-HttpCode -Url "http://localhost:8088/api/me" -Headers $authHeaders
if ($codeWithToken -ne 200) {
    throw "Expected 200 for authenticated /api/me, got $codeWithToken"
}
Write-Host "PASS: authenticated request allowed ($codeWithToken)." -ForegroundColor Green

Write-Host "[6/8] Verify health/monitoring endpoints..." -ForegroundColor Cyan
$gw = Invoke-RestMethod -Uri "http://localhost:8088/health" -Method GET
$telemetry = Invoke-RestMethod -Uri "http://localhost:9090/telemetry" -Method GET
$isolations = Invoke-RestMethod -Uri "http://localhost:4100/isolations" -Method GET
Write-Host "Gateway enforcement: $($gw.enforcement)" -ForegroundColor Yellow
Write-Host "Telemetry entries: $($telemetry.recentTelemetry.Count)" -ForegroundColor Yellow
Write-Host "Isolation actions: $($isolations.Count)" -ForegroundColor Yellow

Write-Host "[7/8] Container status..." -ForegroundColor Cyan
docker compose -f $composeFile ps

Write-Host "[8/8] Verification complete." -ForegroundColor Green
Write-Host "To stop: docker compose -f $composeFile down" -ForegroundColor Gray



