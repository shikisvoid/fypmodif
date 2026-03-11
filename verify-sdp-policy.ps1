# verify-sdp-policy.ps1
$ErrorActionPreference = "Stop"

$controllerUrl = "http://127.0.0.1:7000"
$composeFile = "docker-compose.sdp.yml"

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

function Assert-Authorize {
    param(
        [string]$Name,
        [string]$Pathname,
        [string]$Method = "GET",
        [hashtable]$Identity = $null,
        [bool]$ExpectedAllow,
        [string]$ExpectedReasonLike = ""
    )

    $body = @{
        pathname = $Pathname
        method = $Method
        identity = $Identity
        enforcement = $true
    } | ConvertTo-Json -Depth 8 -Compress

    $resp = Invoke-RestMethod -Uri "$controllerUrl/authorize" -Method POST -ContentType "application/json" -Body $body

    if ([bool]$resp.allow -ne $ExpectedAllow) {
        throw "FAIL [$Name] expected allow=$ExpectedAllow but got allow=$($resp.allow), reason=$($resp.reason)"
    }

    if ($ExpectedReasonLike -and ($resp.reason -notlike $ExpectedReasonLike)) {
        throw "FAIL [$Name] expected reason like '$ExpectedReasonLike' but got '$($resp.reason)'"
    }

    Write-Host "PASS [$Name] allow=$($resp.allow) reason=$($resp.reason) policyVersion=$($resp.policyVersion)" -ForegroundColor Green
}

Write-Host "`n[1/4] Starting sdp-controller..." -ForegroundColor Cyan
docker compose -f $composeFile up -d sdp-controller | Out-Null

Write-Host "[2/4] Waiting for controller health..." -ForegroundColor Cyan
Wait-Http200 "$controllerUrl/health" 180 | Out-Null
$health = Invoke-RestMethod -Uri "$controllerUrl/health" -Method GET
Write-Host "Policy source: $($health.policy.source)" -ForegroundColor Yellow
Write-Host "Policy version: $($health.policy.version)" -ForegroundColor Yellow

Write-Host "[3/4] Running policy assertions..." -ForegroundColor Cyan
Assert-Authorize -Name "PublicPath-NoIdentity" -Pathname "/api/login" -ExpectedAllow $true -ExpectedReasonLike "public_*"
Assert-Authorize -Name "Protected-NoIdentity" -Pathname "/api/lab/results" -ExpectedAllow $false -ExpectedReasonLike "missing_identity"
Assert-Authorize -Name "Doctor-Lab-Allow" -Pathname "/api/lab/results" -Identity @{ email = "doctor@hospital.com"; role = "doctor" } -ExpectedAllow $true -ExpectedReasonLike "policy_allow_*"
Assert-Authorize -Name "Receptionist-Lab-Deny" -Pathname "/api/lab/results" -Identity @{ email = "receptionist@hospital.com"; role = "receptionist" } -ExpectedAllow $false -ExpectedReasonLike "role_denied"
Assert-Authorize -Name "Accountant-Billing-Allow" -Pathname "/api/billing/invoices" -Identity @{ email = "accountant@hospital.com"; role = "accountant" } -ExpectedAllow $true -ExpectedReasonLike "policy_allow_*"
Assert-Authorize -Name "Patient-Billing-Deny" -Pathname "/api/billing/invoices" -Identity @{ email = "patient@hospital.com"; role = "patient" } -ExpectedAllow $false -ExpectedReasonLike "role_denied"
Assert-Authorize -Name "Admin-Bypass-Allow" -Pathname "/api/admin/users" -Identity @{ email = "admin@hospital.com"; role = "admin" } -ExpectedAllow $true -ExpectedReasonLike "admin_bypass"

Write-Host "[4/4] Policy verification complete." -ForegroundColor Green
Write-Host "Tip: edit sdp-controller/policy.json and re-run this script to validate policy changes." -ForegroundColor Gray
