# Phase 2 Hospital Management System Startup Script
# This script starts all Phase 2 services including EDR, monitoring, and response controller

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Phase 2 Hospital Management System  " -ForegroundColor Cyan
Write-Host "  EDR & Automated Response Platform   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is installed
Write-Host "[1/6] Checking Docker installation..." -ForegroundColor Yellow
try {
    $dockerVersion = docker --version
    Write-Host "âœ“ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "âœ— Docker not found! Please install Docker Desktop." -ForegroundColor Red
    Write-Host "Download from: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

# Check if Docker is running
Write-Host "[2/6] Checking if Docker is running..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "âœ“ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "âœ— Docker is not running! Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Create required directories
Write-Host "[3/6] Creating volume directories..." -ForegroundColor Yellow
$volumeDirs = @(
    "D:\PHASE1\docker-volumes\db-data",
    "D:\PHASE1\docker-volumes\encryption-data",
    "D:\PHASE1\docker-volumes\monitor-logs",
    "D:\PHASE1\docker-volumes\prometheus-data",
    "D:\PHASE1\docker-volumes\grafana-data"
)

foreach ($dir in $volumeDirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created: $dir" -ForegroundColor Gray
    } else {
        Write-Host "  Exists: $dir" -ForegroundColor Gray
    }
}
Write-Host "âœ“ All volume directories ready" -ForegroundColor Green

# Stop any existing containers
Write-Host "[4/6] Stopping existing containers..." -ForegroundColor Yellow
docker compose -f docker-compose.sdp.yml down 2>&1 | Out-Null
Write-Host "âœ“ Cleaned up existing containers" -ForegroundColor Green

# Start all services
Write-Host "[5/6] Starting all services..." -ForegroundColor Yellow
Write-Host "  This may take 1-2 minutes for npm install..." -ForegroundColor Gray
docker compose -f docker-compose.sdp.yml up -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "âœ“ All services started" -ForegroundColor Green
} else {
    Write-Host "âœ— Failed to start services" -ForegroundColor Red
    exit 1
}

# Wait for services to initialize
Write-Host "[6/6] Waiting for services to initialize..." -ForegroundColor Yellow
Write-Host "  Waiting 60 seconds for npm install and startup..." -ForegroundColor Gray
Start-Sleep -Seconds 60

# Check service status
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
docker compose -f docker-compose.sdp.yml ps

# Display access information
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Access Information" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Healthcare Application:" -ForegroundColor Yellow
Write-Host "  Frontend:        http://localhost:5173" -ForegroundColor White
Write-Host "  Backend API:     http://localhost:3000" -ForegroundColor White
Write-Host "  IAM Server:      http://localhost:4000" -ForegroundColor White
Write-Host "  Adminer:         http://localhost:8081" -ForegroundColor White
Write-Host ""
Write-Host "Phase 2 - Monitoring & Response:" -ForegroundColor Yellow
Write-Host "  Prometheus:      http://localhost:9091" -ForegroundColor White
Write-Host "  Grafana:         http://localhost:3002 (admin/admin)" -ForegroundColor White
Write-Host "  Response Ctrl:   http://localhost:4100" -ForegroundColor White
Write-Host "  Telemetry API:   http://localhost:9090/telemetry" -ForegroundColor White
Write-Host ""
Write-Host "Logs Location:" -ForegroundColor Yellow
Write-Host "  D:\PHASE1\docker-volumes\monitor-logs\" -ForegroundColor White
Write-Host ""

# Display quick test commands
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Quick Test Commands" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test SDP Enforcement:" -ForegroundColor Yellow
Write-Host '  curl http://localhost:8088/api/patients  # Should return 401 without token' -ForegroundColor Gray
Write-Host '  curl http://localhost:8088/health         # Should return SDP gateway health JSON' -ForegroundColor Gray
Write-Host ""
Write-Host "Send Test Alert:" -ForegroundColor Yellow
Write-Host '  curl -X POST http://localhost:4100/alert -H "Content-Type: application/json" -d "{\"severity\":\"CRITICAL\",\"event\":\"TEST\",\"hostId\":\"test-1\"}"' -ForegroundColor Gray
Write-Host ""
Write-Host "View Isolations:" -ForegroundColor Yellow
Write-Host '  curl http://localhost:4100/isolations' -ForegroundColor Gray
Write-Host ""
Write-Host "View Telemetry:" -ForegroundColor Yellow
Write-Host '  curl http://localhost:9090/telemetry' -ForegroundColor Gray
Write-Host ""
Write-Host "View Logs:" -ForegroundColor Yellow
Write-Host '  docker logs hospital-monitor --tail=50' -ForegroundColor Gray
Write-Host '  docker logs hospital-response-controller --tail=50' -ForegroundColor Gray
Write-Host ""

# Display monitoring information
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Automated Monitoring Active" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "The following automated processes are running:" -ForegroundColor Yellow
Write-Host "  âœ“ SDP policy/access tests (every 10 seconds)" -ForegroundColor Green
Write-Host "  âœ“ Telemetry collection and correlation" -ForegroundColor Green
Write-Host "  âœ“ Rule-based threat detection" -ForegroundColor Green
Write-Host "  âœ“ Automated response to CRITICAL alerts" -ForegroundColor Green
Write-Host "  âœ“ Prometheus metrics collection (every 15 seconds)" -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  System Ready!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "For detailed testing instructions, see:" -ForegroundColor Yellow
Write-Host "  PHASE2-TESTING-GUIDE.md" -ForegroundColor White
Write-Host "  PHASE2-QUICK-REFERENCE.md" -ForegroundColor White
Write-Host ""
Write-Host "To stop all services:" -ForegroundColor Yellow
Write-Host "  docker compose -f docker-compose.sdp.yml down" -ForegroundColor White
Write-Host ""



