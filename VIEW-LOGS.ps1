# View Comprehensive Network Monitoring Logs
# Displays detailed network monitoring, traffic analysis, and security logs

param(
    [ValidateSet('comprehensive', 'statistics', 'all')]
    [string]$LogType = 'comprehensive',

    [int]$Lines = 100,

    [switch]$Follow,

    [switch]$Full
)

$LogDir = "D:\PHASE1\docker-volumes\monitor-logs"

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "           COMPREHENSIVE NETWORK MONITORING LOGS VIEWER                       " -ForegroundColor Green
Write-Host "===============================================================================`n" -ForegroundColor Cyan

# Check if log directory exists
if (-not (Test-Path $LogDir)) {
    Write-Host "[ERROR] Log directory not found: $LogDir" -ForegroundColor Red
    Write-Host "Make sure the monitoring service is running." -ForegroundColor Yellow
    exit 1
}

function Show-Log {
    param(
        [string]$FilePath,
        [string]$Title
    )

    if (-not (Test-Path $FilePath)) {
        Write-Host "[WARNING] Log file not found: $FilePath" -ForegroundColor Yellow
        return
    }

    Write-Host "`n$Title" -ForegroundColor Yellow
    Write-Host ("-" * 79) -ForegroundColor Gray

    if ($Follow) {
        Write-Host "[Following log in real-time - Press Ctrl+C to stop]`n" -ForegroundColor Cyan
        Get-Content $FilePath -Tail $Lines -Wait | ForEach-Object {
            Format-LogLine $_
        }
    } elseif ($Full) {
        Get-Content $FilePath | ForEach-Object {
            Format-LogLine $_
        }
    } else {
        Get-Content $FilePath -Tail $Lines | ForEach-Object {
            Format-LogLine $_
        }
    }
}

function Format-LogLine {
    param([string]$Line)

    if ($Line -match '^\[.*?\] \[INFO\]') {
        Write-Host $Line -ForegroundColor White
    }
    elseif ($Line -match '^\[.*?\] \[WARNING\]') {
        Write-Host $Line -ForegroundColor Yellow
    }
    elseif ($Line -match '^\[.*?\] \[ERROR\]') {
        Write-Host $Line -ForegroundColor Red
    }
    elseif ($Line -match '^\[.*?\] \[CRITICAL\]') {
        Write-Host $Line -ForegroundColor Magenta
    }
    elseif ($Line -match '^=+') {
        Write-Host $Line -ForegroundColor Cyan
    }
    elseif ($Line -match 'PASS|SUCCEED|ALLOWED|HEALTHY|EFFECTIVE') {
        Write-Host $Line -ForegroundColor Green
    }
    elseif ($Line -match 'FAIL|BLOCKED|VIOLATION|COMPROMISED') {
        Write-Host $Line -ForegroundColor Red
    }
    else {
        Write-Host $Line -ForegroundColor Gray
    }
}

# Display logs based on type
switch ($LogType) {
    'comprehensive' {
        Show-Log -FilePath "$LogDir\comprehensive-network-monitor.log" -Title "[COMPREHENSIVE NETWORK MONITORING LOG]"
    }
    'statistics' {
        Show-Log -FilePath "$LogDir\network-statistics.log" -Title "[NETWORK STATISTICS REPORT]"
    }
    'all' {
        Show-Log -FilePath "$LogDir\comprehensive-network-monitor.log" -Title "[COMPREHENSIVE NETWORK MONITORING LOG]"
        Write-Host "`n"
        Show-Log -FilePath "$LogDir\network-statistics.log" -Title "[NETWORK STATISTICS REPORT]"
    }
}

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "                              LOG VIEWER COMMANDS                              " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  View comprehensive log:    .\VIEW-LOGS.ps1 -LogType comprehensive" -ForegroundColor White
Write-Host "  View statistics report:    .\VIEW-LOGS.ps1 -LogType statistics" -ForegroundColor White
Write-Host "  View all logs:             .\VIEW-LOGS.ps1 -LogType all" -ForegroundColor White
Write-Host "  Follow in real-time:       .\VIEW-LOGS.ps1 -Follow" -ForegroundColor White
Write-Host "  View full log:             .\VIEW-LOGS.ps1 -Full" -ForegroundColor White
Write-Host "  Custom line count:         .\VIEW-LOGS.ps1 -Lines 200" -ForegroundColor White
Write-Host ""
Write-Host "  Check monitor status:      docker logs hospital-monitor" -ForegroundColor White
Write-Host "  List all log files:        Get-ChildItem $LogDir" -ForegroundColor White
Write-Host ""
Write-Host "===============================================================================`n" -ForegroundColor Cyan

