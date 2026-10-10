$ts = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "=== AGC-007 Macro Lure Document Simulation ==="
Write-Output "Start: $ts UTC"

Write-Output "`n--- Step 1: Create lure .docm in Downloads ---"
$docPath = "C:\Users\michael.chen.ASHFORDGROVE\Downloads\Signed-Contract-2026.docm"
if (-not (Test-Path "C:\Users\michael.chen.ASHFORDGROVE\Downloads")) {
    $docPath = "$env:USERPROFILE\Downloads\Signed-Contract-2026.docm"
}

$docContent = "PK-FAKE-DOCM-HEADER-AGC007-SIMULATION`nSub AutoOpen()`n    Open ""C:\Windows\Temp\macro_marker.txt"" For Output As #1`n    Print #1, ""AGC-007 macro executed at "" & Now() & "" UTC by "" & Environ(""USERNAME"")`n    Close #1`nEnd Sub"
$docContent | Out-File -FilePath $docPath -Encoding ascii -Force
Write-Output "Lure document saved to: $docPath"

Write-Output "`n--- Step 2: Simulate macro execution (marker file write) ---"
$markerPath = "C:\Windows\Temp\macro_marker.txt"
$markerContent = "AGC-007 macro executed at $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC by $env:USERNAME"
$markerContent | Out-File -FilePath $markerPath -Encoding ascii -Force
$ts2 = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[$ts2] Marker file written to: $markerPath"
Write-Output "Content: $markerContent"
Write-Output "Sysmon EID 11 should capture this write to system temp directory"

Write-Output "`n--- Step 3: Verify marker file ---"
if (Test-Path $markerPath) {
    $content = Get-Content $markerPath -Raw
    Write-Output "CONFIRMED: $markerPath exists"
    Write-Output "Content: $content"
} else {
    Write-Output "ERROR: marker file not found"
}

Write-Output "`n--- Step 4: Collect Sysmon evidence ---"
$ts4 = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[$ts4] Collecting Sysmon events..."

Write-Output "`nEID 11 (File Create) - looking for macro_marker and .docm:"
try {
    $fc = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=11]]" -MaxEvents 30 -ErrorAction Stop
    foreach ($e in $fc) {
        if ($e.Message -match "macro_marker" -or $e.Message -match "\.docm" -or $e.Message -match "Signed-Contract") {
            $short = $e.Message
            if ($short.Length -gt 400) { $short = $short.Substring(0,400) }
            Write-Output "  [$($e.TimeCreated)] $short"
            Write-Output "  ---"
        }
    }
} catch {
    Write-Output "  [Notice] Live Sysmon log query in terminal requires Administrator elevation."
}

$tsEnd = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "`n=== AGC-007 Complete: $tsEnd UTC ==="
