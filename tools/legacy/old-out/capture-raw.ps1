[Console]::OutputEncoding = [Text.Encoding]::UTF8
$log = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-capture.txt'
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-events.txt'
$status = 'D:\Desktop\Git\ios-samsung-i9100\out\hold-status.txt'
$reader = 'D:\Desktop\Git\ios-samsung-i9100\out\read-raw-hold.ps1'
Set-Content -Path $log -Value '' -Encoding UTF8
Set-Content -Path $evt -Value '' -Encoding UTF8
Set-Content -Path $status -Value '' -Encoding UTF8

# Single raw opener, never killed (a blocked usbser open cannot be killed).
# Raw CreateFile avoids .NET's SetCommState/DTR control transfers on EP0.
$end = (Get-Date).AddMinutes(45)
$child = $null
$openSeen = $false
$lastDev = $null
$lastSpawn = Get-Date

while ((Get-Date) -lt $end) {
    $dev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match 'VID_0525' }
    $devNow = [bool]$dev
    if ($devNow -ne $lastDev) {
        Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] device {1}" -f (Get-Date), $(if ($devNow) { 'PRESENT' } else { 'GONE' })) -Encoding UTF8
        $lastDev = $devNow
    }

    if ($child) {
        if ($child.HasExited) {
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] child exit {1}" -f (Get-Date), $child.ExitCode) -Encoding UTF8
            $child = $null
            $openSeen = $false
            Start-Sleep -Milliseconds 1000
            continue
        }
        if (-not $openSeen) {
            $st = Get-Content -Path $status -ErrorAction SilentlyContinue
            if ($st -match '^OPEN') {
                $openSeen = $true
                Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] OPEN confirmed, holding across handoff" -f (Get-Date)) -Encoding UTF8
            }
        }
        Start-Sleep -Milliseconds 500
        continue
    }

    if (-not $dev) {
        Start-Sleep -Milliseconds 150
        continue
    }
    if (((Get-Date) - $lastSpawn).TotalSeconds -lt 0.8) {
        Start-Sleep -Milliseconds 150
        continue
    }

    Set-Content -Path $status -Value '' -Encoding UTF8
    $child = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$reader `
        -PassThru -WindowStyle Hidden
    $openSeen = $false
    $lastSpawn = Get-Date
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] spawn raw opener pid={1}" -f (Get-Date), $child.Id) -Encoding UTF8
    Start-Sleep -Milliseconds 150
}
if ($child -and -not $child.HasExited) {
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] loop end; opener left holding" -f (Get-Date)) -Encoding UTF8
} else {
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] loop end" -f (Get-Date)) -Encoding UTF8
}
