[Console]::OutputEncoding = [Text.Encoding]::UTF8
$log = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-capture.txt'
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-events.txt'
Set-Content -Path $log -Value '' -Encoding UTF8
Set-Content -Path $evt -Value '' -Encoding UTF8

$inst = 'USB\VID_0525&PID_A4A7\S2I9100-1'
$end = (Get-Date).AddMinutes(5)
$sb = New-Object System.Text.StringBuilder
$lastFlush = Get-Date
$lastErrLog = Get-Date
$p = $null
$sessions = 0

while ((Get-Date) -lt $end) {
    $present = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match 'VID_0525' }

    if ($present -and -not $p) {
        $pn = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\$inst\Device Parameters" -ErrorAction SilentlyContinue).PortName
        if (-not $pn) { $pn = 'COM11' }
        try {
            $p = New-Object System.IO.Ports.SerialPort $pn,115200,None,8,one
            $p.ReadTimeout = 200
            $p.Open()          # no DTR/RTS: that control transfer hangs usbser
            $sessions++
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] OPEN #{1} {2}" -f (Get-Date), $sessions, $pn) -Encoding UTF8
        } catch {
            if (((Get-Date) - $lastErrLog).TotalSeconds -gt 2) {
                Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] open fail: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
                $lastErrLog = Get-Date
            }
            $p = $null
        }
    }

    if ($p) {
        try {
            $s = $p.ReadExisting()
            if ($s) { [void]$sb.Append($s) }
            if (((Get-Date) - $lastFlush).TotalSeconds -gt 0.5) {
                Set-Content -Path $log -Value $sb.ToString() -Encoding UTF8
                $lastFlush = Get-Date
            }
            if (-not $present) {
                Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] gone" -f (Get-Date)) -Encoding UTF8
                try { $p.Close() } catch {}
                $p = $null
            }
        } catch {
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] read err: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
            try { $p.Close() } catch {}
            $p = $null
        }
    }

    Start-Sleep -Milliseconds 50
}

if ($p) { try { $p.Close() } catch {} }
Set-Content -Path $log -Value $sb.ToString() -Encoding UTF8
Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] END {1} chars, {2} sessions" -f (Get-Date), $sb.Length, $sessions) -Encoding UTF8
