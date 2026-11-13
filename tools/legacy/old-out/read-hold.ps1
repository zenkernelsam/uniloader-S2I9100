$log = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-capture.txt'
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-events.txt'
$status = 'D:\Desktop\Git\ios-samsung-i9100\out\hold-status.txt'

$port = 'COM11'
try {
    $w = Get-CimInstance Win32_SerialPort -ErrorAction SilentlyContinue |
        Where-Object { $_.PNPDeviceID -like '*VID_0525&PID_A4A7*' } |
        Select-Object -First 1
    if ($w -and $w.DeviceID) { $port = $w.DeviceID }
} catch {}

$p = $null
Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] opener start port={1} pid={2}" -f (Get-Date), $port, $PID) -Encoding UTF8
try {
    $p = New-Object System.IO.Ports.SerialPort $port,115200,None,8,one
    $p.Open()
    Set-Content -Path $status -Value ("OPEN {0}" -f (Get-Date -Format o)) -Encoding UTF8
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] open OK port={1}" -f (Get-Date), $port) -Encoding UTF8
    $p.ReadTimeout = 250
    $buf = New-Object byte[] 4096
    $t0 = Get-Date
    $last = Get-Date
    $bytes = 0
    $sb = New-Object System.Text.StringBuilder
    while (((Get-Date) - $t0).TotalSeconds -lt 900) {
        try {
            $n = $p.Read($buf, 0, $buf.Length)
            if ($n -gt 0) {
                $bytes += $n
                [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
            }
        } catch [System.TimeoutException] {
        } catch {
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] read err after {1}B: {2}" -f (Get-Date), $bytes, $_.Exception.Message) -Encoding UTF8
            break
        }
        if (((Get-Date) - $last).TotalSeconds -gt 0.5) {
            [IO.File]::AppendAllText($log, $sb.ToString())
            [void]$sb.Clear()
            $last = Get-Date
        }
    }
    [IO.File]::AppendAllText($log, $sb.ToString())
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] read done bytes={1}" -f (Get-Date), $bytes) -Encoding UTF8
} catch {
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] open fail: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
} finally {
    if ($p) { try { $p.Close() } catch {} }
}
