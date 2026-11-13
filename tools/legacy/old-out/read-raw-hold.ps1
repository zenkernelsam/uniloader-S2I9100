. "$PSScriptRoot\rawcom.cs.ps1"
$log = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-capture.txt'
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-events.txt'
$status = 'D:\Desktop\Git\ios-samsung-i9100\out\hold-status.txt'

$port = 'COM11'
# No WMI/Get-CimInstance here: Win32_SerialPort probes the device and
# hangs forever (holding the port) when the gadget stops answering EP0.
# The loader always enumerates us under the same cached COM number.

Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] RAW opener start port={1} pid={2}" -f (Get-Date), $port, $PID) -Encoding UTF8
$t0 = Get-Date
# Raw CreateFile: no SetCommState, no DTR/RTS, so usbser has no reason
# to put a control transfer on EP0 before returning the handle.
$h = [RawCom]::Open($port)
Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] RAW open -> {1} after {2:N2}s" -f (Get-Date), $h, ((Get-Date) - $t0).TotalSeconds) -Encoding UTF8
if ($h -le 0) {
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] RAW open failed err={1}" -f (Get-Date), $h) -Encoding UTF8
    exit
}
Set-Content -Path $status -Value ("OPEN {0}" -f (Get-Date -Format o)) -Encoding UTF8
[void][RawCom]::SetTimeout($h, 250)

$buf = New-Object byte[] 4096
$t1 = Get-Date
$bytes = 0
$reads = 0
$last = Get-Date
$sb = New-Object System.Text.StringBuilder
while (((Get-Date) - $t1).TotalSeconds -lt 900) {
    $n = [RawCom]::Read($h, $buf)
    if ($n -gt 0) {
        $reads++
        $bytes += $n
        [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
    } elseif ($n -lt 0) {
        Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] RAW read err {1} after {2}B" -f (Get-Date), $n, $bytes) -Encoding UTF8
        break
    }
    if (((Get-Date) - $last).TotalSeconds -gt 0.5) {
        [IO.File]::AppendAllText($log, $sb.ToString())
        [void]$sb.Clear()
        $last = Get-Date
    }
}
[IO.File]::AppendAllText($log, $sb.ToString())
Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] RAW read done reads={1} bytes={2}" -f (Get-Date), $reads, $bytes) -Encoding UTF8
[RawCom]::Close($h)
