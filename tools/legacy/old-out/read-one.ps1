$log = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-capture.txt'
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-events.txt'
$p = $null
$reads = 0; $tos = 0; $bytes = 0
try {
    $p = New-Object System.IO.Ports.SerialPort 'COM11',115200,None,8,one
    $p.Open()
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] reader OPEN" -f (Get-Date)) -Encoding UTF8
    # A blocking Read (not ReadExisting) is what makes usbser submit an
    # IN URB to EP1; ReadExisting with an empty buffer issues nothing.
    $p.ReadTimeout = 300
    $buf = New-Object byte[] 4096
    $t0 = Get-Date
    $last = Get-Date
    $sb = New-Object System.Text.StringBuilder
    while (((Get-Date) - $t0).TotalSeconds -lt 20) {
        try {
            $n = $p.Read($buf, 0, $buf.Length)
            $reads++
            if ($n -gt 0) {
                $bytes += $n
                [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
            }
        } catch [System.TimeoutException] {
            $tos++
        } catch {
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] read err: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
            break
        }
        if (((Get-Date) - $last).TotalSeconds -gt 1) {
            [IO.File]::AppendAllText($log, $sb.ToString())
            [void]$sb.Clear()
            $last = Get-Date
        }
    }
    [IO.File]::AppendAllText($log, $sb.ToString())
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] reader DONE reads={1} timeouts={2} bytes={3}" -f (Get-Date), $reads, $tos, $bytes) -Encoding UTF8
} catch {
    Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] reader fail: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
} finally {
    if ($p) { try { $p.Close() } catch {} }
}
