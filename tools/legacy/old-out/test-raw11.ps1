. "$PSScriptRoot\rawcom.cs.ps1"
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\raw-events.txt'
function Log($m) { Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) -Encoding UTF8 }
$t0 = Get-Date
Log 'raw COM11 open attempt'
$h = [RawCom]::Open('COM11')
Log ("open -> {0} after {1:N2}s" -f $h, ((Get-Date) - $t0).TotalSeconds)
if ($h -gt 0) {
    Log ("timeout -> {0}" -f [RawCom]::SetTimeout($h, 250))
    $buf = New-Object byte[] 4096
    $log = 'D:\Desktop\Git\ios-samsung-i9100\out\raw-capture.txt'
    $t1 = Get-Date
    $bytes = 0
    while (((Get-Date) - $t1).TotalSeconds -lt 8) {
        $n = [RawCom]::Read($h, $buf)
        if ($n -gt 0) {
            $bytes += $n
            [IO.File]::AppendAllText($log, [Text.Encoding]::ASCII.GetString($buf, 0, $n))
        } elseif ($n -lt 0) {
            Log ("read err {0}" -f $n)
            break
        }
    }
    Log ("raw read done bytes={0}" -f $bytes)
    [RawCom]::Close($h)
}
