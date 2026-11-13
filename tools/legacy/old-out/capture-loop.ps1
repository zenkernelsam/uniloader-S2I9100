[Console]::OutputEncoding = [Text.Encoding]::UTF8
$log = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-capture.txt'
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\com11-events.txt'
$reader = 'D:\Desktop\Git\ios-samsung-i9100\out\read-one.ps1'
Set-Content -Path $log -Value '' -Encoding UTF8
Set-Content -Path $evt -Value '' -Encoding UTF8

$end = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $end) {
    $dev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match 'VID_0525' }
    if ($dev) {
        Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] spawn reader" -f (Get-Date)) -Encoding UTF8
        $pr = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$reader `
            -PassThru -WindowStyle Hidden
        if (-not $pr.WaitForExit(25000)) {
            try { $pr.Kill() } catch {}
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] reader hung -> killed" -f (Get-Date)) -Encoding UTF8
        } else {
            Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] reader exit {1}" -f (Get-Date), $pr.ExitCode) -Encoding UTF8
        }
    }
    Start-Sleep -Milliseconds 300
}
Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] loop end" -f (Get-Date)) -Encoding UTF8
