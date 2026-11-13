$ErrorActionPreference = 'Continue'
$dev = Get-WmiObject -Class Win32_PnPEntity -Filter "DeviceID like 'USB\\VID_0525%'" | Select-Object -First 1
if (-not $dev) { Write-Output 'device not found'; exit 1 }
Write-Output ("found: " + $dev.DeviceID + " status=" + $dev.Status)
try {
    $r = $dev.SetPowerState(6, (Get-Date))   # 6 = power off
    Write-Output ("SetPowerState(6) -> " + $r.ReturnValue)
} catch {
    Write-Output ("SetPowerState exc: " + $_.Exception.Message)
}
