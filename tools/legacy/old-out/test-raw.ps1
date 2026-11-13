. "$PSScriptRoot\rawcom.cs.ps1"
$h = [RawCom]::Open('COM1')
Write-Output ("COM1 open -> {0}" -f $h)
if ($h -gt 0) {
    Write-Output ("timeout -> {0}" -f [RawCom]::SetTimeout($h, 200))
    $buf = New-Object byte[] 64
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt 2) {
        $n = [RawCom]::Read($h, $buf)
        Write-Output ("read -> {0}" -f $n)
        Start-Sleep -Milliseconds 300
    }
    [RawCom]::Close($h)
}
