$log = "$env:TEMP\i9100_usb_enum.txt"
Get-PnpDevice | Where-Object {
    $_.FriendlyName -match 'SAMSUNG|Odin|Download|Gadget|Android|i9100|SEC |MODEM|CDC|Serial|Gadget' -or
    $_.InstanceId -match 'VID_04E8|VID_18D1|VID_0525'
} | Select-Object Status, Class, FriendlyName, InstanceId |
    Format-Table -AutoSize | Out-String -Width 250 | Out-File $log -Encoding utf8
# also dump problem devices
Get-PnpDevice | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Unknown' -or $_.Status -eq 'Degraded' } |
    Select-Object Status, Class, FriendlyName, InstanceId |
    Format-Table -AutoSize | Out-String -Width 250 | Out-File -Append $log -Encoding utf8
Write-Output $log
