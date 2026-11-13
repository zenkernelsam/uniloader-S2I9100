Get-PnpDevice -PresentOnly | Where-Object {
    $_.FriendlyName -match 'SAMSUNG|Galaxy|Android|ADB|GT-I9100|9100|CDC|Gadget' -or
    $_.DeviceID -match 'VID_04E8|VID_18D1'
} | Select-Object Status, Class, FriendlyName, DeviceID | Format-Table -AutoSize | Out-String -Width 200
