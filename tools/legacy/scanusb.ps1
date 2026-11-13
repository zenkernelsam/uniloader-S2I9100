Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_04E8|VID_0FCE|VID_05C6|VID_18D1' } | Select-Object Class, Name, Status, InstanceId | Format-List
Write-Output "=== name-match ==="
Get-PnpDevice -PresentOnly | Where-Object { $_.Name -match 'SAMSUNG|GT-I91|Galaxy|Android|ADB|Composite' } | Select-Object Class, Name, Status | Format-Table -AutoSize
Write-Output "=== problem devices ==="
Get-PnpDevice -PresentOnly | Where-Object { $_.Status -ne 'OK' } | Select-Object Class, Name, Status, InstanceId | Format-List
