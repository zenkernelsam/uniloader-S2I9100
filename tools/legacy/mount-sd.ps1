$ErrorActionPreference='Continue'
$out = & wsl --mount \.\PHYSICALDRIVE2 --bare 2>&1 | Out-String
"mount-exit=$LASTEXITCODE`n$out" | Out-File -Encoding utf8 D:\Desktop\Git\ios-samsung-i9100\out\mount-sd.log
