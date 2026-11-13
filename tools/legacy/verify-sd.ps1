$log='D:\Desktop\Git\ios-samsung-i9100\out\verify-sd.out'
try{
  $fs=[IO.File]::OpenRead('D:\Desktop\Git\ios-samsung-i9100\out\sd-fast.img')
  $len=$fs.Length
  $d=[IO.File]::Open('\\.\PHYSICALDRIVE2','Open','Read','ReadWrite')
  $sha=[Security.Cryptography.SHA256]::Create()
  $buf=New-Object byte[] (4MB)
  $off=0L
  while($off -lt $len){
    $want=[int][Math]::Min([long]$buf.Length,[long]($len-$off))
    $nr=$d.Read($buf,0,$want); if($nr -le 0){break}
    $sha.TransformBlock($buf,0,$nr,$null,0)|Out-Null
    $off+=$nr
  }
  $sha.TransformFinalBlock(@(),0,0)|Out-Null
  $diskHash=($sha.Hash|ForEach-Object{$_.ToString('x2')}) -join ''
  "disk first $off bytes sha256=$diskHash"|Out-File -Append $log
  "img               sha256=58f4946135c72dbf7cc1eee825488eecc6193670e7998fc9f756ea7a32752933"|Out-File -Append $log
  if($off -lt $len){"WARN only read $off of $len"|Out-File -Append $log}
  $d.Close(); $fs.Close()
}catch{"FAIL: $_"|Out-File -Append $log}
