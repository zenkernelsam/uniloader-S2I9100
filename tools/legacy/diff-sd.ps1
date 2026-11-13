$log='D:\Desktop\Git\ios-samsung-i9100\out\diff-sd.out'
"run $(Get-Date)"|Out-File $log
try{
  $fs=[IO.File]::OpenRead('D:\Desktop\Git\ios-samsung-i9100\out\sd-fast.img')
  $d=[IO.File]::Open('\\.\PHYSICALDRIVE2','Open','Read','ReadWrite')
  $len=$fs.Length
  $bs=4096
  $a=New-Object byte[] $bs; $b=New-Object byte[] $bs
  $off=0L; $badBlocks=0; $reported=0
  while($off -lt $len){
    $nr=$d.Read($a,0,$bs); if($nr -le 0){break}
    $fs.Read($b,0,$nr)|Out-Null
    $neq=$false
    for($i=0;$i -lt $nr;$i++){ if($a[$i] -ne $b[$i]){$neq=$true;break} }
    if($neq){
      $badBlocks++
      if($reported -lt 30){
        ('DIFF @0x{0:x} (sector {1}, in-part2={2})' -f ($off+$i),[long](($off+$i)/512),[bool](($off+$i) -ge 1MB))|Out-File -Append $log
        $reported++
      }
    }
    $off+=$nr
  }
  "checked=$off bad4kBlocks=$badBlocks"|Out-File -Append $log
  $d.Close();$fs.Close()
}catch{"FAIL: $_"|Out-File -Append $log}
