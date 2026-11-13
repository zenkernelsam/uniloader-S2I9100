$ErrorActionPreference='Continue'
$log='D:\Desktop\Git\ios-samsung-i9100\out\write-sd.log'
"start $(Get-Date)" | Out-File $log
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class RawDisk {
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFile(string name,uint acc,uint share,IntPtr sec,uint disp,uint attr,IntPtr tmpl);
  [DllImport("kernel32.dll",SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h,uint code,IntPtr ib,uint ilen,IntPtr ob,uint olen,out uint ret,IntPtr ovl);
  [DllImport("kernel32.dll",SetLastError=true)]
  public static extern bool WriteFile(IntPtr h,byte[] buf,uint len,out uint wr,IntPtr ovl);
  [DllImport("kernel32.dll")] public static extern bool FlushFileBuffers(IntPtr h);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool SetFilePointerEx(IntPtr h,long off,out long np,uint meth);
}
'@
try {
  $vol=[RawDisk]::CreateFile('\\.\E:',[uint32]3221225472,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
  $err=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if($vol -ne [IntPtr]::Zero -and $vol -ne [IntPtr]::new(-1)){
    $r=0
    [RawDisk]::DeviceIoControl($vol,[uint32]589848,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$r,[IntPtr]::Zero)|Out-Null
    [RawDisk]::DeviceIoControl($vol,[uint32]589856,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$r,[IntPtr]::Zero)|Out-Null
    [RawDisk]::CloseHandle($vol)|Out-Null
    "volume lock+dismount sent"|Out-File -Append $log
  } else { "volume open failed err=$err"|Out-File -Append $log }
  Start-Sleep 1
  $fs=[IO.File]::OpenRead('D:\Desktop\Git\ios-samsung-i9100\out\sd-fast.img')
  "src size=$($fs.Length)"|Out-File -Append $log
  $out=[RawDisk]::CreateFile('\\.\PHYSICALDRIVE2',[uint32]1073741824,0,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
  $err=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if($out -eq [IntPtr]::Zero -or $out -eq [IntPtr]::new(-1)){
    $out=[RawDisk]::CreateFile('\\.\PHYSICALDRIVE2',[uint32]3221225472,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
    $err=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
  }
  "disk handle=$out err=$err"|Out-File -Append $log
  $buf=New-Object byte[] (4MB)
  $total=0L; $w=[uint32]0
  while(($n=$fs.Read($buf,0,$buf.Length)) -gt 0){
    $ok=$false
    for($t=0;$t -lt 8 -and !$ok;$t++){
      if([RawDisk]::WriteFile($out,$buf,[uint32]$n,[ref]$w,[IntPtr]::Zero)){$ok=$true;break}
      $e=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
      "retry@$total err=$e"|Out-File -Append $log
      Start-Sleep -Milliseconds 400
      $np=[long]0
      [RawDisk]::SetFilePointerEx($out,$total,[ref]$np,0)|Out-Null
    }
    if(!$ok){"write fail at $total"|Out-File -Append $log;break}
    $total+=$n
  }
  [RawDisk]::FlushFileBuffers($out)|Out-Null
  [RawDisk]::CloseHandle($out)|Out-Null; $fs.Close()
  "DONE wrote=$total $(Get-Date)"|Out-File -Append $log
} catch { "FAIL: $_"|Out-File -Append $log }
