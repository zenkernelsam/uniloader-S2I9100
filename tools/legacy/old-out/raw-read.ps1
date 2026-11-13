param([string]$Port = 'COM11', [int]$Seconds = 15)
$evt = 'D:\Desktop\Git\ios-samsung-i9100\out\raw-events.txt'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class RawCom {
    [StructLayout(LayoutKind.Sequential)]
    public struct COMMTIMEOUTS {
        public uint ReadIntervalTimeout;
        public uint ReadTotalTimeoutMultiplier;
        public uint ReadTotalTimeoutConstant;
        public uint WriteTotalTimeoutMultiplier;
        public uint WriteTotalTimeoutConstant;
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateFile(string name, uint access, uint share,
        IntPtr sec, uint create, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetCommTimeouts(IntPtr h, ref COMMTIMEOUTS t);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadFile(IntPtr h, byte[] buf, uint n, out uint read, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
'@
function Log($m) { Add-Content -Path $evt -Value ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) -Encoding UTF8 }

$t0 = Get-Date
$h = [RawCom]::CreateFile("\\.\$Port", 0x80000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Log ("CreateFile -> {0} err={1} after {2:N2}s" -f $h, $err, ((Get-Date) - $t0).TotalSeconds)
if ($h -eq [IntPtr](-1)) { exit }

$t = New-Object RawCom+COMMTIMEOUTS
$t.ReadIntervalTimeout = 0
$t.ReadTotalTimeoutMultiplier = 0
$t.ReadTotalTimeoutConstant = 250
$ok = [RawCom]::SetCommTimeouts($h, [ref]$t)
Log ("SetCommTimeouts -> {0} err={1}" -f $ok, [Runtime.InteropServices.Marshal]::GetLastWin32Error())

$buf = New-Object byte[] 4096
$log = 'D:\Desktop\Git\ios-samsung-i9100\out\raw-capture.txt'
$bytes = 0
$reads = 0
$last = Get-Date
$sb = New-Object System.Text.StringBuilder
while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
    $n = [uint32]0
    $r = [RawCom]::ReadFile($h, $buf, [uint32]$buf.Length, [ref]$n, [IntPtr]::Zero)
    if ($r -and $n -gt 0) {
        $reads++
        $bytes += $n
        [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
    } elseif (-not $r) {
        Log ("ReadFile fail err={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        break
    }
    if (((Get-Date) - $last).TotalSeconds -gt 0.5) {
        [IO.File]::AppendAllText($log, $sb.ToString()); [void]$sb.Clear(); $last = Get-Date
    }
}
[IO.File]::AppendAllText($log, $sb.ToString())
Log ("raw read done reads={0} bytes={1}" -f $reads, $bytes)
[void][RawCom]::CloseHandle($h)
