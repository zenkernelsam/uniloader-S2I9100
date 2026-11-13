param([string]$Port='COM12',[int]$Wait=12,[int]$Read=65536)
$p = New-Object System.IO.Ports.SerialPort($Port,115200,'None',8,'One')
$p.ReadTimeout=800; $p.WriteTimeout=3000; $p.DtrEnable=$true
try { $p.Open() } catch { Write-Host "OPEN_FAIL $_"; exit 1 }
Start-Sleep -Seconds $Wait
$buf = New-Object byte[] $Read
try { $n = $p.Read($buf,0,$Read) } catch { $n = -1 }
$p.Close()
Write-Host "read=$n"
if ($n -gt 0) { [System.Text.Encoding]::ASCII.GetString($buf,0,$n) -split "`r?`n" | Select-Object -Last 18 }
