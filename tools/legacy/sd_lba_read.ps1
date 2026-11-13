$logp = $env:TEMP + "\sd_lba_read.log"
[System.IO.File]::WriteAllText($env:TEMP + "\sd_probe_alive.txt", "ran " + (Get-Date))
try {
    $fs = [System.IO.File]::Open("\\.\PHYSICALDRIVE2", 'Open', 'Read', 'ReadWrite')
    $fs.Position = 16 * 512
    $buf = New-Object byte[] 1024
    [void]$fs.Read($buf, 0, $buf.Length)
    $fs.Close()
    [System.IO.File]::WriteAllBytes(($env:TEMP + "\forensic-lba.bin"), $buf)
    $m0 = [Text.Encoding]::ASCII.GetString($buf[0..3])
    $m1 = [Text.Encoding]::ASCII.GetString($buf[512..515])
    $hex = ($buf[0..31] | ForEach-Object { $_.ToString('x2') }) -join ' '
    [System.IO.File]::WriteAllText($logp, "LBA16='$m0' LBA17='$m1'`nhead32=$hex")
} catch {
    [System.IO.File]::WriteAllText($logp, "ERROR: " + $_.Exception.ToString())
}
