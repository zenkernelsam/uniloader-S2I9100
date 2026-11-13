$logp = "D:\Desktop\Git\ios-samsung-i9100\out\sd_dump_read.log"
try {
    $fs = [System.IO.File]::Open("\\.\PHYSICALDRIVE2", 'Open', 'Read', 'ReadWrite')
    $fs.Position = 16 * 512
    $buf = New-Object byte[] (512 * 2)
    [void]$fs.Read($buf, 0, $buf.Length)
    $fs.Close()
    [System.IO.File]::WriteAllBytes("D:\Desktop\Git\ios-samsung-i9100\out\forensic-lba16-17.bin", $buf)
    $sdhb = ($buf[0] -eq 0x42 -and $buf[1] -eq 0x48 -and $buf[2] -eq 0x44 -and $buf[3] -eq 0x53)
    $dm1f = ($buf[512] -eq 0x44 -and $buf[513] -eq 0x4D -and $buf[514] -eq 0x31 -and $buf[515] -eq 0x46)
    [System.IO.File]::WriteAllText($logp, "LBA16 SDHB=$sdhb LBA17 DM1F=$dm1f")
} catch {
    [System.IO.File]::WriteAllText($logp, "ERROR: " + $_.Exception.ToString())
}
