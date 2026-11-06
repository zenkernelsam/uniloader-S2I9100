param([ValidatePattern('^COM[0-9]+$')][string]$Port,
      [ValidateRange(1,3600)][int]$Seconds=900,
      [string]$ReaderExe,
      [ValidateSet('ping','status','root-status','reboot','reboot-download')][string]$Send,
      [ValidatePattern('^[0-9a-f]{16}$')][string]$ExpectBuild)
$ErrorActionPreference='Stop'
$loader=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $ReaderExe) { $ReaderExe=Join-Path $loader 'out/one-shot/host/rawcom.exe' }
if (-not (Test-Path -LiteralPath $ReaderExe)) { throw "Reader executable missing: $ReaderExe" }
if (-not $Port) {
    $devices=@(Get-PnpDevice -PresentOnly -Class Ports -ErrorAction Stop |
        Where-Object { $_.InstanceId -eq 'USB\VID_0525&PID_A4A7\S2I9100-OS6' -and
            $_.Status -eq 'OK' -and $_.FriendlyName -match '\(COM[0-9]+\)' })
    if ($devices.Count -ne 1) { throw 'Expected exactly one healthy S2I9100-OS6 COM device.' }
    $device=$devices[0]
    $Port=[regex]::Match($device.FriendlyName,'\((COM[0-9]+)\)').Groups[1].Value
}
$run=Join-Path $loader ('out/captures/' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[void][IO.Directory]::CreateDirectory($run)
[IO.File]::WriteAllText((Join-Path $run 'session.txt'),"started=$([DateTime]::UtcNow.ToString('o'))`r`nport=$Port`r`n")
Write-Output "Opening $Port once; evidence: $run"
Write-Output 'A driver-blocked Open may require device disconnect. Do not start another reader or force-kill it.'
# The executable also owns a process-wide mutex. No WMI serial probing,
# .NET SerialPort, retry loop, forced kill, or text conversion of received bytes.
$readerArgs=@($Port,$Seconds,$run)
if ($Send) { $readerArgs+=@('-Send',$Send) }
if ($ExpectBuild) {
    if (-not $Send) { throw '-ExpectBuild requires -Send.' }
    $readerArgs+=@('-Expect',$ExpectBuild)
}
& $ReaderExe @readerArgs
Write-Output "Reader exit: $LASTEXITCODE; evidence: $run"
if ($LASTEXITCODE -ne 0) { throw 'Reader failed; stop without retrying or killing it.' }
