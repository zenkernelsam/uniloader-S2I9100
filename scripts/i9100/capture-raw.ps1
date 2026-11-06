param([ValidatePattern('^COM[0-9]+$')][string]$Port,
      [ValidateRange(1,3600)][int]$Seconds=900,
      [string]$ReaderExe)
$ErrorActionPreference='Stop'
$loader=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $ReaderExe) { $ReaderExe=Join-Path $loader 'out/one-shot/host/rawcom.exe' }
if (-not (Test-Path -LiteralPath $ReaderExe)) { throw "Reader executable missing: $ReaderExe" }
if (-not $Port) {
    $device=Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match 'VID_0525&PID_A4A7' -and
            $_.InstanceId -match 'S2I9100-OS6' -and $_.FriendlyName -match '\(COM[0-9]+\)' } |
        Select-Object -First 1
    if (-not $device) { throw 'S2I9100-OS6 is not present. Connect the candidate loader, or supply its -Port.' }
    $Port=[regex]::Match($device.FriendlyName,'\((COM[0-9]+)\)').Groups[1].Value
}
$run=Join-Path $loader ('out/captures/' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[void][IO.Directory]::CreateDirectory($run)
[IO.File]::WriteAllText((Join-Path $run 'session.txt'),"started=$([DateTime]::UtcNow.ToString('o'))`r`nport=$Port`r`n")
Write-Output "Opening $Port once; evidence: $run"
Write-Output 'A driver-blocked Open may require device disconnect. Do not start another reader or force-kill it.'
# The executable also owns a process-wide mutex. No WMI serial probing,
# .NET SerialPort, retry loop, forced kill, or text conversion of received bytes.
& $ReaderExe $Port $Seconds $run
Write-Output "Reader exit: $LASTEXITCODE; evidence: $run"
