param(
    [ValidateRange(1, 300)][int]$Seconds = 60,
    [ValidateRange(1, 25)][int]$AttemptSeconds = 20,
    [switch]$Reader,
    [ValidatePattern('^COM[0-9]+$')][string]$Port,
    [string]$AttemptDirectory
)

# Run only after permission for a real-device serial test. No flash commands.
# Every run gets new files; no existing evidence is truncated or deleted.
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$captureRoot = Join-Path $repo 'out\usbcdc-captures'
$encoding = New-Object Text.UTF8Encoding($false)

function Write-Event([string]$Path, [string]$Message) {
    [IO.File]::AppendAllText($Path, ("{0:o} {1}`r`n" -f [DateTime]::UtcNow, $Message), $encoding)
}

if ($Reader) {
    if (-not $Port -or -not $AttemptDirectory) { throw 'Reader requires port and evidence directory' }
    $attempt = [IO.Path]::GetFullPath($AttemptDirectory)
    if (-not $attempt.StartsWith($captureRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Evidence must stay inside the repository capture directory'
    }
    $events = Join-Path $attempt 'reader.log'
    $serial = $null
    $stream = $null
    $byteCount = 0
    $timeouts = 0
    try {
        $stream = [IO.File]::Open((Join-Path $attempt 'received.bin'),
            [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $serial = New-Object IO.Ports.SerialPort $Port,115200,None,8,One
        $serial.Handshake = [IO.Ports.Handshake]::None
        $serial.DtrEnable = $true
        $serial.RtsEnable = $true
        $serial.ReadTimeout = 300
        Write-Event $events "OPEN_BEGIN port=$Port dtr=1 rts=1"
        $serial.Open()
        Write-Event $events 'OPEN_OK'
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $buffer = New-Object byte[] 4096
        while ($watch.Elapsed.TotalSeconds -lt $AttemptSeconds) {
            try {
                $n = $serial.Read($buffer, 0, $buffer.Length)
                if ($n -gt 0) {
                    $stream.Write($buffer, 0, $n)
                    $stream.Flush()
                    [IO.File]::AppendAllText((Join-Path $attempt 'received.txt'),
                        [Text.Encoding]::ASCII.GetString($buffer, 0, $n), $encoding)
                    $byteCount += $n
                    Write-Event $events "READ n=$n total=$byteCount"
                }
            } catch [TimeoutException] { $timeouts++ }
        }
        Write-Event $events "DONE bytes=$byteCount timeouts=$timeouts"
    } catch {
        Write-Event $events ("ERROR bytes={0} {1}" -f $byteCount, $_.Exception.Message)
        exit 1
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($serial) { $serial.Dispose() }
    }
    exit 0
}

$run = Join-Path $captureRoot ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[IO.Directory]::CreateDirectory($run) | Out-Null
$events = Join-Path $run 'session.log'
Write-Event $events "SESSION seconds=$Seconds attemptSeconds=$AttemptSeconds"
Write-Output "Evidence: $run"
$watch = [Diagnostics.Stopwatch]::StartNew()
$attemptNumber = 0
while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
    $device = Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match '^USB\\VID_0525&PID_A4A7(?:&|\\)' -and
            $_.FriendlyName -match '\(COM[0-9]+\)' } | Select-Object -First 1
    if (-not $device) { Start-Sleep -Milliseconds 300; continue }
    $portName = [regex]::Match($device.FriendlyName, '\((COM[0-9]+)\)').Groups[1].Value
    $attemptNumber++
    $attempt = Join-Path $run ('attempt-{0:D3}' -f $attemptNumber)
    [IO.Directory]::CreateDirectory($attempt) | Out-Null
    Write-Event $events "DEVICE port=$portName status=$($device.Status) id=$($device.InstanceId)"
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Reader -Port {1} -AttemptSeconds {2} -AttemptDirectory "{3}"' -f
        $PSCommandPath, $portName, $AttemptSeconds, $attempt
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
    try {
        $limit = [Math]::Min($AttemptSeconds + 3, [Math]::Max(1, $Seconds - $watch.Elapsed.TotalSeconds))
        if (-not $process.WaitForExit([int]($limit * 1000))) {
            $process.Kill()
            [void]$process.WaitForExit(2000)
            Write-Event $events "READER_TIMEOUT attempt=$attemptNumber"
        } else {
            Write-Event $events "READER_EXIT attempt=$attemptNumber code=$($process.ExitCode)"
        }
    } finally {
        # Only our own reader is stopped, including on an interrupted run.
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
    Start-Sleep -Milliseconds 300
}
Write-Event $events "SESSION_END attempts=$attemptNumber"
$files = Get-ChildItem -LiteralPath $run -Recurse -Filter received.bin
$total = ($files | Measure-Object -Property Length -Sum).Sum
Write-Output "Received bytes: $total; evidence: $run"
