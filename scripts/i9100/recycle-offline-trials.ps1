param(
    [Parameter(Mandatory=$true)][string]$Plan,
    [Parameter(Mandatory=$true)][string]$PlanSha256,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$project=[System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$planPath=[System.IO.Path]::GetFullPath($Plan)
$outputPath=[System.IO.Path]::GetFullPath($Output)
$archivePrefix=Join-Path $project 'research\archive\'
if (-not $planPath.StartsWith($archivePrefix,[System.StringComparison]::OrdinalIgnoreCase) -or
    -not $outputPath.StartsWith($archivePrefix,[System.StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $outputPath)) { throw 'Use retained project archive plan and a fresh receipt file' }
if ((Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $PlanSha256.ToLowerInvariant()) {
    throw 'Retirement plan SHA256 changed'
}
$record=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ($record.schema -ne 1 -or $record.hardware_access -ne $false -or $record.product_dependency_conflicts.Count -ne 0) {
    throw 'Unverified retirement plan'
}
$allowedVolumes=@(
    'uniloader-S2I9100/out/ios6-data-volume-20261120-021014-924377/DATAFS.HFS',
    'uniloader-S2I9100/out/ios6-data-volume-20261120-021545-946163/DATAFS.HFS',
    'uniloader-S2I9100/out/ios6-data-layout-probe-20261120/blank.hfs',
    'uniloader-S2I9100/out/ios6-system-volume-20261120-022721-579846/FACTORYFS.HFS',
    'uniloader-S2I9100/out/ios6-system-volume-20261120-023623-120833/FACTORYFS.HFS',
    'uniloader-S2I9100/out/one-shot/ROOTFS6-inspect.hfs'
)
$targetRows=@()
foreach ($row in $record.files) {
    $relative=[string]$row.path
    $isHostObject=($relative -match '^xnu-S2I9100/out/.+/host-model-[A-Za-z0-9_-]+\.(c|cpp)\.o$')
    if (($allowedVolumes -notcontains $relative) -and -not $isHostObject) { throw "Not in exact retirement whitelist: $relative" }
    if ($relative -match '(^|/)\.\.(/|$)|\\|:') { throw 'Noncanonical relative path' }
    $absolute=[System.IO.Path]::GetFullPath((Join-Path $project $relative))
    if (-not $absolute.StartsWith($project+'\',[System.StringComparison]::OrdinalIgnoreCase)) { throw 'Target escaped project' }
    $item=Get-Item -LiteralPath $absolute -Force
    if ($item.PSIsContainer -or $item.Length -ne $row.bytes) { throw "File missing or resized: $relative" }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked file refused: $relative" }
    for ($cursor=$item.Directory; $cursor -and $cursor.FullName.Length -ge $project.Length; $cursor=$cursor.Parent) {
        if ($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked target refused: $relative" }
        if ($cursor.FullName -eq $project) { break }
    }
    if ($isHostObject -and $item.LastWriteTimeUtc -ge [datetime]'2026-11-20T12:20:00Z') { throw 'Current-round host intermediate is protected' }
    $targetRows+=@{row=$row;absolute=$absolute}
}
if ($targetRows.Count -ne $record.file_count) { throw 'Retirement count differs' }
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$recycle=Join-Path ([System.IO.Path]::GetPathRoot($project)) ('$Recycle.Bin\'+$sid)
if (-not (Test-Path -LiteralPath $recycle)) { throw 'Windows recycle metadata directory is unavailable' }
$before=@(Get-ChildItem -LiteralPath $recycle -Force -Filter '$I*' | Select-Object -ExpandProperty Name)
$beforeSet=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach($name in $before){[void]$beforeSet.Add($name)}
$started=Get-Date
$results=[System.Collections.Generic.List[object]]::new()
Add-Type -AssemblyName Microsoft.VisualBasic
foreach ($target in $targetRows) {
    $row=$target.row
    if ((Get-FileHash -LiteralPath $target.absolute -Algorithm SHA256).Hash.ToLowerInvariant() -ne $row.sha256) {
        throw "File SHA changed before recycling: $($row.path)"
    }
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($target.absolute,
        [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
        [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
        [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    if(Test-Path -LiteralPath $target.absolute){throw 'Recycle did not remove the original file'}
    $results.Add([pscustomobject]@{path=$row.path;original=$target.absolute;bytes=$row.bytes;sha256=$row.sha256;state='sent-to-Windows-recycle-bin'})
    if ($results.Count -le 6 -or ($results.Count % 100) -eq 0) {
        Write-Output ("RECYCLED {0}/{1} {2}" -f $results.Count,$targetRows.Count,$row.path)
        @{schema=1;state='inProgress';plan_sha256=$PlanSha256;files=@($results.ToArray());recycle_bin=$recycle} |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outputPath -Encoding utf8
    }
}
# Read original-path $I records rather than guessing from opaque $R names.
$metadata=@{}
foreach($file in Get-ChildItem -LiteralPath $recycle -Force -Filter '$I*') {
    if($beforeSet.Contains($file.Name)){continue}
    $bytes=[System.IO.File]::ReadAllBytes($file.FullName)
    if($bytes.Length -lt 26){continue}
    $version=[BitConverter]::ToInt64($bytes,0)
    $length=[BitConverter]::ToInt64($bytes,8)
    $offset=if($version -eq 2){28}else{24}
    if($bytes.Length -lt $offset){continue}
    $original=[System.Text.Encoding]::Unicode.GetString($bytes,$offset,$bytes.Length-$offset).TrimEnd([char]0)
    $payload=Join-Path $recycle ('$R'+$file.Name.Substring(2))
    $metadata[$original]=@{metadata=$file.FullName;payload=$payload;bytes=$length}
}
foreach($result in $results){
    $entry=$metadata[$result.original]
    if(-not $entry -or $entry.bytes -ne $result.bytes -or -not(Test-Path -LiteralPath $entry.payload) -or
       (Get-Item -LiteralPath $entry.payload).Length -ne $result.bytes){throw "Windows recycle receipt missing: $($result.path)"}
    $result | Add-Member -NotePropertyName metadata -NotePropertyValue $entry.metadata
    $result | Add-Member -NotePropertyName payload -NotePropertyValue $entry.payload
    $result.state='verified-recyclable'
}
$receipt=@{schema=1;state='PASS';plan_sha256=$PlanSha256;started_utc=$started.ToUniversalTime().ToString('o');
    ended_utc=(Get-Date).ToUniversalTime().ToString('o');files=@($results.ToArray());file_count=$results.Count;
    total_bytes=($results|Measure-Object bytes -Sum).Sum;recycle_bin=$recycle;permanent_delete=$false;recycle_bin_emptied=$false}
$receipt|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $outputPath -Encoding utf8
Write-Output ("PASS verified Windows recycle receipts: {0} files, {1} bytes" -f $results.Count,$receipt.total_bytes)
