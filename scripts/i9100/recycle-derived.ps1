param(
    [Parameter(Mandatory=$true)][string]$Plan,
    [Parameter(Mandatory=$true)][string]$PlanSha256,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$project=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$archive=Join-Path $project 'research\archive\'
$planPath=[IO.Path]::GetFullPath($Plan)
$outputPath=[IO.Path]::GetFullPath($Output)
if (-not $planPath.StartsWith($archive,[StringComparison]::OrdinalIgnoreCase) -or
    -not $outputPath.StartsWith($archive,[StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $outputPath)) { throw 'Use retained plan and fresh receipt inside the project archive' }
if ((Get-FileHash -LiteralPath $planPath).Hash.ToLowerInvariant() -ne $PlanSha256.ToLowerInvariant()) {
    throw 'Plan SHA256 differs'
}
$record=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ($record.schema -ne 2 -or $record.hardware_access -ne $false -or
    $record.product_dependency_conflicts.Count -ne 0 -or $record.file_count -le 0) { throw 'Invalid retirement evidence' }
$targets=[Collections.Generic.List[object]]::new()
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($row in $record.files) {
    if ($row.path -notmatch '^uniloader-S2I9100/out/automation/control-2026111[3-6]-[A-Za-z0-9-]+/(Image\.raw|Image\.lz4|mach_kernel)$' -or
        -not $seen.Add([string]$row.path)) { throw 'Path not in historical derived-file whitelist' }
    $absolute=[IO.Path]::GetFullPath((Join-Path $project $row.path))
    if (-not $absolute.StartsWith($project+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Target escaped project' }
    $item=Get-Item -LiteralPath $absolute -Force
    if ($item.PSIsContainer -or $item.Length -ne $row.bytes -or
        (Get-FileHash -LiteralPath $absolute).Hash.ToLowerInvariant() -ne $row.sha256) { throw 'Target changed before recycling' }
    for ($cursor=$item; $cursor -and $cursor.FullName.Length -ge $project.Length; $cursor=$cursor.Parent) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point refused' }
        if ($cursor.FullName -eq $project) { break }
        if ($cursor -is [IO.FileInfo]) { $cursor=$cursor.Directory; if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked parent refused' } }
    }
    $targets.Add([pscustomobject]@{row=$row;absolute=$absolute})
}
if ($targets.Count -ne $record.file_count) { throw 'Count differs' }
# Retained zImage, kernel, manifest and symbols were checked before plan creation.
foreach ($package in $record.packages) {
    foreach ($property in $package.retained.PSObject.Properties) {
        $file=$property.Value
        $retained=[IO.Path]::GetFullPath((Join-Path $project $file.path))
        if (-not $retained.StartsWith($project+'\',[StringComparison]::OrdinalIgnoreCase) -or
            (Get-Item -LiteralPath $retained).Length -ne $file.bytes -or
            (Get-FileHash -LiteralPath $retained).Hash.ToLowerInvariant() -ne $file.sha256) { throw 'Retained recovery evidence changed' }
    }
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bin=Join-Path ([IO.Path]::GetPathRoot($project)) ('$Recycle.Bin\'+$sid)
$before=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (Test-Path -LiteralPath $bin) {
    foreach ($file in Get-ChildItem -LiteralPath $bin -Force -Filter '$I*') { [void]$before.Add($file.Name) }
}
Add-Type -AssemblyName Microsoft.VisualBasic
$results=[Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($target.absolute,
        [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
        [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
        [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    if (Test-Path -LiteralPath $target.absolute) { throw 'Original remains' }
    $row=$target.row
    $results.Add([pscustomobject]@{path=$row.path;original=$target.absolute;bytes=$row.bytes;sha256=$row.sha256;state='recycled'})
    @{schema=2;state='inProgress';plan_sha256=$PlanSha256;files=@($results.ToArray())} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outputPath -Encoding utf8
}
$metadata=@{}
foreach ($file in Get-ChildItem -LiteralPath $bin -Force -Filter '$I*') {
    if ($before.Contains($file.Name)) { continue }
    $data=[IO.File]::ReadAllBytes($file.FullName)
    if ($data.Length -lt 28) { continue }
    $version=[BitConverter]::ToInt64($data,0)
    $offset=if ($version -eq 2) { 28 } else { 24 }
    $original=[Text.Encoding]::Unicode.GetString($data,$offset,$data.Length-$offset).TrimEnd([char]0)
    $metadata[$original]=@{metadata=$file.FullName;payload=Join-Path $bin ('$R'+$file.Name.Substring(2));bytes=[BitConverter]::ToInt64($data,8)}
}
foreach ($row in $results) {
    $entry=$metadata[$row.original]
    if (-not $entry -or $entry.bytes -ne $row.bytes -or -not (Test-Path -LiteralPath $entry.payload) -or
        (Get-Item -LiteralPath $entry.payload).Length -ne $row.bytes -or
        (Get-FileHash -LiteralPath $entry.payload).Hash.ToLowerInvariant() -ne $row.sha256) { throw 'Recycle payload not verified' }
    $row | Add-Member -NotePropertyName metadata -NotePropertyValue $entry.metadata
    $row | Add-Member -NotePropertyName payload -NotePropertyValue $entry.payload
    $row.state='verified-recyclable'
}
@{schema=2;state='PASS';plan_sha256=$PlanSha256;files=@($results.ToArray());
  file_count=$results.Count;total_bytes=($results | Measure-Object bytes -Sum).Sum;
  every_recycle_payload_sha256_verified=$true;ended_utc=(Get-Date).ToUniversalTime().ToString('o');
  permanent_delete=$false;recycle_bin_emptied=$false} |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputPath -Encoding utf8
Write-Output ("PASS {0} derived files verified in Windows Recycle Bin" -f $results.Count)
