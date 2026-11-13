$procs = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match 'qemu|msend|qmon|uart2|sd-fast|uniloader' -and $_.Name -ne 'find_qemu_parent.ps1'
}
$procs | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-List
