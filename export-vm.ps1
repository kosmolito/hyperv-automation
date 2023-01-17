. .\Variables.ps1
Clear-Host
Write-Host "VM to export" -ForegroundColor Red
$ExistingVMList = Get-VM
$ExistingVMList | ForEach-Object {$index=0} {$_;$index++} | Format-Table -Property @{Label="Index";Expression={$index}},Name,State
