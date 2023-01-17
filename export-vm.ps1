. .\Variables.ps1
Clear-Host
Write-Host "VM to export" -ForegroundColor Red
$ExistingVMList = Get-VM
$ExistingVMList | ForEach-Object {$index=0} {$_;$index++} | Format-Table -Property @{Label="Index";Expression={$index}},Name,State

$VMSelected = Read-Host "Chose VM to export, multiple vm can be selected by coma separation`nex. 1,3 (b) for back, (e) for exit"
if ($VMSelected -like "b") {
    Invoke-Script -ScriptItem Main -PauseBefore $false
    exit
} elseif ($VMSelected -like "e") {
    exit
}
