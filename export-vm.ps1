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
$VMSelected = $VMSelected.split(",")
$VMSelected | ForEach-Object {

    # If the selection is not a digit, trough an error and reload the script
    if ($_ -notmatch "\d" ) {
        write-Error "Only Numbers Allowed"
        Invoke-Script -ScriptItem ItSelf
        exit
    }

    # If the selection is out of index of available VM, through an errror and reload the script
    $VMSelected = $VMSelected | ForEach-Object { Invoke-Expression $_ }
    $VMSelected | ForEach-Object {
        if ($_ -gt ($ExistingVMList.Count -1)) {
            Write-Error "The selection was out of index! Try again."
            Invoke-Script -ScriptItem ItSelf
            exit
        }
    }
}
