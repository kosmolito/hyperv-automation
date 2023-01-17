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

$VMToExport = $ExistingVMList[$VMSelected]
Write-Host "VM Selected to export" -ForegroundColor Red
$VMToExport | Format-Table Name,State

$VMExportPath = Read-Host "Specify the path where you want to export the VM(s), (b) for back"

if ($VMExportPath -like "b") {
    Invoke-Script -ScriptItem ItSelf -PauseBefore $false
    exit
}

$VMToExport | ForEach-Object {

    if ($_.State -like "Running") {
        Write-Host "[$($_.VMName)] is in RUNNING state. Press Enter to turn off the VM"
        Pause
        Stop-VM -VMName $_.VMName -Force -Verbose
        Start-Sleep -Seconds 1
    }

    $VHD = Get-VHD -Path $_.HardDrives.Path
    $VHD | Out-Host
    if (Test-Path ("$VMExportPath\$($_.VMName)")) {
        Write-Error "The folder ["$VMExportPath\$($_.VMName)"] already exist! skipping [$($_.VMName)]"
        Invoke-Script -ScriptItem ItSelf
        exit
    } elseif ($VHD.VhdType -like "Differencing") {
        Write-Error "differencing VHD type not supported! Skipping [$($_.VMName)]"
        Invoke-Script -ScriptItem ItSelf
        exit
    } else {
        Export-VM -Name $_.VMName -Path $VMExportPath -Verbose
    }
}
Invoke-Script -ScriptItem ItSelf