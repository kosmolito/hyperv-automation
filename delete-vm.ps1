. .\Variables.ps1
#########################################################################################################################
################################################# LIST ALL EXISTING VM ##################################################

Clear-Host
Write-Host -ForegroundColor red "Existing VM to be Deleted!"
$ExistingVMList = get-vm
$ExistingVMList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}}, VMName,State,CreationTime

#########################################################################################################################
################################################## CHOSE VM TO DELETE ###################################################

# Select the script to run and Convert the string array to int array
[array]$VMSelected = Read-Host "Please select VM to DELETE eg. 0,1"
$VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
$ExistingVMSelected = $ExistingVMList[$VMSelected]
Write-Host -ForegroundColor yellow

Clear-Host
Write-Host -ForegroundColor red "$($ExistingVMSelected.count) Machines will be deleted, details shown down below"

$ExistingVMSelected | Format-Table VMName,State,CreationTime

#########################################################################################################################
###################################### DELETING OF THE SELECTED VM IF CONFIRMED  ########################################

$DeleteConfirmation = Read-Host "Do you really want to DELETE the machine(s)? (yes/no)"

if ($DeleteConfirmation -notlike "yes") {
    Write-Host -ForegroundColor red "Sorry I did not get correct confirmation, EXITING!"
    exit
} else {

    foreach ($ExistingVM in $ExistingVMSelected) {


#########################################################################################################################
################# COMPARE THE VMList VM WITH EXISTING VM IN THE SYSTEM. KEEP ONLY THE EXISTING MACHINES #################
    
    $ExistingVMID = (Get-VM $ExistingVM.VMName | Select-Object).VMId
    # [array]$TEMPVM = $null
    foreach ($VM in $VMList) {
        if ($VM.VMId -eq $ExistingVMID) {
            $VM.DeletionTime = $LogDateTime
            $OldDeployments = [array]$OldDeployments + [array]$VM
        }

    }

        if (((get-vm $ExistingVM.VMName).State) -notlike "Off") {
            Write-Verbose "[$($ExistingVM.VMName)] is running, turning off the machine.." -Verbose
            Stop-vm -Name $ExistingVM.VMName -Force
        }

        Write-Verbose "Deleting [$($ExistingVM.VMName)] and its components.." -Verbose
        foreach ($HDD in $ExistingVM) { Remove-Item $HDD.HardDrives.Path -Force }
        Remove-VM -Name $ExistingVM.VMName -Force
        Remove-Item -Recurse $ExistingVM.Path -Force
        Write-Host -ForegroundColor green "$($ExistingVM.VMName) are deleted!"
    }
}
$OldDeployments | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\old-deployments.json"


Write-Host -ForegroundColor green "All Selected VM Machines are deleted."

$BackOrExit = Read-Host "Please chose (b) for back, (e) for Exit"

#########################################################################################################################
###################################### DELETING OF THE SELECTED VM IF CONFIRMED  ########################################
switch ($BackOrExit) {
    "b" { & $PSScriptRoot\main.ps1 }
    "e" {exit}
}