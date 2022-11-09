. .\variables.ps1
$HostName = hostname
$TemplateMachines = Get-Content -Path "$PSScriptRoot\template-machines.json" | ConvertFrom-Json
$Menu = Get-Content -Path "$PSScriptRoot\menu.json" | ConvertFrom-Json
$VMList = Get-Content -Path "$PSScriptRoot\$HostName-inventory.json" | ConvertFrom-Json

#########################################################################################################################
################# COMPARE THE VMList VM WITH EXISTING VM IN THE SYSTEM. KEEP ONLY THE EXISTING MACHINES #################

$ExistingVMList = (Get-VM).VMId.Guid
[array]$TEMPVM = $null
foreach ($VM in $VMList) {
    foreach ($ExistingVM in $ExistingVMList) {
        if ($VM.VMId -eq $ExistingVM) {
            $TEMPVM = [array]$TEMPVM + [array]$VM
        }
    }
}

$TEMPVM | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"
$VMList = Get-Content -Path "$PSScriptRoot\$HostName-inventory.json" | ConvertFrom-Json

#########################################################################################################################
####################### SETTING ALL isSelected to $false AND REASSIGN THE VARIABLE AGAIN ################################

foreach ($VM in $TemplateMachines) {
    $VM.isSelected = $false
}
$TemplateMachines | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\template-machines.json"

foreach ($VM in $VMList) {
    $VM.isSelected = $false
}
$VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"

foreach ($Array in $Menu) {
    foreach ($Item in $Array) {
        $Item.isSelected = $false
    }
}
$Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"

#########################################################################################################################
######################################################## MAIN MENU ######################################################

Clear-Host
$Menu[0] | Select-Object * -ExcludeProperty isSelected | Out-Host

$MenuSelected = Read-Host -Prompt "Please select ONE of the option above"

#########################################################################################################################
##################################################### VM SELECTION ######################################################

switch ($MenuSelected[0]) {
    "0" 
    { 
        Clear-Host
        Write-Host -ForegroundColor red "New VM To Provision"
        $TemplateMachines | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        # Select the script to run and Convert the string array to int array
        $VMSelected = Read-Host "Select VM to deploy-configure, eg. 0,1"
        $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
        foreach ($VM in $TemplateMachines[$VMSelected]) {
            $VM.isSelected = $True
        }
        $TemplateMachines | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\template-machines.json"
        $TemplateMachines[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $VMList = [array]$VMList + [array]$TemplateMachines[$VMSelected] | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"
    }
    "1" 
    {
        Clear-Host
        Write-Host -ForegroundColor red "Existing VM To Configure"
        ## This field is is entered in order to add "INDEX" column to the object
        ## ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}} is for 
        $VMList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $VMSelected = Read-Host "Select VM to configure, eg. 0,1"
        $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}

        foreach ($VM in $VMList[$VMSelected]) {
            $VM.isSelected = $True
        }
        $VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"
        $VMList[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles

    }
    "2" 
    {
        Clear-Host
        & $PSScriptRoot\delete-vm.ps1
        exit
    }
    Default {exit}
}

#########################################################################################################################
#################################################### SCRIPTS TO CHOSE ###################################################

switch ($MenuSelected[0]) {
    "0" 
    { 
        Clear-Host
        Write-Host -ForegroundColor red "New VM Selected To Provision"
        $TemplateMachines[$VMSelected] | Format-table Index,VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $Menu[1] | Format-Table Index,option | Out-Host

        $MenuSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (exit for exit)"
        $MenuSelected = $MenuSelected.split(',') | ForEach-Object {Invoke-Expression $_}
        foreach ($Script in $Menu[1][$MenuSelected]) {
            $Script.isSelected = $True
        }
        $Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"
        $Menu[1][$MenuSelected] | Format-Table option
    }

    "1" 
    {
        Clear-Host
        Write-Host -ForegroundColor red "Existing VM Selected To Configure"
        $VMList[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $Menu[1][1..$Menu[1].Length] | Format-Table Index,option | Out-Host

        $MenuSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (exit for exit)"
        $MenuSelected = $MenuSelected.split(',') | ForEach-Object {Invoke-Expression $_}
        foreach ($Script in $Menu[1][$MenuSelected]) {
            $Script.isSelected = $True
        }
        $Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"
        $Menu[1][$MenuSelected] | Format-Table option

    }
}

#########################################################################################################################
############################################### RUNNING THE SCRIPTS CHOSEN ##############################################

$Confirmation = read-host "The Following Scripts Will be Run, Do you want to continue? (y/n)"
if ($Confirmation -eq "y" -or $Confirmation -eq "yes") {
    foreach ($Selection in $Menu[1][$MenuSelected]) {
        $Script = ($Selection).ScriptPath
        & $PSScriptRoot\$Script
    }
} else{
    Write-Host -ForegroundColor red -BackgroundColor Black  "Sorry I did not get correct confirmation. EXITING..."
    exit
}