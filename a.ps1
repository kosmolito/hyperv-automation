. .\Variables.ps1
$HostName = hostname
$TemplateMachines = Get-Content -Path "$PSScriptRoot\TemplateMachines.json" | ConvertFrom-Json
$Choices = Get-Content -Path "$PSScriptRoot\choices.json" | ConvertFrom-Json
$VMList = Get-Content -Path "$PSScriptRoot\$HostName-inventory.json" | ConvertFrom-Json

#########################################################################################################################
################# COMPARE THE VMList VM WITH EXISTING VM IN THE SYSTEM. KEEP ONLY THE EXISTING MACHINES #################

$ExistingVMList = Get-VM | Select-Object -ExpandProperty VMId
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
$TemplateMachines | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\TemplateMachines.json"

foreach ($VM in $VMList) {
    $VM.isSelected = $false
}
$VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"

foreach ($Choice in $Choices) {
    foreach ($Array in $Choice) {
        $Array.isSelected = $false
    }
}
$Choices | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\choices.json"

#########################################################################################################################
######################################################## MAIN MENU ######################################################

Clear-Host
$Choices[0] | Select-Object * -ExcludeProperty isSelected | Out-Host

[validateRange(0,2)]$ChoicesSelected = Read-Host -Prompt "Please select ONE of the option above"

#########################################################################################################################
##################################################### VM SELECTION ######################################################

switch ($ChoicesSelected[0]) {
    "0" 
    { 
        Clear-Host
        Write-Host -ForegroundColor red "New VM To Provision"
        $TemplateMachines | Format-table Index,VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        # Select the script to run and Convert the string array to int array
        $VMSelected = Read-Host "Select VM to deploy-configure, eg. 0,1"
        $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
        foreach ($VM in $TemplateMachines[$VMSelected]) {
            $VM.isSelected = $True
        }
        $TemplateMachines | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\TemplateMachines.json"
        $TemplateMachines[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        # $TemplateMachines[$VMSelected] | Format-Table option
    }
    "1" 
    {
        Clear-Host
        Write-Host -ForegroundColor red "Existing VM To Configure"
        ## This field is is entered in order to add "INDEX" column to the object
        ## ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}} is for 
        $VMList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}}, VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        # $VMList | Format-table VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        # Select the script to run and Convert the string array to int array
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

switch ($ChoicesSelected[0]) {
    "0" 
    { 
        Clear-Host
        Write-Host -ForegroundColor red "New VM Selected To Provision"
        $TemplateMachines[$VMSelected] | Format-table Index,VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $Choices[1] | Format-Table Index,option | Out-Host
        # Select the script to run and Convert the string array to int array
        $ScriptSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (exit for exit)"
        $ScriptSelected = $ScriptSelected.split(',') | ForEach-Object {Invoke-Expression $_}
        foreach ($Script in $Choices[1][$ScriptSelected]) {
            $Script.isSelected = $True
        }
        $Choices | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\choices.json"
        $Choices[1][$ScriptSelected] | Format-Table option
    }

    "1" 
    {
        Clear-Host
        Write-Host -ForegroundColor red "Existing VM Selected To Configure"
        $VMList[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $Choices[1][1..$Choices[1].Length] | Format-Table Index,option | Out-Host
        # Select the script to run and Convert the string array to int array
        $ScriptSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (exit for exit)"
        $ScriptSelected = $ScriptSelected.split(',') | ForEach-Object {Invoke-Expression $_}
        foreach ($Script in $Choices[1][$ScriptSelected]) {
            $Script.isSelected = $True
        }
        $Choices | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\choices.json"
        $Choices[1][$ScriptSelected] | Format-Table option

    }
}

#########################################################################################################################
############################################### RUNNING THE SCRIPTS CHOSEN ##############################################

$VMList = [array]$VMList + [array]$TemplateMachines[$VMSelected] | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"


foreach ($Script in $Choices[1][$ScriptSelected]) {
    $Script = $Script.ScriptPath
    & $PSScriptRoot\$Script
}