. .\variables.ps1
Get-ElevatedInfo
$Menu = Get-Content -Path "$PSScriptRoot\menu.json" | ConvertFrom-Json

#########################################################################################################################
################# COMPARE THE VMList VM WITH EXISTING VM IN THE SYSTEM. KEEP ONLY THE EXISTING MACHINES #################

if (($PSVersionTable.PSVersion).Major -lt 7) {
    Write-Host "Error! Powershell version 7 and newer required!" -ForegroundColor Red
    Write-Host "Powershell 7 can be downloaded from https://github.com/PowerShell/PowerShell/release" -ForegroundColor green
    Write-Host "Exiting!" -ForegroundColor red
    exit
}

$ExistingVMList = (Get-VM).VMId.Guid
[array]$TEMPVM = $null
foreach ($VM in $VMList) {
    foreach ($ExistingVM in $ExistingVMList) {
        if ($VM.VMId -eq $ExistingVM) {
            $TEMPVM = [array]$TEMPVM + [array]$VM
        }
    }
}

$TEMPVM | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
$VMList = Get-Content -Path "$ConfigFolder\inventory.json" | ConvertFrom-Json

#########################################################################################################################
####################### SETTING ALL isSelected to $false AND REASSIGN THE VARIABLE AGAIN ################################

foreach ($VM in $TemplateMachines) {
    $VM.isSelected = $false
}
$TemplateMachines | ConvertTo-Json | Out-File -FilePath $JSONTemplatePath

if (!( $Null -like $VMList )) {
    foreach ($VM in $VMList) {
        $VM.isSelected = $false
    }
    $VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
}

foreach ($Array in $Menu) {
    foreach ($Item in $Array) {
        if ($Item -match "isSelected") {
            $Item.isSelected = $False
        }
    }
}

$Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"

#########################################################################################################################
######################################################## MAIN MENU ######################################################

Clear-Host
$Menu[0] | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Option | Out-Host

$MenuSelected = Read-Host -Prompt "Please select ONE of the option above"

#########################################################################################################################
##################################################### VM SELECTION ######################################################

switch ($MenuSelected[0]) {
    "0" 
    { 
        Clear-Host
        Write-Host -ForegroundColor red "New VM To Deploy"
        $TemplateMachines | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},VMName,DomainName,isCore,IPAddress,DNSAddress,Roles,NonOSHardDrivs
        # Select the script to run and Convert the string array to int array
        $VMSelected = Read-Host "Select VM to deploy-configure, eg. 0,1 (b for back)"

        if ($VMSelected -like "b") {
            Invoke-Script -ScriptItem Main -PauseBefore $false
            exit
         } else {
            $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
         }

        
        foreach ($VM in $TemplateMachines[$VMSelected]) {
            $VM.isSelected = $True
        }
        $TemplateMachines | ConvertTo-Json | Out-File -FilePath $JSONTemplatePath
        $TemplateMachines[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,DNSAddress,NonOSHardDrivs,Roles
        $VMList = [array]$VMList + [array]$TemplateMachines[$VMSelected] | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"


            Clear-Host
            Write-Host -ForegroundColor red "New VM Selected To Deploy"
            Write-Host "You can change and save the JSON inventory file to desired values before continue" -ForegroundColor Yellow
            $TemplateMachines[$VMSelected] | Format-table VMName,DomainName,isCore,IPAddress,DNSAddress,Roles,NonOSHardDrivs
            $Menu[1] | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Option | Out-Host
            $MenuSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (b for back)"

            if ($MenuSelected -like "b") {
                Invoke-Script -ScriptItem Main -PauseBefore $false
               exit
            } else {
                $MenuSelected = $MenuSelected.split(',') | ForEach-Object {Invoke-Expression $_}
            }

            foreach ($Script in $Menu[1][$MenuSelected]) {
                $Script.isSelected = $True
            }
    
            $Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"
            $Menu[1][$MenuSelected] | Format-Table option
    }

    "1" 
    {
        Clear-Host
        Write-Host -ForegroundColor red "Existing VM To Configure"
        $VMList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},VMName,DomainName,isCore,IPAddress,DNSAddress,Roles,NonOSHardDrivs
        $VMSelected = Read-Host "Select VM to configure, eg. 0,1 (b for back)"

        if ($VMSelected -like "b") {
            Invoke-Script -ScriptItem Main -PauseBefore $false
            exit
         } else {
            $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
         }

        foreach ($VM in $VMList[$VMSelected]) {
            $VM.isSelected = $True
        }
        $VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
        $VMList[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,DNSAddress,NonOSHardDrivs,Roles

            Clear-Host
            Write-Host -ForegroundColor red "Existing VM Selected To Configure"
            $VMList[$VMSelected] | Format-table -Property VMName,DomainName,IPAddress,DNSAddress,Roles
            $Menu[1][1..$Menu[1].Length] | ForEach-Object {$index=1} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Option | Out-Host
            $MenuSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (b for back)"

            if ($MenuSelected -like "b") {
                Invoke-Script -ScriptItem Main -PauseBefore $false
               exit
            } else {
                $MenuSelected = $MenuSelected.split(',') | ForEach-Object {Invoke-Expression $_}
            }
            
            foreach ($Script in $Menu[1][$MenuSelected]) {
                $Script.isSelected = $True
            }

            $Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"
            $Menu[1][$MenuSelected] | Format-Table option

    }

    "2" { Clear-Host;& $PSScriptRoot\delete-vm.ps1;exit }

    "3" { Clear-Host;& "$PSScriptRoot\config-change.ps1";exit }

    "4" { Clear-Host;& "$PSScriptRoot\export-vm.ps1";exit }
    
    Default {exit}
}

#########################################################################################################################
############################################### RUNNING THE SCRIPTS CHOSEN ##############################################

$Confirmation = read-host "The Following Scripts Will be Run, Do you want to continue? (y/n)"
if ($Confirmation -eq "y" -or $Confirmation -eq "yes") {
    $ScriptList = $Menu[1][$MenuSelected]
    $ScriptIndex = 0
    foreach ($Selection in $ScriptList) {
        $Script = ($Selection).ScriptPath
    if (($ScriptIndex -gt 0) -and ( $ScriptList[($ScriptIndex - 1)].ScriptPath -like "network-config.ps1")) {
       Write-Host "waiting for network configuration to be completed" -ForegroundColor Yellow
       Start-Sleep -Seconds 10
    }
    & $PSScriptRoot\$Script
    $ScriptIndex++

    }
} else{
    Write-Host -ForegroundColor red -BackgroundColor Black  "Sorry I did not get correct confirmation. EXITING..."
    exit
}