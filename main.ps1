. .\variables.ps1
Get-ElevatedInfo
$Menu = Get-Content -Path "$PSScriptRoot\menu.json" | ConvertFrom-Json
#########################################################################################################################
####################### CHECK IF CONFIG FOLDER EXIST, IF NOT CREATE ONE AND CREATE REQUIRED FILES #######################

# Create files if its exist
if (!(test-path $ConfigFolder)) {
    Clear-Host
    Write-Verbose "Cannot find Config Folder. Creating folder and nessecary files..." -Verbose
    New-Item -Path $ConfigFolder -ItemType Directory | Out-Null

    if (!(test-path "$ConfigFolder\config.json")) {
        Copy-Item "$PSScriptRoot\example-resource\example-config.json" -Destination "$ConfigFolder\config.json" | Out-Null
    }

    if (!(test-path "$ConfigFolder\template-machines.json")) {
        Copy-Item "$PSScriptRoot\example-resource\template-machines.json" -Destination "$ConfigFolder\template-machines.json" | Out-Null
    }

    if (!(test-path "$ConfigFolder\inventory.json")) {
        New-Item -Path "$ConfigFolder\inventory.json" -ItemType File | Out-Null
    }

    if (!(test-path "$ConfigFolder\old-deployments.json")) {
        New-Item -Path "$ConfigFolder\old-deployments.json" -ItemType File | Out-Null
    }

    if (!(test-path "$ConfigFolder\credentials.csv")) {
        Copy-Item "$PSScriptRoot\example-resource\example-credentials.csv" -Destination "$ConfigFolder\credentials.csv" | Out-Null
    }

    if (!(test-path "$ConfigFolder\domain-users.csv")) {
        Copy-Item "$PSScriptRoot\example-resource\example-domain-users.csv" -Destination "$ConfigFolder\domain-users.csv" | Out-Null
    }

    Write-Verbose "Config Folder and files have been created." -Verbose
    Write-Verbose "Config folder Path:[$($ConfigFolder)]`n" -Verbose
    
    Write-Host "Change the credentials, save the file and press any Enter to continue ....." 
    Start-Sleep -Seconds 2
    notepad.exe "$ConfigFolder\credentials.csv"
    Pause
    Clear-Host
    Write-Host "==================================================================================================="
    
    Write-Host "
    `tWelcome to Hyper-v Automation`n

    `tThe main purpose of this program is to speed up the VM deployment and VM configuration.`n

    `tTemplate VM are located in template-machines.JSON file
    `tThe VM have multiple properties stored, ex. Domain, Network configurations
    `tPlease change the information to your need. 
    `tonce the VM are deployed, they will be stored in
    `t(hostname)-inventory.JSON file.`n
    `tYou will be asked for VM path where you want to save the VM
    `tSame for path to your sysprep .vhdx files for server and windows10 clients.
    `tlocated in template-machines.json file inside the config folder`n

    `tPlease report create issue if you find any bugs so it can be addressed.
    `tThe issues can be created on Github
    `tlink: (https://github.com/kosmo-lito/hyperv-automation)`n`n


    `tI hope you you find thes small scripts helpful."
    
    Write-Host "`n==================================================================================================="
    Pause

}

#########################################################################################################################
################# COMPARE THE VMList VM WITH EXISTING VM IN THE SYSTEM. KEEP ONLY THE EXISTING MACHINES #################

if (($PSVersionTable.PSVersion).Major -lt 7) {
    Write-Host "Error! Powershell version 7 and newer required!" -ForegroundColor Red
    Write-Host "Powershell 7 can be downloaded from https://github.com/PowerShell/PowerShell/releases/download/v7.3.0/PowerShell-7.3.0-win-x64.msi" -ForegroundColor green
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
$TemplateMachines | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\template-machines.json"

if (!($VMList -like $Null)) {
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
        Write-Host -ForegroundColor red "New VM To Provision"
        $TemplateMachines | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},VMName,DomainName,isCore,IPAddress,Roles,NonOSHardDrivs
        # Select the script to run and Convert the string array to int array
        $VMSelected = Read-Host "Select VM to deploy-configure, eg. 0,1 (b for back)"

        if ($VMSelected -like "b") {
            & $PSScriptRoot\main.ps1
            exit
         } else {
            $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
         }

        
        foreach ($VM in $TemplateMachines[$VMSelected]) {
            $VM.isSelected = $True
        }
        $TemplateMachines | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\template-machines.json"
        $TemplateMachines[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles
        $VMList = [array]$VMList + [array]$TemplateMachines[$VMSelected] | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"


            Clear-Host
            Write-Host -ForegroundColor red "New VM Selected To Provision"
            Write-Host "You can change and save the JSON inventory file to desired values before continue" -ForegroundColor Yellow
            $TemplateMachines[$VMSelected] | Format-table VMName,DomainName,isCore,IPAddress,Roles,NonOSHardDrivs
            $Menu[1] | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Option | Out-Host
            $MenuSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (b for back)"

            if ($MenuSelected -like "b") {
               & $PSScriptRoot\main.ps1
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
        ## This field is is entered in order to add "INDEX" column to the object
        ## ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}} is for 
        $VMList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},VMName,DomainName,isCore,IPAddress,Roles,NonOSHardDrivs
        $VMSelected = Read-Host "Select VM to configure, eg. 0,1 (b for back)"

        if ($VMSelected -like "b") {
            & $PSScriptRoot\main.ps1
            exit
         } else {
            $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
         }

        foreach ($VM in $VMList[$VMSelected]) {
            $VM.isSelected = $True
        }
        $VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
        $VMList[$VMSelected] | Format-table -Property VMName,MachineType,isCore,IPAddress,NonOSHardDrivs,Roles

            Clear-Host
            Write-Host -ForegroundColor red "Existing VM Selected To Configure"
            $VMList[$VMSelected] | Format-table -Property VMName,DomainName,IPAddress,Roles
            $Menu[1][1..$Menu[1].Length] | ForEach-Object {$index=1} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Option | Out-Host
            $MenuSelected = Read-Host "Please select the script to run`nMultiple scripts can be chosen eg. 0,2,5 (b for back)"

            if ($MenuSelected -like "b") {
               & $PSScriptRoot\main.ps1
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
    "2" 
    {
        Clear-Host
        & $PSScriptRoot\delete-vm.ps1
        exit
    }

    "3" 
    {
        Clear-Host
        Write-Host -ForegroundColor red "Template Files to Select"
        $JSONTemplateList = Get-ChildItem -Path $ConfigFolder | Where-Object {$_.Name -Match ".json$" -and $_.Name -like "*template*"}
        $JSONTemplateList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Name | Out-Host
        [int32]$TemplateSelection = Read-Host "Select a Template from the list"
        if (($JSONTemplateSelection -cle -1) -xor ($JSONTemplateSelection -gt ($JSONTemplateList.Count -1)) ) {
            Write-Error "Wrong option entered! Exiting"
            exit
        } else {
            
            ($ConfigFile | Where-Object {$_.HostName -like $HostName}).JSONTemplateFile = ($JSONTemplateList[$TemplateSelection]).FullName
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Pause
            & "$PSScriptRoot\main.ps1"
        }
    }

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