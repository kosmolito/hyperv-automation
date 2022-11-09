# Importing All Variables from the variable.ps1 file
. .\Variables.ps1

foreach ($VM in $VMList) {
    $VM.isSelected = $false
}
$VMList | Export-Csv -Path .\vm-to-deploy.csv

# Clean the screen
Clear-Host
############################################# REQUIRMENT CHECK ##############################################


Write-Host -ForegroundColor Yellow "Checking requirement files.."
foreach ($Requirment in $RequirementFiles) {
    if ((Test-Path $Requirment) -eq $false) {
        Write-Host -ForegroundColor Red "WARNING! The Requirement file:" $Requirment "is missing!"
        Write-Host -ForegroundColor Red "EXITING..."
        exit
    }
}

Write-Host -ForegroundColor green "All required files found :)"



################################## Delete - Deploy/Configure Option ###################################

Write-Host -ForegroundColor Green "----------------------------------"
Write-Host -ForegroundColor Red "||  KARKER MASTER SCRIPT V 1.6  ||"
Write-Host -ForegroundColor Green "----------------------------------"
$i = 0
foreach ($Option in $OptionToGo) {
    Write-Host -ForegroundColor green $i" - " -NoNewline
    Write-Host -ForegroundColor green "Name:" $Option
    $i++
}
Write-Host -ForegroundColor Green "--------------------------------"

# Select the script to run and Convert the string array to int array
[array]$OptionSelected = Read-Host "Please select ONE of the option above"
$OptionSelected = $OptionSelected.split(',') | ForEach-Object {Invoke-Expression $_}
$OptionToGo = $OptionToGo[$OptionSelected]


if ($OptionToGo -like "delete-VM") {
    Clear-Host
    & $DeleteVMScript
    exit
}

# Remove the vm-to-deploy if the file exist already in order to enter new data of selected VM to deploy / configure
if ($OptionToGo -like "deploy-configure-new-VM") {


    # Show all the available VM
    Clear-Host
    Write-Host -ForegroundColor Green "----------------------------------"
    Write-Host -ForegroundColor Red "|||| VM MACHINE LIST TO CHOSE ||||"
    Write-Host -ForegroundColor Green "----------------------------------"
    $i = 0
    foreach ($VM in $NewVMList) {
        Write-Host -ForegroundColor green $i" - " -NoNewline
        Write-Host -ForegroundColor green "Name:" $VM.VMName "- Role:" $VM.Roles "- Ipv4:" $VM.IPAddress "- DNS:" $VM.DNSAddress1
        $i++
    }
    Write-Host -ForegroundColor Green "----------------------------------"

    # Select the VM to chose, Convert the string array to int array
    [array]$VMSelected = Read-Host "Please select VM to deploy/configure, eg. 0,1"
    $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
    $VMList = $NewVMList[$VMSelected]
    $VMSelected = $VMList

    foreach ($VM in $VMSelected) {
        $VM.isSelected = $True
    }

    # If the old file exist. Move that to "old-deployments" folder
    $VMListPath = "$PSScriptRoot\vm-to-deploy.csv"
    if (test-path ($VMListPath)) {
        Move-Item $VMListPath -Destination $OldDeployments
    }
    $VMList | Export-Csv -Path "$PSScriptRoot\vm-to-deploy.csv"
}

if ($OptionToGo -like "configure-existing-VM") {
    $VMList = Import-Csv -path "$PSScriptRoot\vm-to-deploy.csv"


    # Show all the available VM
    Clear-Host
    Write-Host -ForegroundColor Green "----------------------------------"
    Write-Host -ForegroundColor Red "|||| EXISTING VM MACHINE LIST TO CHOSE ||||"
    Write-Host -ForegroundColor Green "----------------------------------"
    $i = 0
    foreach ($VM in $VMList) {
        Write-Host -ForegroundColor green $i" - " -NoNewline
        Write-Host -ForegroundColor green "Name:" $VM.VMName "- Role:" $VM.Roles
        $i++
    }
    Write-Host -ForegroundColor Green "----------------------------------"

    # Select the VM to chose, Convert the string array to int array
    [array]$VMSelected = Read-Host "Please select the which VM to deploy/configure, eg. 0,1"
    $VMSelected = $VMSelected.split(',') | ForEach-Object {Invoke-Expression $_}
    $VMSelected = $VMList[$VMSelected]

    foreach ($VM in $VMSelected) {
        $VM.isSelected = $True
    }
    $VMList | Export-Csv -Path "$PSScriptRoot\vm-to-deploy.csv"


}

###########################################################################################################



################################################ CHOSE VM #################################################

# Clean the screen
Clear-Host

Write-Host -ForegroundColor Red "|||" $VMSelected.count "Machines will be deployed/configured, details shown down below |||"
foreach ($VM in $VMSelected) {
    Write-Host -ForegroundColor Yellow "------------------------"
    Write-Host -ForegroundColor green "Name:" $VM.VMName "- Role:" $VM.Roles

}


################################### CHOSE SCRIPTS ###################################

# Show all the available scripts
Write-Host -ForegroundColor Green "------------------------"

# Removing VM deployment script if chosing convigure existing VM
if ($OptionToGo -like "configure-existing-VM") {
    $i = 1
}else {
    $i = 0
}


for ($i; $i -lt $ScriptList.Count) {
    Write-Host $i" - " -NoNewline
    Write-Host $ScriptList[$i]
    $i++
}

Write-Host -ForegroundColor Green "------------------------"

# Select the script to run and Convert the string array to int array
[array]$ScriptsToRun = read-host "Please select the script to run `nMultiple scripts can be chosen eg. 0,2,5 (exit for exit)"


$ScriptsToRun = $ScriptsToRun.split(',') | ForEach-Object {Invoke-Expression $_}
$ScriptsToRun = $ScriptList[$ScriptsToRun]

Write-Host -ForegroundColor Yellow "-------------------------"

foreach ($Script in $ScriptsToRun) {
    Write-Host "# " -NoNewline
    Write-Host -ForegroundColor Green $Script
}
Write-Host -ForegroundColor Yellow "-------------------------"

$Confirmation = read-host "The Following Scripts Will be Run, Do you want to continue? (y/n)"

if ($Confirmation -eq "y" -or $Confirmation -eq "yes") {
        Write-Host "Ok lets get the job done then..."
        # Run The Selected Scripts
    foreach ($script in $ScriptsToRun) {
        & $PSScriptRoot\$Script
    }

} else{
     Write-Host -ForegroundColor red -BackgroundColor Black  "Sorry I did not get correct confirmation. EXITING..."
    exit
}