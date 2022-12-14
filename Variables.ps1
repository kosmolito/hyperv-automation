########################## Functions ##########################
<#
.SYNOPSIS
Create New VHD and Attach it to a Virtual Machine. VHD type will be Dynamic Disk.
.DESCRIPTION
Long description

.PARAMETER VMName
Specify the name of VM.

.PARAMETER DiskAmount
Integer value. Specify how many disk the function will create

.PARAMETER DiskSize
Specify the Disk size in GB

.EXAMPLE
Add-HardDrive -VMName TESTVM -DiskAmount 3 -DiskSize 20GB
.NOTES
General notes
#>
function New-HardDrive {
    param ([string]$VMName,[int32]$DiskAmount,[UInt64]$DiskSize)

    $Num = 0
    $VMPath = Get-VM -Name $VMName | Select-Object -ExpandProperty Path
    for ($i = 0; $i -lt $DiskAmount; $i++) {


        $VHD = ($VMPath + "\" + $VMName + "DATA" + $Num + ".vhdx")
        
        while (test-path($VHD)) {
            $Num++
            $VHD = ($VMPath + "\" + $VMName + "DATA" + $Num + ".vhdx")
        }



        $NewVHD = New-VHD -Path $VHD -SizeBytes $DiskSize -Dynamic
        Write-Verbose "Attaching [$($NewVHD.Path)] Disk to [$($VMName)]" -Verbose
        Add-VMHardDiskDrive -VMName $VMName -Path $VHD
    }

}


function Invoke-VMConnectionConfirmation {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]$VMName,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Credential

    )

    Write-Verbose "Waiting for PowerShell to start on VM [$($VMName)]" -Verbose
    while ((Invoke-Command -VMName $VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}
    Write-Verbose "PowerShell responding on VM [$($VMName)]. Moving On...." -Verbose
}

# Check if the process is running in elevated mode, if not, the scrip stops
function Get-ElevatedInfo {
    $currentPrincipal = [System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!($isAdmin)) {
    Write-Error "You need to run the script as administrator!"
    Pause
    exit
    }
}

########################## End of Functions ##########################

$LogDateTime = Get-Date -UFormat %Y-%m-%d-%H%M
$HostName = hostname
$ConfigFolder = ((Get-Location).Path | ForEach-Object { Split-Path -Path $_ -Parent }) + "\$HostName-ha-config"

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

$Menu = Get-Content -Path "$PSScriptRoot\menu.json" | ConvertFrom-Json
$ConfigFile = Get-Content -Path "$ConfigFolder\config.json" | ConvertFrom-Json
$JSONTemplatePath = ($ConfigFile | Where-Object {$_.HostName -like $HostName}).JSONTemplateFile
$TemplateMachines = Get-Content -Path $JSONTemplatePath | ConvertFrom-Json
$VMList = Get-Content -Path "$ConfigFolder\inventory.json" | ConvertFrom-Json
$OldDeployments = Get-Content -Path "$ConfigFolder\old-deployments.json" | ConvertFrom-Json
$UserList = Import-Csv -path "$ConfigFolder\domain-users.csv"


################################## Credentials ##################################
$Credentials = Import-Csv -path "$ConfigFolder\credentials.csv"
$DomainName = $Credentials.DomainName
$DomainNetbiosName = $DomainName.Split(".")[0]

$ClientLocalAdmin = $Credentials.ClientLocalAdmin
$ClientLocalPwd = ConvertTo-SecureString $Credentials.ClientLocalPwd -AsPlainText -Force
$ClientCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientLocalAdmin, $ClientLocalPwd

$ServerLocalAdmin = $Credentials.ServerLocalAdmin
$ServerLocalPwd = ConvertTo-SecureString -String $Credentials.ServerLocalPwd -AsPlainText -Force
$ServerLocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ServerLocalAdmin, $ServerLocalPwd

$DomainAdmin = $Credentials.DomainAdmin
$DomainPwd = ConvertTo-SecureString -String $Credentials.DomainPwd -AsPlainText -Force
$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainNetbiosName\$DomainAdmin, $DomainPwd

$ForestRecoveryPwd = ConvertTo-SecureString -String $Credentials.ForestRecoveryPwd -AsPlainText -Force
######################################################################################################