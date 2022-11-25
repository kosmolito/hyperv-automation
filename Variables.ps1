########################## Functions ##########################
function Add-TheADUser {
    param($FirstName,$LastName,$UserPassword,$OU,$DomainName,$SecurityGroups)

    $FullName = $FirstName + " " + $LastName
    $username = ("$($FirstName)".ToLower() + "." + "$($LastName)".ToLower())

    # Converting non [a-z] charactor for the username to [a-z]
    # The string has been converted to Char array and the each char is been checked.
    # If its find å ä or ö it will convert to [a-z] letters.
    # TempUsername has $null value at the beginning. Char are been added to the variable on every loop.
    $TempUserName = $null
    foreach ($Char in $UserName.ToCharArray()) {
        switch -Regex ($Char) {
        "å" { $Char = "a" }
        "ä" { $Char = "a" }
        "ö" { $Char = "o" }
        }
        $TempUserName += $Char
    }
    $UserName = $TempUserName

    $UserPassword = ConvertTo-SecureString $UserPassword -AsPlainText -Force
    $DomainNetbiosName = $DomainName.Split(".")[0]
    $DomainTop = $DomainName.Split(".")[1]
    $SecurityGroups = $SecurityGroups.split(",")

    if (-not (Get-ADOrganizationalUnit -Filter 'name -like $OU')) 
    { New-ADOrganizationalUnit -Name $OU -Path "DC=$DomainNetbiosName,DC=$DomainTop" -ProtectedFromAccidentalDeletion $false}
 
    foreach ($SecurityGroup in $SecurityGroups) {
        if (-not (Get-ADGroup -Filter 'Name -like $SecurityGroup')) 
        { New-ADGroup -Name $SecurityGroup -GroupCategory Security -GroupScope Global -Path "ou=$OU,DC=$DomainNetbiosName,DC=$DomainTop" }    
    }

    New-AdUser -AccountPassword $UserPassword `
    -GivenName $FirstName `
    -Surname $LastName `
    -DisplayName $FullName `
    -Name $FullName `
    -SamAccountName $username `
    -UserPrincipalName $username"@"$DomainName `
    -PasswordNeverExpires $true `
    -Path "ou=$OU,$(([ADSI]`"").distinguishedName)" `
    -Enabled $true

    foreach ($SecurityGroup in $SecurityGroups) {
        Add-ADGroupMember -Identity $SecurityGroup -Members $username
    }
}
# Needs to make a variable of the function in order to pass the values to the remote machine
$AddTheADUser = Get-Content function:Add-TheADUser



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

########################## End of Functions ##########################

$LogDateTime = Get-Date -UFormat %Y-%m-%d-%H%M
$HostName = hostname
$ConfigFolder = ((Get-Location).Path | ForEach-Object { Split-Path -Path $_ -Parent }) + "\$HostName-ha-config"

# Create files if its exist
if (!(test-path $ConfigFolder)) {
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


    Write-Verbose "Cannot find Config Folder. Creating folder and nessecary files..." -Verbose
    Write-Verbose "Config Folder and files have been created." -Verbose
    Write-Verbose "The Path to the config folder: [$($ConfigFolder)]`n" -Verbose
    
    Write-Host "The Credential file is located in ["$ConfigFolder\credentials.csv"]" -ForegroundColor green
    Write-Host "Change the credentials, save the file and press any key to continue ....."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    # Read-Host "Change the credentials in the csv file save the file and press any key" 
    Clear-Host
    Write-Host "==================================================================================================="
    
    Write-Host "
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
    # $Confirm = read-host "Enter yes to continue"
    while (($Confirm = read-host "Enter ( y/yes) to continue") -notmatch "y" ) {
        # $Confirm = read-host "Enter yes to continue"
        
    }

}

$TemplateMachines = Get-Content -Path "$ConfigFolder\template-machines.json" | ConvertFrom-Json
$VMList = Get-Content -Path "$ConfigFolder\inventory.json" | ConvertFrom-Json
$OldDeployments = Get-Content -Path "$ConfigFolder\old-deployments.json" | ConvertFrom-Json
$UserList = Import-Csv -path "$ConfigFolder\domain-users.csv"

$Menu = Get-Content -Path "$PSScriptRoot\menu.json" | ConvertFrom-Json
$ConfigFile = Get-Content -Path "$ConfigFolder\config.json" | ConvertFrom-Json


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