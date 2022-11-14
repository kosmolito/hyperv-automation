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
    -EmployeeID $username `
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

function Install-FeaturesAndRoles {
    param($Role)

    switch ($Role) {
        "AD-Domain-Services" 
        {

            if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {               
                Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
                Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

                Write-Verbose "Configuring New Domain with Name [$DomainName] on VM [$($VM.VMName)]" -Verbose
                Import-Module ADDSDeployment

                Install-ADDSForest `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -DomainMode "WinThreshold" `
                -DomainName $DomainName `
                -DomainNetbiosName $DomainNetbiosName `
                -ForestMode "WinThreshold" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$false `
                -SysvolPath "C:\Windows\SYSVOL" `
                -SafeModeAdministratorPassword $ForestRecoveryPwd `
                -Force:$true
            }

        }

        "DNS" 
        {  

            if (((Get-WindowsFeature -Name DNS).InstallState) -notlike "Installed") {
                Write-Verbose "Installing [$Role] on VM [$($VM.VMName)]" -Verbose
                Install-WindowsFeature -Name DNS -IncludeAllSubFeature -IncludeManagementTools
            }

        }

        "DHCP" 
        {
            if (((Get-WindowsFeature -Name DHCP).InstallState) -notlike "Installed") {
                Write-Verbose "Installing [$Role] on VM [$($VM.VMName)]" -Verbose
                Install-WindowsFeature -Name DHCP -IncludeAllSubFeature -IncludeManagementTools
            }

            if (((Get-DhcpServerv4Scope).Name -notlike "staff_ipv4_scope")) {
            # Selecting the first 3 part of the ip-address (Network-Address)
            $NetworkAddress = $VM.IPAddress.Split(".")[0,1,2]
            $tempAddress = $null
            foreach ($octet in $NetworkAddress) {
                $tempAddress += $octet + "."
            }
            $NetworkAddress = $tempAddress
            Write-Host -ForegroundColor green "NetWorkAdress:" $NetworkAddress
            
            netsh dhcp add securitygroups
            Restart-Service dhcpserver
            Add-DhcpServerInDC -DnsName ($VM.VMName + "." + $DomainName) -IPAddress $VM.IPAddress
            Get-DhcpServerInDC
            Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
            Set-DhcpServerv4DnsSetting -ComputerName ($VM.VMName + "." + $DomainName) -DynamicUpdates "Always" -DeleteDnsRRonLeaseExpiry $True
        
            ######### SETTING UP THE SCOPE #########
            Add-DhcpServerv4Scope -name "staff_ipv4_scope" -StartRange "$($NetworkAddress)100" -EndRange "$($NetworkAddress)200" -SubnetMask 255.255.255.0 -State Active
            Add-DhcpServerv4ExclusionRange -ScopeID "$($NetworkAddress)0" -StartRange "$($NetworkAddress)1" -EndRange "$($NetworkAddress)30"
            Set-DhcpServerv4OptionValue -OptionID 3 -Value "$($NetworkAddress)1" -ScopeID "$($NetworkAddress)0" -ComputerName AD01.mstile.se
            Set-DhcpServerv4OptionValue -DnsDomain AD01.mstile.se -DnsServer "$($NetworkAddress)10"
        }
  

        }

        "FS-DFS-Namespace" 
        {
            if (((Get-WindowsFeature -Name FS-DFS-Namespace).InstallState) -notlike "Installed") {
                Write-Verbose "Installing [$Role] on VM [$($VM.VMName)]" -Verbose
                Install-WindowsFeature -Name FS-DFS-Namespace -IncludeAllSubFeature -IncludeManagementTools
            }
        }

        "FS-DFS-Replication" 
        {
            if (((Get-WindowsFeature -Name FS-DFS-Replication).InstallState) -notlike "Installed") {
                Write-Verbose "Installing [$Role] on VM [$($VM.VMName)]" -Verbose
                Install-WindowsFeature -Name FS-DFS-Replication -IncludeAllSubFeature -IncludeManagementTools
            }
        }
        "DirectAccess-VPN" 
        {
            if (((Get-WindowsFeature -Name DirectAccess-VPN).InstallState) -notlike "Installed") {
                Write-Verbose "Installing [$Role] on VM [$($VM.VMName)]" -Verbose
                Install-WindowsFeature -Name DirectAccess-VPN -IncludeAllSubFeature -IncludeManagementTools
            }
        }
        default { write-host -ForegroundColor red "Not Finding any valid Roles or Features!" }
    }

}
$InstallFeaturesAndRoles = Get-Content function:Install-FeaturesAndRoles


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

if (!(test-path "$PSScriptRoot\old-deployments")) {
	New-Item -Path "$PSScriptRoot\old-deployments" -ItemType Directory
	New-Item -Path "$PSScriptRoot\old-deployments\$HostName-old-deployments.json" -ItemType File
}

$Menu = Get-Content -Path "$PSScriptRoot\menu.json" | ConvertFrom-Json
$TemplateMachines = Get-Content -Path "$PSScriptRoot\template-machines.json" | ConvertFrom-Json
$VMList = Get-Content -Path "$PSScriptRoot\$HostName-inventory.json" | ConvertFrom-Json
$OldDeployments = Get-Content -Path "$PSScriptRoot\old-deployments\$HostName-old-deployments.json" | ConvertFrom-Json
$UserList = Import-Csv -path "$PSScriptRoot\domain-users.csv"


################################## Credentials ##################################
$Credentials = Import-Csv -path "$PSScriptRoot\Credentials.csv"
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