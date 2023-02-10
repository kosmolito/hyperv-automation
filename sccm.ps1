. .\Variables.ps1

$VM = $VMList | Where-Object {$_.isSelected -eq $true}

$DomainName = $VM.DomainName
$DomainNetbiosName = $DomainName.split(".")[0].ToUpper()
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainName\$DomainAdmin,$DomainPwd

function Show-Menu {
    param (
        [String]$Title = "SCCM Installation / Configuration / Deployment"
    )
    Clear-Host
    Write-Host -ForegroundColor red "VM Selected"
    $VM | Format-table -Property VMName,DomainName,IPAddress,DNSAddress,NetworkSwitches
    Write-Host "================ $Title ================`n"
    Write-Host "  1: Non SCCM VM Firewall & File Sharing Configuration" -ForegroundColor Green
    Write-Host "  2: SCCM VM Installation / Configuration / Deployment" -ForegroundColor Green
    Write-Host "  B: Back to Main Menu" -ForegroundColor Green
    Write-Host "  Q: To quit" -ForegroundColor Green
}

Show-Menu
$Selection = Read-Host "Select an option from menu"


if ( $Selection -match "All" ) {
    $Selection = "All"
} elseif ( $Selection -like "Q") { 
    $Selection = $Selection 
} elseif ($Selection -like "B") {
    $Selection = $Selection
} else {
    $Selection = $Selection.Split(",") | ForEach-Object { Invoke-Expression $_ }
}

switch ($Selection) 
{
    ######################################################################################################
    ######################################################################################################
    #### Non SCCM VM LIST
    { @(1,"all") -contains $_ } {

    # Change the firewall settings for the VM other than SCCM VM
    $NonSCCMVMList = $VMList | Where-Object {$_.Roles -notcontains "SCCM" -and $_.DomainName -like $VM.DomainName}
    $NonSCCMVMList | Format-Table -Property VMName,DomainName,Roles | Out-Host
    $Confirmation = Read-Host "Do you want to continue with the Firewall & Files Sharing configuration? (Y/N)"

    if ($Confirmation -notlike "Y") {
        Write-Error "Sorry, did not get correct confirmation"
        exit
    } else {

    $NonSCCMVMList | ForEach-Object -ThrottleLimit 4 -Parallel {
        if ((Get-VM -VMName $_.VMName).State -like "Off" ) {
            Write-Verbose "[$($_.VMName)] is turned off. Starting the VM..."
            Start-VM -VMName $_.VMName -Verbose
        }
    }

    $NonSCCMVMList | ForEach-Object {
    Invoke-VMConnectionConfirmation -VMName $_.VMName -Credential $Credential
        Invoke-Command -VMName $_.VMName -Credential $Credential -ScriptBlock {

            ## FireWall config for SCCM Client push installation ##

            # Enable Files Sharing, WMI and network discovery if its not enabled already
            $Services = ("File and Printer Sharing","Windows Management Instrumentation (WMI)",”network discovery”)
            $Services | ForEach-Object {
                $Status = (Get-NetFirewallRule -DisplayGroup $_)
                $StatusCount = 0
                $Status | ForEach-Object {
                    if ($_.Enabled -like "False") {
                        $StatusCount++
                    }
                }

                if ($StatusCount -gt 0 ) {
                    Write-Verbose "Enabling [$($_)]..." -Verbose
                    Set-NetFirewallRule -DisplayGroup $_ -Enabled True -Profile Any
                    Write-Verbose "[$($_)] enabled." -Verbose
                } else {
                    Write-Verbose "[$($_)] is enabled already" -Verbose
                }
            }

            $NonSCCMFireWallRules = @{
                "Client Notification" = @{
                    Protocol = "TCP"
                    LocalPort = 10123
                    Direction = "Outbound"
                }
                "Remote Control" = @{
                    Protocol = "TCP"
                    LocalPort = 2701
                    Direction = "Inbound"
                }

            }

            # Create Firewall Rules if it does not exist already
            $NonSCCMFireWallRules.GetEnumerator() | ForEach-Object {
                if (!(Get-NetFireWallRule -DisplayName $_.Key -ErrorAction SilentlyContinue)) {
                    Write-Verbose "Creating Firewall Rule [Name:$($_.Key) :Protocol:$($_.Value.Protocol) LocalPort:$($_.Value.LocalPort)]..." -Verbose
                    New-NetFirewallRule -DisplayName $_.Key -Direction $_.Value.Direction -Protocol $_.Value.Protocol -LocalPort $_.Value.LocalPort -Action Allow | Out-Null
                }
            }
        }
    }
    }
    Invoke-Script -ScriptItem ItSelf
}

{ @(2,"all") -contains $_ } {
    ######################################################################################################
    ######################################################################################################
    #### SCCM VM
    
    if ($VM.Count -ne 1) {
        Write-Error "Only 1 VM can be selected!"
        Invoke-Script -ScriptItem Main
    }
    
    If ($VM.MachineType -notlike "server") {
        Write-Host "Only [server] types of machines are allowed!" -ForegroundColor Red
        Invoke-Script -ScriptItem Main
    }
    if (!($VM.HasJoinedDomain)) {
        Write-Host "The VM is NOT joined any Domain, Please join the VM before continue!" -ForegroundColor Red
        Invoke-Script -ScriptItem Main
    }

if ($VM.Roles -notcontains "SCCM") { 
    Write-Error "You have NOT selected a server with SCCM Role!"
    Invoke-Script -ScriptItem Main
} else {
    if ((Get-VMHardDiskDrive -VMName $VM.VMName).Path -notcontains "$ConfigFolder\sccmusb.vhdx") {
        Write-Verbose "Attaching the SCCM .vhdx file containing the installation files.." -Verbose
        Add-VMHardDiskDrive -VMName $VM.VMName -Path "$ConfigFolder\sccmusb.vhdx"
    }
}
if (((get-vm $VM.VMName).State) -like "Off") {
    Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
    Start-vm -Name $VM.VMName
}

Invoke-VMConnectionConfirmation -VMName $VM.VMName -Credential $Credential
Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {

$VM = $using:VM
$DomainName = $using:DomainName
$DomainNetbiosName = $using:DomainNetbiosName
$SiteCode = "GBG"
$SiteName = "Goteborg"

# Make the SCCM offline VHD Disk online if its not online already
if ((Get-Volume -FriendlyName "sccmusb" -ErrorAction SilentlyContinue)) {
    $SourcePath = ((Get-Volume -FriendlyName "sccmusb").DriveLetter + ":")
} else {
    Get-Disk | Where-Object {$_.OperationalStatus -like "Offline"} | Set-Disk -IsOffline $False
    $SourcePath = ((Get-Volume -FriendlyName "sccmusb").DriveLetter + ":")
}

######################################################################################################
######################################################################################################
#### Installing AD Feature

if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {
    $StartTime = Get-Date           
    Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    $EndTime = Get-Date
    $ResultTime = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host "The time it took for Active Directory Installation:"
    $ResultTime | Format-Table -Property Hours,Minutes,Seconds | Out-Host
}

######################################################################################################
######################################################################################################
#### Creating System Management Container and set the permissions

Import-Module ADDSDeployment
$DNSHostName = (Get-ADComputer -Identity $env:COMPUTERNAME).DNSHostName

Write-Verbose "Creating [System Management] Container..." -Verbose
# Get the distinguished name of the Active Directory domain
$DCPath = (Get-ADDomain).DistinguishedName

# Build distinguished name path of the System container
$SystemPath = "CN=System," + $DCPath

# Get the AD computer object for this system
$SCCMServer = Get-ADComputer -Identity $VM.VMName

# Get or create the System Management container
$Container = $null 
Try 
{ 
    $Container = Get-ADObject "CN=System Management,$SystemPath" 
} 
Catch 
{ 
Write-Verbose "System Management container does not exist." 
}

If ($null -eq $Container) { 
    $Container = New-ADObject -Type Container -name "System Management" -Path "$SystemPath" -Passthru 
}

# Get current ACL for the System Management container
Write-Verbose "Setting [System Management] container permissions..." -Verbose
$ACL = Get-ACL -Path AD:\$Container

# Get the SID for the computer object
$SID = $SCCMServer.SID

# Create a new access control entry for the System Management container
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
$SID,$adRights,$type,$inheritanceType

# Add the new access control entry to the ACL object we grabbed earlier
$ACL.AddAccessRule($ACE)

# Commit the new audit rule
Set-ACL -AclObject $ACL -Path "AD:$Container"

######################################################################################################
######################################################################################################
#### Extending AD Schema

# Extend the Active Directroy Schema if its not extended already
$SchemaPath = (Get-ADRootDSE).schemanamingContext
$SchemaAttributes = Get-ADObject -Filter * -searchbase $SchemaPath -Properties * | Where-Object Name -eq "MS-SMS-Site-Code"

if ($SchemaAttributes) { 
  Write-Verbose "The Schema has already been extended." -Verbose
}
else {
    Write-Verbose "Extending the Active Directory Schema..." -Verbose
    & "$SourcePath\MEM_Configmgr_2103\SMSSETUP\BIN\X64\extadsch.exe"
    Start-Sleep -Seconds 10
}

######################################################################################################
######################################################################################################
#### Installing IIS Roles and Features, based on the XML file

if (!((Get-WindowsFeature -Name Web-Server).InstallState -eq "Installed")) {
    $StartTime = Get-Date
    Write-Verbose "Installing roles and features [IIS]..." -Verbose
    Install-WindowsFeature -ConfigurationFilePath "$SourcePath\DeploymentConfigTemplate-IIS.xml"
    Write-Verbose "[IIS] roles and features installation completed" -Verbose
    $EndTime = Get-Date
    $ResultTime = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host "Time duration for [IIS] Roles and features installation:"
    $ResultTime | Format-Table -Property Hours,Minutes,Seconds | Out-Host
} else {
    Write-Verbose "[IIS] roles and features are installed already!" -Verbose
}

######################################################################################################
######################################################################################################
#### Installing Windows 10 ADK

# Install ADK Deployment Tools,  Windows Preinstallation Enviroment
if (!(Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit' -ErrorAction SilentlyContinue)) {
Write-Verbose "Installing Windows ADK..." -Verbose
$StartTime = Get-Date
Start-Process -FilePath "$SourcePath\ADK\adksetup.exe" -Wait `
-ArgumentList "/Features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment OptionId.ImagingAndConfigurationDesigner OptionId.ICDConfigurationDesigner OptionId.UserStateMigrationTool /norestart /quiet /ceip off" -Verbose
Start-Sleep -s 120
Write-Verbose "Windows ADK installation completed." -Verbose
$EndTime = Get-Date
$ResultTime = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host "Time duration for Windows ADK installation:"
$ResultTime | Format-Table -Property Hours,Minutes,Seconds | Out-Host
} else {
    Write-Verbose "Windows ADK is installed already! Skipping the installation." -Verbose
}

######################################################################################################
######################################################################################################
#### Firwall Rules & Configuration

# Configure Firewall Rules for SQL and Web
Write-Verbose "Configuring SQL Server Firewall settings..." -Verbose

$FireWallRules = @{
    "SQL Server" = @{
        Protocol = "TCP"
        LocalPort = 1433
    }
    "SQL Admin Connection" = @{
        Protocol = "TCP"
        LocalPort = 1434
    }
    "SQL Database Management" = @{
        Protocol = "UDP"
        LocalPort = 1434
    }
    "SQL Service Broker" = @{
        Protocol = "TCP"
        LocalPort = 4022
    }
    "SQL Debugger/RPC"= @{
        Protocol = "TCP"
        LocalPort = 135
    }
    "SQL Analysis Services"= @{
        Protocol = "TCP"
        LocalPort = 2383
    }
    "SQL Browser"= @{
        Protocol = "TCP"
        LocalPort = 2382
    }
    "SQL Server Browse Button Service"= @{
        Protocol = "UDP"
        LocalPort = 1433
    }
    "HTTP"= @{
        Protocol = "TCP"
        LocalPort = 80
    }
    "SSL"= @{
        Protocol = "TCP"
        LocalPort = 443
    }
}

# Create Firewall Rules if it does not exist already
$FireWallRules.GetEnumerator() | ForEach-Object {
    if (!(Get-NetFireWallRule -DisplayName $_.Key -ErrorAction SilentlyContinue)) {
        Write-Verbose "Creating Firewall Rule [Name:$($_.Key) :Protocol:$($_.Value.Protocol) LocalPort:$($_.Value.LocalPort)]..." -Verbose
        New-NetFirewallRule -DisplayName $_.Key -Direction Inbound -Protocol $_.Value.Protocol -LocalPort $_.Value.LocalPort -Action Allow | Out-Null
    }
}

#Enable Windows Firewall
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True

Write-Verbose "Firewall Rules configuration completed." -Verbose

######################################################################################################
######################################################################################################
#### SQL Server

$SQLsource = "$SourcePath\sqlserver2019"
$SQLSYSADMINACCOUNTS = whoami.exe
$SQLConfigData = @"
[OPTIONS]
IAcceptSQLServerLicenseTerms="True"
IACCEPTPYTHONLICENSETERMS="True"
ACTION="Install"
IACCEPTROPENLICENSETERMS="True"
SUPPRESSPRIVACYSTATEMENTNOTICE="True"
ENU="True"
QUIET="True"
UpdateEnabled="False"
USEMICROSOFTUPDATE="False"
SUPPRESSPAIDEDITIONNOTICE="False"
UpdateSource="MU"
FEATURES=SQLENGINE
HELP="False"
INDICATEPROGRESS="False"
X86="False"
INSTANCENAME="MSSQLSERVER"
INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server"
INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server"
INSTANCEID="MSSQLSERVER"
SQLTELSVCACCT="NT Service\SQLTELEMETRY"
SQLTELSVCSTARTUPTYPE="Automatic"
INSTANCEDIR="C:\Program Files\Microsoft SQL Server"
AGTSVCACCOUNT="NT Service\SQLSERVERAGENT"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL="0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
SQLMAXDOP="2"
ENABLERANU="False"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="NT Service\MSSQLSERVER"
SQLSVCINSTANTFILEINIT="False"
SQLSYSADMINACCOUNTS="$SQLSYSADMINACCOUNTS"
SQLTEMPDBFILECOUNT="2"
SQLTEMPDBFILESIZE="8"
SQLTEMPDBFILEGROWTH="64"
SQLTEMPDBLOGFILESIZE="8"
SQLTEMPDBLOGFILEGROWTH="64"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="0"
BROWSERSVCSTARTUPTYPE="Disabled"
SQLMAXMEMORY="2147483647"
SQLMINMEMORY="0"
"@

# start the SQL installer if its not installed already

# These 2 services needs exist if the SQL server is installed.
$SQLServices = "MSSQLSERVER","SQLSERVERAGENT"
$ServiceCount = 0
foreach ($Service in $SQLServices) {
    $ServiceState = Get-Service -Name $Service -ErrorAction SilentlyContinue
    if ($ServiceState) { $ServiceCount++ }
}

if ((Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server" -ErrorAction SilentlyContinue) -and $ServiceCount -eq 2) {
    Write-Verbose "Microsoft SQL Server is installed already!" -Verbose } 
else {

    $SQLConfiginiFile="c:\SQLConfigurationFile.ini"

    if (Test-Path $SQLConfiginiFile){
        Write-Verbose "Found an old Configuration file [$($SQLConfiginiFile)], removing the file..." -Verbose
        Remove-Item -Path $SQLConfiginiFile -Force
    }

    Write-Verbose "Creating a New Configuration file [$($SQLConfiginiFile)]..." -Verbose
    New-Item -Path $SQLConfiginiFile -ItemType File -Value $SQLConfigData | Out-Null

Try
{
    if (Test-Path $SQLsource){
        Write-Verbose "Microsoft SQL Server installation started..." -Verbose
        $StartTime = Get-Date
        $SQLSetupFile =  "$SQLsource\setup.exe"
        & $SQLSetupFile  /CONFIGURATIONFILE=$SQLConfiginiFile
        Write-Verbose "Installation of SQL Server completed." -Verbose
        $EndTime = Get-Date
        $ResultTime = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host "Time duration for Microsoft SQL Server Installation:"
        $ResultTime | Format-Table -Property Hours,Minutes,Seconds | Out-Host
        }  else {
        Write-Error "Could not find the media for SQL Server"
        break
    }
}
catch
{
    write-Error "Something went wrong with the installation of SQL Server, aborting."
    break
}
}

######################################################################################################
######################################################################################################
#### Installing WSUS Feature if its not installed already

if (!((Get-WindowsFeature -Name UpdateServices).InstallState -eq "Installed")) {
$WSUSFolder = "C:\WSUS"
$ServerName = $Env:COMPUTERNAME
# create WSUS folder
if (Test-Path $WSUSFolder){
    Write-Verbose "WSUS folder [$WSUSFolder] already exist."
} else {
    Write-Verbose "Creating WSUS folder [$WSUSFolder]"
    New-Item -Path $WSUSFolder -ItemType Directory | Out-Null
}

Write-Verbose "Installing WSUS roles and features..." -Verbose
$StartTime = Get-Date
Install-WindowsFeature -ConfigurationFilePath "$SourcePath\DeploymentConfigTemplate-WSUS.xml"
Start-Sleep -s 10
& "C:\Program Files\Update Services\Tools\WsusUtil.exe" postinstall SQL_INSTANCE_NAME=$ServerName CONTENT_DIR=$WSUSFolder | out-file Null
Write-Verbose "Installation of WSUS roles and features completed." -Verbose
$EndTime = Get-Date
$ResultTime = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host "Time duration for WSUS roles and features Installation:"
$ResultTime | Format-Table -Property Hours,Minutes,Seconds | Out-Host
} else {
    Write-Verbose "WSUS roles and features is installed already." -Verbose
}

######################################################################################################
######################################################################################################
#### SCCM Installation

# Status if SCCM is already installed on the machine
$SCCMStatus = Get-CimInstance Win32_Service | Where-Object {$_.Name -eq "ccmexec"}
if (!($null -eq $SCCMStatus)) {
    Write-Verbose "SCCM is already installed on the machine!" -Verbose
} else {
    # Change the account permissions of SQL services to the Domain Administrator
    Write-Verbose "Changing Account Permission of SQL Services and starting..." -Verbose
foreach ($Item in $SQLServices) {
    $Service = Get-WmiObject win32_service -Filter "Name='$Item'"
    # If the Service is not runned under the correct user and or is running, run this block
    if (!($Service.StartName -like (whoami.exe) -and $Service.State -like "Running")) {
        $Service.StopService() | Out-Null
        Start-Sleep -Seconds 5
        $Service.Change($null,$null,$null,$null,$null,$null,$SQLSYSADMINACCOUNTS,$using:ServerPwdPlainText,$null,$null,$null) | Out-Null
        $Service.StartService() | Out-Null
        Start-Sleep -Seconds 5

        $Service = Get-Service -Name $Item
        while ($Service.Status -notlike "Running") {
            Write-Verbose "Trying to start the service [$Item]..." -Verbose
            Set-Service -Name $Item -Status Running
            Start-Sleep -Seconds 5
        }
    }
}
Write-Verbose "SQL Services Permission & Status OK." -Verbose


$SCCMSource="$SourcePath\MEM_Configmgr_2103"

# start the SCCM installer
if (!(Test-Path $SCCMSource)){
    Write-Error "Could not find the installtion media for SCCM! Exiting."
    exit
} else {
    Write-Verbose "Installation media for SCCM found." -Verbose
}

# define SCCM Current Branch variables

$SCCMConfigData= @"
[Identification]
Action="InstallPrimarySite"

[Options]
ProductID="EVAL"
SiteCode="$SiteCode"
SiteName="$SiteName"
SMSInstallDir="C:\Program Files\Microsoft Configuration Manager"
SDKServer="$DNSHostName"
RoleCommunicationProtocol="HTTPorHTTPS"
ClientsUsePKICertificate="0"
PrerequisiteComp="1"
PrerequisitePath="$SourcePath\sccm"
ManagementPoint="$DNSHostName"
ManagementPointProtocol="HTTP"
DistributionPoint="$DNSHostName"
DistributionPointProtocol="HTTP"
DistributionPointInstallIIS="0"
AdminConsole="1"
JoinCEIP="0"

[SQLConfigOptions]
SQLServerName="$DNSHostName"
DatabaseName="CM_GBG"
SQLSSBPort="4022"

[CloudConnectorOptions]
CloudConnector="1"
CloudConnectorServer="$DNSHostName"
UseProxy="0"
ProxyName=""
ProxyPort=""

[SystemCenterOptions]
SysCenterId=""

[HierarchyExpansionOption]
"@

$SCCMConfigFile = "C:\ConfigMgrAutoSave-sccm.ini"

if (Test-Path $SCCMConfigFile){
    Write-Verbose "The file [$SCCMConfigFile] already exists, removing..." -Verbose
    Remove-Item -Path $SCCMConfigFile -Force
}

# Create file:
Write-Verbose "Creating [$SCCMConfigFile]..." -Verbose
New-Item -Path $SCCMConfigFile -ItemType File -Value $SCCMConfigData | Out-Null

# Rename the old setup log file and create a new one if the file exist already
$SCCMSetupLogFile = "C:\ConfigMgrSetup.log"
if (Test-Path $SCCMSetupLogFile) {
    Rename-Item -Path $SCCMSetupLogFile -NewName "c:\ConfigMgrSetup-$($using:LogDateTime).log"
}

New-Item -Path "C:\ConfigMgrSetup.log" -ItemType File -Force | Out-Null

# start the SCCM installer if its not installed already in the system
if (!(Get-ChildItem "HKLM:\Software\Microsoft\SMS" -ErrorAction SilentlyContinue)) {
Write-Verbose "Starting Installation of SCCM..." -Verbose
$SCCMSetupFile = "$SCCMSource\SMSSETUP\bin\X64\Setup.exe"
$SccmArgumentList = "/script $SCCMConfigFile"
Try
{
    $StartTime = Get-Date
    Start-Process $SCCMSetupFile -ArgumentList $SccmArgumentList -Wait -NoNewWindow
}
catch
{
    Write-Error "Someting went wrong. Exiting!"
    break
}
    Start-Sleep -Seconds 30
    Write-Verbose "Setup of SCCM completed." -Verbose
    $EndTime = Get-Date
    $ResultTime = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host "Time duration for SCCM Installation:"
    $ResultTime | Format-Table -Property Hours,Minutes,Seconds | Out-Host
}
}

######################################################################################################
######################################################################################################
#### SCCM Configuration

# Importing the Module
Write-Verbose "Importing the SCCM Module..." -Verbose
if (!($Null -eq $env:SMS_ADMIN_UI_PATH)) {
    Import-Module $env:SMS_ADMIN_UI_PATH\..\ConfigurationManager.psd1
} else {
    Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
}

$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$LDAPString = "LDAP://$DomainDistinguishedName"

# If the Site Drive does not exist in the shell, Create one
$IsSiteDriveExist = Get-PSDrive -Name $SiteCode -PSProvider "CMSite" -ErrorAction SilentlyContinue
if ($IsSiteDriveExist) {
    Set-Location "$($SiteCode):\"
} else {
    New-PSDrive -Name $SiteCode -PSProvider "CMSite" -Root $DNSHostName | Out-Null
    Start-Sleep -Seconds 1
    Set-Location "$($SiteCode):\"
    Start-Sleep -Seconds 1
}

# Enable Active Directory System Discovery
Write-Verbose "Enabling Active Directory System Discovery..." -Verbose
Set-CMDiscoveryMethod `
-ActiveDirectorySystemDiscovery `
-SiteCode $SiteCode `
-Enabled $True `
-AddActiveDirectoryContainer $LDAPString `
-EnableIncludeGroups $True `
-EnableDeltaDiscovery $true `
-DeltaDiscoveryMins 5

# CM Boundry & Boundry Groups
Write-Verbose "Creating New CM Boundry Group..." -Verbose
$BoundaryGroupName = "$SiteCode-BG"
if (!(Get-CMBoundaryGroup -Name $BoundaryGroupName)) { 
    New-CMBoundaryGroup -Name $BoundaryGroupName
}

# Selecting the first 3 part of the ip-address (Network-Address)
$NetworkAddress = $VM.IPAddress.Split(".")[0,1,2]
$tempAddress = $null
foreach ($octet in $NetworkAddress) {
    $tempAddress += $octet + "."
}
$NetworkAddress = $tempAddress

Write-Verbose "Creating New CM Boundry..." -Verbose
if (!(Get-CMBoundary -Name $SiteCode)) { 
    New-CMBoundary -Name $SiteCode -Type IPSubnet -Value "$($NetworkAddress)0/24"
}

Write-Verbose "Adding the CM Boundry to the CM Boundry Group..."
Add-CMBoundaryToGroup -BoundaryGroupName $BoundaryGroupName -BoundaryName $SiteCode

# Install Client Application on sitewide Machines incl. Domain Controllers
Write-Verbose "Enable Client Application Installation on Sitewide Machines..." -Verbose
Set-CMClientPushInstallation `
-SiteCode $SiteCode `
-EnableAutomaticClientPushInstallation $true `
-EnableSystemTypeConfigurationManager $true `
-InstallClientToDomainController $true


if ((Get-CMClientPushInstallation).PropLists.Values -ne (whoami.exe)) {
    Set-CMClientPushInstallation -SiteCode $SiteCode -AddAccount (whoami.exe)
}

# Adding the Site System Server to the Boundary group
$SiteSystemServer = Get-CMSiteSystemServer
Set-CMBoundaryGroup -Name $BoundaryGroupName -AddSiteSystemServer $SiteSystemServer

# Start the Active Directory System Disovery, to find Devices
Invoke-CMSystemDiscovery -Site $SiteCode
Start-Sleep -Seconds 1

$i = 0
do {
    $CMDevies = Get-CMDevice | Where-Object {$_.AdSiteName -eq "Default-First-Site-Name"}
    Start-Sleep -Seconds 2
    $i++
} while (
    # Run the loop if the Device count is 0 for 3 times maximum
    ($i -lt 3) -xor ($CMDevies.Count -gt 0)
)

# If Devices found, check if the installation has been done, for the vm without installatio or with error code other than 0
if ($CMDevies.Count -gt 0) {
    $DeviceWithoutClient = $CMDevies | Where-Object {$_.LastInstallationError -ne 0}
}

# If value is not 0 run this code, meaning if its not empty
if ($DeviceWithoutClient.Count -gt 0) {
    # Install the Client Application on the founded devices
    $DeviceWithoutClient | ForEach-Object { 
    Install-CMClient -IncludeDomainController $True -AlwaysInstallClient $True -InputObject $_ -SiteCode $SiteCode -Verbose
    }
}


######################################################################################################
######################################################################################################
#### SCCM Application Deployment

# Create New Folder and Share the folder for the applications source
$SCCMAppSourceFolder = "sccm-applications"
$SCCMAppSourceFolderPath = "c:\sccm-applications"
if (!(test-path $SCCMAppSourceFolderPath -ErrorAction SilentlyContinue)) {
    New-Item -Name $SCCMAppSourceFolder -Path "c:\" -ItemType Directory | Out-Null

    $DomainAdmins = "$DomainNetBiosName\Domain Admins"
    $DomainUsers = "$DomainNetBiosName\Domain Users"

    # Disabling The inheritance
    $ACL = Get-Acl -Path $SCCMAppSourceFolderPath
    $isProtected = $true
    $PreserveInheritance = $true
    $ACL.SetAccessRuleProtection($isProtected,$PreserveInheritance)
    Set-Acl -Path $SCCMAppSourceFolderPath -AclObject $ACL

    # Removing the builtin Users from the folder
    $ACL = Get-Acl -Path $SCCMAppSourceFolderPath
    $ACL.Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users"} | ForEach-Object { $ACL.RemoveAccessRuleSpecific($_) }
    Set-Acl $SCCMAppSourceFolderPath $ACL

    # Grant Permission to the Domain Users, in this  case only ReadAndExecute
    # The permission is applied to this folder/object and sub subfolders
    $rights = "ReadAndExecute,Synchronize" #Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
    $inheritance = "ContainerInherit, ObjectInherit"#'ContainerInherit, ObjectInherit' #Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
    $propagation = "None" #Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
    $type = "allow" #Other options: [enum]::GetValues('System.Security.AccessControl.AccessControlType')
    $ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($DomainUsers,$rights,$inheritance,$propagation,$type)
    $Acl = Get-Acl -Path $SCCMAppSourceFolderPath
    $Acl.AddAccessRule($ACE)
    Set-Acl -Path $SCCMAppSourceFolderPath -AclObject $Acl

    # Grant Permission to the Domain Admins, in this  case only FullControl
    # The permission is applied to this folder/object and sub subfolders
    $rights = "FullControl" #Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
    $inheritance = "ContainerInherit, ObjectInherit"#'ContainerInherit, ObjectInherit' #Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
    $propagation = "None" #Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
    $type = "allow" #Other options: [enum]::GetValues('System.Security.AccessControl.AccessControlType')
    $ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($DomainAdmins,$rights,$inheritance,$propagation,$type)
    $Acl = Get-Acl -Path $SCCMAppSourceFolderPath
    $Acl.AddAccessRule($ACE)
    Set-Acl -Path $SCCMAppSourceFolderPath -AclObject $Acl

    if (!(Get-SmbShare -Name $SCCMAppSourceFolder -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $SCCMAppSourceFolder -Path $SCCMAppSourceFolderPath `
        -FolderEnumerationMode AccessBased -FullAccess "Everyone"
    } else { write-host -ForegroundColor Yellow "$SCCMAppSourceFolder folder is shared already!" }
}

$AppDeploymentConfirmation = Read-Host "Do you want to deploy [.msi] applications? (Y/N)"
if ($AppDeploymentConfirmation -notlike "y") {
    Write-Host "No confirmation received. Skipping Application Deployment"
} else {

Write-Host "Enter the .msi File in [$SCCMAppSourceFolderPath]. Press Enter to continue" -ForegroundColor Red
Pause
### Deploying and Installing the applications

$MSIAppsInFolder = Get-ChildItem -Path $SCCMAppSourceFolderPath -File | Where-Object {$_.Extension -like ".msi"}

# Getting all the .msi application in a the folder as a hashtable
$AppsToDeploy = @{}
$MSIAppsInFolder | ForEach-Object {
    $AppsToDeploy.Add($_.BaseName,$_.Name)
}


$DistributionPointName = (Get-CMDistributionPoint).NetworkOSPath.trimstart("\\")

# Run this only if the hashtable is not emply, meaning there are .msi application in the folder
if ($AppsToDeploy.Count -ne 0) {

$AppsToDeploy.GetEnumerator() | ForEach-Object {
    
    # create the application and allow the it to be installed in a task
    New-CMApplication -Name $_.Key -AutoInstall $true
    
    # Add the MSI deployment type to the application, selecting the source path (msi file)
    Add-CMMsiDeploymentType -ApplicationName $_.Key `
    -ContentLocation "\\$env:COMPUTERNAME\$SCCMAppSourceFolder\$($_.Value)" `
    -InstallationBehaviorType InstallForSystem -ForceForUnknownPublisher
    
    # Distribute the content to the Distribution Point group
    Start-CMContentDistribution -ApplicationName $_.Key -DistributionPointName $DistributionPointName -Verbose
    
    # Deploy the application to the collection make this available in software center immediately
    New-CMApplicationDeployment -CollectionName "All Desktop and Server Clients" -Name $_.Key `
    -DeployAction Install -DeployPurpose Required -UserNotification DisplayAll -AvailableDateTime (get-date) -TimeBaseOn LocalTime -Verbose
    }
}

}
}

Invoke-Script -ScriptItem ItSelf
exit
}

    # Quick the program
"Q" { exit }

    # Go back to Main Menu
"B" { Invoke-Script -ScriptItem Main -PauseBefore $false }

Default { Write-Host "Wrong Selection!" -ForegroundColor Red; Invoke-Script -ScriptItem ItSelf }

}