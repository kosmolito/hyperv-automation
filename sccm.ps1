. .\Variables.ps1

$VM = $VMList | Where-Object {$_.isSelected -eq $true}

if ($VM.Count -ne 1) {
    Write-Error "Only 1 VM can be selected! Exiting"
    exit
}

$DomainName = $VM.DomainName
$DomainNetbiosName = $DomainName.split(".")[0].ToUpper()

If ($VM.MachineType -notlike "server") {
    Write-Error "Only [server] types of machines are allowed! Exiting"
    Exit
}

if (($VM.HasJoinedDomain)) {
    Write-Error "The VM is NOT joined any Domain, Please join the VM before continue!"
    Exit
}


$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainName\$DomainAdmin,$DomainPwd

if ($VM.Role -like "SCCM") {
    if ((Get-VMHardDiskDrive -VMName $VM.VMName).Path -notcontains "$ConfigFolder\sccmusb.vhdx") {
        Write-Verbose "Attaching the SCCM .vhdx file containing the installation files.."
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

# Make the SCCM offline VHD Disk online
Get-Disk | Where-Object {$_.OperationalStatus -like "Offline"} | Set-Disk -IsOffline $False
$SourcePath = ((Get-Volume -FriendlyName "sccmusb").DriveLetter + ":")

######################################################################################################
######################################################################################################
#### Installing AD Feature

if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {               
    Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}

######################################################################################################
######################################################################################################
#### Creating System Management Container and set the permissions

Import-Module ADDSDeployment
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

Write-Verbose "Extend the Active Directory Schema..." -Verbose
# Extend the Active Directroy Schema
& "$SourcePath\MEM_Configmgr_2103\SMSSETUP\BIN\X64\extadsch.exe"
Start-Sleep -Seconds 10

######################################################################################################
######################################################################################################
#### Installing IIS Roles and Features, based on the XML file


if (!((Get-WindowsFeature -Name Web-Server).InstallState -eq "Installed")) {
    Write-Verbose "Installing roles and features [IIS]..." -Verbose
    Install-WindowsFeature -ConfigurationFilePath "$SourcePath\DeploymentConfigTemplate-IIS.xml"
    Write-Verbose "[IIS] roles and features installation completed" -Verbose
} else {
    Write-Verbose "[IIS] roles and features are installed already!" -Verbose
}

######################################################################################################
######################################################################################################
#### Installing Windows 10 ADK

# Install ADK Deployment Tools,  Windows Preinstallation Enviroment
if (!(Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit' -ErrorAction SilentlyContinue)) {
Write-Verbose "Installing Windows ADK..." -Verbose
Start-Process -FilePath "$SourcePath\ADK\adksetup.exe" -Wait `
-ArgumentList "/Features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment OptionId.ImagingAndConfigurationDesigner OptionId.ICDConfigurationDesigner OptionId.UserStateMigrationTool /norestart /quiet /ceip off" -Verbose
Start-Sleep -s 120
Write-Verbose "Windows ADK installation completed." -Verbose
} else {
    Write-Verbose "Windows ADK is installed already! Skipping the installation." -Verbose
}

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
                        
$SQLConfiginiFile="c:\SQLConfigurationFile.ini"

if (Test-Path $SQLConfiginiFile){
    Write-Verbose "Found an old Configuration file [$($SQLConfiginiFile)], removing the file..." -Verbose
    Remove-Item -Path $SQLConfiginiFile -Force
}

Write-Verbose "Creating a New Configuration file [$($SQLConfiginiFile)]..." -Verbose
New-Item -Path $SQLConfiginiFile -ItemType File -Value $SQLConfigData | Out-Null


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

# start the SQL installer if its not installed already
if (!(Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server" -ErrorAction SilentlyContinue)) {
Try
{
    if (Test-Path $SQLsource){
        Write-Verbose "Microsoft SQL Server installation started..." -Verbose
        $SQLSetupFile =  "$SQLsource\setup.exe"
        & $SQLSetupFile  /CONFIGURATIONFILE=$SQLConfiginiFile
        Write-Verbose "Installation of SQL Server completed." -Verbose
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
} else {
    Write-Verbose "Microsoft SQL Server is installed already!" -Verbose
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
Install-WindowsFeature -ConfigurationFilePath "$SourcePath\DeploymentConfigTemplate-WSUS.xml"
Start-Sleep -s 10
& "C:\Program Files\Update Services\Tools\WsusUtil.exe" postinstall SQL_INSTANCE_NAME=$ServerName CONTENT_DIR=$WSUSFolder | out-file Null
Write-Verbose "Installation of WSUS roles and features completed." -Verbose
} else {
    Write-Verbose "WSUS roles and features is installed already." -Verbose
}

######################################################################################################
######################################################################################################
#### SCCM

# Status if SCCM is already installed on the machine

$SCCMStatus = Get-CimInstance Win32_Service | Where-Object {$_.Name -eq "ccmexec"}
$SiteCode = "GBG"
$SiteName = "Goteborg"
if (!($null -eq $SCCMStatus)) {
    Write-Verbose "SCCM is already installed on the machine!" -Verbose
} else {
# Change the account permissions of SQL services to the Domain Administrator
$SQLServices = "MSSQLSERVER","SQLSERVERAGENT"
Write-Verbose "Changing Account Permission of SQL Services and starting..." -Verbose
foreach ($Item in $SQLServices) {
    $Service = Get-WmiObject win32_service -Filter "Name='$Item'"
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
Write-Verbose "SQL Services Permission & Status OK." -Verbose


$SCCMSource="$SourcePath\MEM_Configmgr_2103"

# start the SCCM installer
if (!(Test-Path $SCCMSource)){
    Write-Error "Could not find the installtion media for SCCM! Exiting."
    exit
} else {
    Write-Verbose "Installation media for SCCM found." -Verbose
}

$DNSHostName = (Get-ADComputer -Identity $env:COMPUTERNAME).DNSHostName

# define SCCM Current Branch variables
$SiteCode = "GBG"
$SiteName = "Goteborg"

$conffile= @"
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
New-Item -Path $SCCMConfigFile -ItemType File -Value $Conffile | Out-Null

$SCCMSetupLogFile = "C:\ConfigMgrSetup.log"
if (Test-Path $SCCMSetupLogFile) {
    Rename-Item -Path $SCCMSetupLogFile -NewName "c:\ConfigMgrSetup-$($using:LogDateTime).log"
}

# Opening the logs to see the setup process
New-Item -Path "C:\ConfigMgrSetup.log" -ItemType File -Force | Out-Null
& "$SCCMSource\SMSSETUP\TOOLS\CMTrace.exe" /"ConfigMgrSetup.log"

# start the SCCM installer if its not installed already in the system
if (!(Get-ChildItem "HKLM:\Software\Microsoft\SMS" -ErrorAction SilentlyContinue)) {
Write-Verbose "Starting Installation of SCCM..." -Verbose
$SCCMSetupFile = "$SCCMSource\SMSSETUP\bin\X64\Setup.exe"
$Parms = "  /script $SCCMConfigFile"
$Prms = $Parms.Split(" ")
Try
{
    & "$SCCMSetupFile" $Prms | Out-Null
}
catch
{
    Write-Error "Someting went wrong. Exiting!"
break
}
    Start-Sleep -Seconds 30
    Write-Verbose "Setup of SCCM completed." -Verbose
}
}

# Importing the Module
Write-Verbose "Importing the SCCM Module..." -Verbose
    Import-Module $env:SMS_ADMIN_UI_PATH\..\ConfigurationManager.psd1

#### Enable Active Directory System Discovery ####
Write-Verbose "Enabling Active Directory System Discovery..." -Verbose
$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$LDAPString = "LDAP://$DomainDistinguishedName"

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
-InstallClientToDomainController $true


if ((Get-CMClientPushInstallation).PropLists.Values -ne (whoami.exe)) {
    Set-CMClientPushInstallation -SiteCode $SiteCode -AddAccount (whoami.exe)
}

# Adding the Site System Server to the Boundary group
$SiteSystemServer = Get-CMSiteSystemServer
Set-CMBoundaryGroup -Name $BoundaryGroupName -AddSiteSystemServer $SiteSystemServer


# Create New Folder and Share the folder for the applications source
$SCCMAppSourceFolder = "sccm-applications"
$SCCMAppSourceFolderPath = "c:\sccm-applications"
if (!(test-path $SCCMAppSourceFolderPath -ErrorAction SilentlyContinue)) {
    New-Item -Name "sccm-applications" -Path "c:\" -ItemType Directory | Out-Null
}


if (!(Get-SmbShare -Name $SCCMAppSourceFolder -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $SCCMAppSourceFolder -Path $SCCMAppSourceFolderPath `
    -FolderEnumerationMode AccessBased -FullAccess "Everyone"
} else { write-host -ForegroundColor Yellow "$SCCMAppSourceFolder folder is shared already!" }



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

# Grant Permission to the Domain Users, in this  case only ReadAndExecute
# The permission is applied to this folder/object and sub subfolders
$rights = "FullControl" #Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
$inheritance = "ContainerInherit, ObjectInherit"#'ContainerInherit, ObjectInherit' #Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
$propagation = "None" #Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
$type = "allow" #Other options: [enum]::GetValues('System.Security.AccessControl.AccessControlType')
$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($DomainAdmins,$rights,$inheritance,$propagation,$type)
$Acl = Get-Acl -Path $SCCMAppSourceFolderPath
$Acl.AddAccessRule($ACE)
Set-Acl -Path $SCCMAppSourceFolderPath -AclObject $Acl

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
    Add-CMMsiDeploymentType -ApplicationName $_.Key -ContentLocation "\\$env:COMPUTERNAME\$SCCMAppSourceFolder\$($_.Value)" -InstallationBehaviorType InstallForSystem
    
    # Distribute the content to the Distribution Point group
    Start-CMContentDistribution -ApplicationName $_.Key -DistributionPointName $DistributionPointName -Verbose
    
    # Deploy the application to the collection make this available in software center immediately
    New-CMApplicationDeployment -CollectionName "All Desktop and Server Clients" -Name $_.Key `
    -DeployAction Install -DeployPurpose Required -UserNotification DisplayAll -AvailableDateTime (get-date) -TimeBaseOn LocalTime -Verbose
    }
}

}
