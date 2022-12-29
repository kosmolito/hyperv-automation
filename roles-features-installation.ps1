. .\variables.ps1
Get-ElevatedInfo
$VMListIndex = 0
$VMSelected = $VMList | Where-Object {$_.isSelected -eq $true}
foreach ($VM in $VMSelected) {

    if (((get-vm $VM.VMName).State) -like "Off") {
        Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $VM.VMName
    }

    # If the previous VM was a Root DC, wait until the Root DC gets ready
    $PreviousVM = $VMSelected[($VMListIndex - 1)]
    if (($VMListIndex -gt 0) -and ( $PreviousVM.Roles -Match "AD-DC-ROOT")) {
       
       $PreviousVMDomainName = $PreviousVM.DomainName
    #    $PreviousVMDomainNetbiosName = $PreviousVMDomainName.split(".")[0].ToUpper()
       $PreviousVMDomainCredential = New-Object -TypeName System.Management.Automation.PSCredential `
       -ArgumentList $PreviousVMDomainName\$DomainAdmin, $DomainPwd

       Start-Sleep -Seconds 60
       Write-Host "waiting for Root DC to be completed" -ForegroundColor Yellow
       while ((Invoke-Command -VMName $PreviousVM.VMName -Credential $PreviousVMDomainCredential { ((Resolve-DnsName -Name $using:PreviousVM.VMName[0].Name)) } -ea SilentlyContinue) -notlike $PreviousVM.VMName + "." + $PreviousVMDomainName ) {Start-Sleep -Seconds 5}
       timeout /t 600
    }
   
    $Roles = $VM.Roles
    foreach ($Role in $Roles) {

        $DomainName = $VM.DomainName
        $DomainNetbiosName = $DomainName.split(".")[0].ToUpper()

        if ($VM.MachineType -like "server") {
            if (($VM.HasJoinedDomain)) {
                $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential `
                -ArgumentList $DomainName\$DomainAdmin, $DomainPwd

                $Credential = $DomainCredential
            } else {
                $Credential = $ServerLocalCredential
            }
        } else {
            $Credential = $ServerLocalCredential
        }

        if ($Role -like "SCCM") {

            if ((Get-VMHardDiskDrive -VMName $VM.VMName).Path -notcontains "$ConfigFolder\sccmusb.vhdx") {
                Add-VMHardDiskDrive -VMName $VM.VMName -Path "$ConfigFolder\sccmusb.vhdx"
            }

        }

        Invoke-VMConnectionConfirmation -VMName $VM.VMName -Credential $Credential
        Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
            # Set-Content function:Install-FeaturesAndRoles -Value $using:InstallFeaturesAndRoles
            Write-Host -ForegroundColor green $using:Role
            # $VMList = $using:VMList
            $VM = $using:VM
            $DomainName = $using:DomainName
            $DomainNetbiosName = $using:DomainNetbiosName
            $ForestRecoveryPwd = $using:ForestRecoveryPwd

            if ($VM.Roles -match "AD-DC") {
                if ($VM.Roles -notcontains "AD-DC-ROOT") {
                    $ParentDomainName = $VM.DCConfig.ParentDomainName
                    # $ParentDomainNetbiosName = $ParentDomainName.split(".")[0]
                    $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential `
                    -ArgumentList $ParentDomainName\$using:DomainAdmin, $using:DomainPwd
                } else { $DomainCredential = $using:DomainCredential }
            } else {
                $DomainCredential = $using:DomainCredential
            }

            function Install-FeaturesAndRoles {
                [CmdletBinding()]
                param($Role)
            
                switch ($Role) {
            
                    "AD-DC-ROOT" 
                    {
                        if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {               
                            Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
                            Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
                        }
            
                        try
                        {
                            Get-ADComputer -filter *
                        }
                        catch
                        {
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
            
                    "AD-DC-REPLICATION" 
                    {
            
                        if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {               
                            Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
                            Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
                        }

                        $DCPath = (Get-ADDomain).DistinguishedName
                        $isPromotedToDC = Get-ADObject -Filter 'Name -like $($VM.VMName)' -SearchBase "OU=Domain Controllers,$DCPath" -ErrorAction SilentlyContinue
                        if (!$isPromotedToDC) {
            
                            # if (((Get-ADDomainController -Filter *).name -notlike $VM.VMName)) {
                                Write-Verbose "Configuring New Domain with Name [$DomainName] on VM [$($VM.VMName)]" -Verbose

                                Import-Module ADDSDeployment
                                Install-ADDSDomainController `
                                -NoGlobalCatalog:$false `
                                -CreateDnsDelegation:$false `
                                -Credential $($using:DomainCredential) `
                                -CriticalReplicationOnly:$false `
                                -DatabasePath "C:\Windows\NTDS" `
                                -DomainName $($VM.DomainName) `
                                -InstallDns:$true `
                                -LogPath "C:\Windows\NTDS" `
                                -NoRebootOnCompletion:$false `
                                -SiteName "Default-First-Site-Name" `
                                -SysvolPath "C:\Windows\SYSVOL" `
                                -SafeModeAdministratorPassword $ForestRecoveryPwd `
                                -Force:$true
                        # }
                        }
                    }
            
                    "AD-DC-CHILD" 
                    {
                        if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {               
                            Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
                            Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
                        }
            
                        try {
                            Get-ADComputer -filter *
                        }
                        catch {
                            Write-Verbose "Configuring Child DC [$DomainName] under [$($VM.DCConfig.ParentDomainName)]  on VM [$($VM.VMName)]" -Verbose
                            
                            Import-Module ADDSDeployment
                            Install-ADDSDomain `
                            -NoGlobalCatalog:$false `
                            -CreateDnsDelegation:$true `
                            -Credential $DomainCredential `
                            -DatabasePath "C:\Windows\NTDS" `
                            -DomainMode "WinThreshold" `
                            -DomainType "ChildDomain" `
                            -InstallDns:$true `
                            -LogPath "C:\Windows\NTDS" `
                            -NewDomainName $VM.DCConfig.NewDomainName `
                            -NewDomainNetbiosName $VM.DCConfig.NewDomainNetbiosName `
                            -ParentDomainName $VM.DCConfig.ParentDomainName `
                            -NoRebootOnCompletion:$false `
                            -SiteName "Default-First-Site-Name" `
                            -SysvolPath "C:\Windows\SYSVOL" `
                            -SafeModeAdministratorPassword $ForestRecoveryPwd `
                            -Force:$true
                        }
                    }
            
                    "AD-DC-TREE" 
                    {
                        if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {               
                            Write-Verbose "Installing Active Directory Services on VM [$($VM.VMName)]" -Verbose
                            Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
                        }
            
                        try {
                            Get-ADComputer -filter *
                        }
                        catch {
                            Write-Verbose "Configuring Tree DC [$DomainName] under [$($VM.DCConfig.ParentDomainName)] on VM [$($VM.VMName)]" -Verbose
                            
                            Import-Module ADDSDeployment
                            Install-ADDSDomain `
                            -NoGlobalCatalog:$false `
                            -CreateDnsDelegation:$false `
                            -Credential $DomainCredential `
                            -DatabasePath "C:\Windows\NTDS" `
                            -DomainMode "WinThreshold" `
                            -DomainType "TreeDomain" `
                            -InstallDns:$true `
                            -LogPath "C:\Windows\NTDS" `
                            -NewDomainName $VM.DCConfig.NewDomainName `
                            -NewDomainNetbiosName $VM.DCConfig.NewDomainNetbiosName `
                            -ParentDomainName $VM.DCConfig.ParentDomainName `
                            -NoRebootOnCompletion:$false `
                            -SiteName "Default-First-Site-Name" `
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
                        
                        try {

                            # Add DHCP Scope
                            Add-DhcpServerv4Scope -name "staff_ipv4_scope" -StartRange "$($NetworkAddress)100" -EndRange "$($NetworkAddress)200" -SubnetMask 255.255.255.0 -State Active

                            Add-DhcpServerInDC -DnsName "$($VM.DomainName)" -IPAddress "$($VM.IPAddress)"
                
                            # Add DNS Server, Router Gateway Options in DHCP
                            Set-DhcpServerV4OptionValue -DnsServer "$($VM.IPAddress)" -Router "$($NetworkAddress)1"

                            # Set Up Lease Duration
                            Set-DhcpServerv4Scope -ScopeId "$($VM.IPAddress)" -LeaseDuration 1.00:00:00

                            # Set Up Dns Domain information
                            Set-DhcpServerv4OptionValue -DnsDomain "$($VM.DomainName)" -DnsServer "$($VM.IPAddress)"

                            # Restart DHCP Service
                            Restart-service dhcpserver

                            start-sleep -Seconds 5

                            # Post installation wizzard configuration
                            Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
                        }
            
                        catch {
                            Write-Error $Error[0]
                        }
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

                    "SCCM" 
                    {
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

                        If ($Container -eq $null) 
                        { 
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

                        Write-Verbose "Installing roles and features [IIS]..." -Verbose
                        Install-WindowsFeature -ConfigurationFilePath "$SourcePath\DeploymentConfigTemplate-IIS.xml"
                        Write-Verbose "[IIS] roles and features installation completed" -Verbose

                        ######################################################################################################
                        ######################################################################################################
                        #### Installing Windows 10 ADK

                        # # This installs Windows Deployment Service
                        # Write-Host "Installing Windows Deployment Services"  -nonewline
                        # Import-Module ServerManager
                        # Install-WindowsFeature -Name WDS -IncludeManagementTools
                        # Start-Sleep -s 10

                        # Install ADK Deployment Tools,  Windows Preinstallation Enviroment
                        Write-Verbose "Installing Windows ADK..." -Verbose
                        Start-Process -FilePath "$SourcePath\ADK\adksetup.exe" -Wait `
                        -ArgumentList "/Features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment OptionId.ImagingAndConfigurationDesigner OptionId.ICDConfigurationDesigner OptionId.UserStateMigrationTool /norestart /quiet /ceip off" -Verbose
                        Start-Sleep -s 120
                        Write-Verbose "Windows ADK installation completed." -Verbose

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
                        New-Item -Path $SQLConfiginiFile -ItemType File -Value $SQLConfigData

                        # Create firewall rule
                        if (!(get-netfirewallrule -DisplayName "SQL Server (TCP 1433) Inbound" -ErrorAction SilentlyContinue)){
                        Write-Verbose "Creating firewall rule for SQL Server..." -Verbose
                        New-NetFirewallRule -DisplayName "SQL Server (TCP 1433) Inbound" -Action Allow -Direction Inbound -LocalPort 1433 -Protocol TCP}

                        # start the SQL installer
                        Try
                        {
                        if (Test-Path $SQLsource){
                            Write-Verbose "SQL Server installation started..." -Verbose
                            $SQLSetupFile =  "$SQLsource\setup.exe"
                            & $SQLSetupFile  /CONFIGURATIONFILE=$SQLConfiginiFile
                            Write-Verbose "Installation of SQL Server completed." -Verbose
                        } else {
                            Write-Error "Could not find the media for SQL Server"
                            break
                        }
                        }
                        catch
                        {
                        write-Error "Something went wrong with the installation of SQL Server, aborting."
                        break
                        }

                        Pause
                        # Configure Firewall settings for SQL

                        Write-Verbose "Configuring SQL Server Firewall settings..." -Verbose

                        #Enable SQL Server Ports

                        New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound –Protocol TCP –LocalPort 1433 -Action allow
                        New-NetFirewallRule -DisplayName "SQL Admin Connection" -Direction Inbound –Protocol TCP –LocalPort 1434 -Action allow
                        New-NetFirewallRule -DisplayName "SQL Database Management" -Direction Inbound –Protocol UDP –LocalPort 1434 -Action allow
                        New-NetFirewallRule -DisplayName "SQL Service Broker" -Direction Inbound –Protocol TCP –LocalPort 4022 -Action allow
                        New-NetFirewallRule -DisplayName "SQL Debugger/RPC" -Direction Inbound –Protocol TCP –LocalPort 135 -Action allow

                        #Enable SQL Analysis Ports

                        New-NetFirewallRule -DisplayName "SQL Analysis Services" -Direction Inbound –Protocol TCP –LocalPort 2383 -Action allow
                        New-NetFirewallRule -DisplayName "SQL Browser" -Direction Inbound –Protocol TCP –LocalPort 2382 -Action allow

                        #Enabling related Applications

                        New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound –Protocol TCP –LocalPort 80 -Action allow
                        New-NetFirewallRule -DisplayName "SQL Server Browse Button Service" -Direction Inbound –Protocol UDP –LocalPort 1433 -Action allow
                        New-NetFirewallRule -DisplayName "SSL" -Direction Inbound –Protocol TCP –LocalPort 443 -Action allow

                        #Enable Windows Firewall
                        Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True

                        Write-Verbose "SQL Server Firewall Settings completed." -Verbose

                        ######################################################################################################
                        ######################################################################################################
                        #### Installing WSUS Feature

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

                        ######################################################################################################
                        ######################################################################################################
                        #### SCCM
                        
                        # Status if SCCM is already installed on the machine

                        $SCCMStatus = Get-CimInstance Win32_Service | Where-Object {$_.Name -eq "ccmexec"}

                        if (!($null -eq $SCCMStatus)) {
                            Write-Verbose "SCCM is already installed on the machine! Exiting!"
                            exit
                        } else {
                        # Change the account permissions of SQL services to the Domain Administrator
                        $SQLServices = "MSSQLSERVER","SQLSERVERAGENT"
                        foreach ($Item in $SQLServices) {
                            $Service = Get-WmiObject win32_service -Filter "Name='$Item'"
                            $Service.StopService()
                            $Service.Change($null,$null,$null,$null,$null,$null,$SQLSYSADMINACCOUNTS,$using:ServerPwdPlainText,$null,$null,$null)
                            $Service.StartService()
                        }

                        $SCCMSource="$SourcePath\MEM_Configmgr_2103"
                        
                        # start the SCCM installer
                        if (!(Test-Path $SCCMSource)){
                            Write-Error "Could not find the installtion media for SCCM! Exiting."
                            exit
                        } else {
                            Write-Verbose "Installation media for SCCM found." -Verbose
                        }

                        $DNSHostName = (Get-ADComputer -Identity $env:COMPUTERNAME).DNSHostName
                        # define your SCCM Current Branch variables here
                        $Action="InstallPrimarySite"
                        $ProductID="EVAL"
                        $SiteCode="GBG"
                        $Sitename="Goteborg"
                        $SMSInstallDir="C:\Program Files\Microsoft Configuration Manager"
                        $SDKServer=$DNSHostName
                        $RoleCommunicationProtocol="HTTPorHTTPS"
                        $ClientsUsePKICertificate="0"
                        $PrerequisiteComp="1"
                        $PrerequisitePath="$SourcePath\sccm"
                        $ManagementPoint=$DNSHostName
                        $ManagementPointProtocol="HTTP"
                        $DistributionPoint=$DNSHostName
                        $DistributionPointProtocol="HTTP"
                        $DistributionPointInstallIIS="0"
                        $AdminConsole="1"
                        $JoinCEIP="0"
                        $SQLServerName=$DNSHostName
                        $DatabaseName="CM_GBG"
                        $SQLSSBPort="4022"
                        $CloudConnector="1"
                        $CloudConnectorServer=$DNSHostName
                        $UseProxy="0"
                        $ProxyName=""
                        $ProxyPort=""
                        $SysCenterId=""

                        # do not edit below this line

                        $conffile= @"
                        [Identification]
                        Action="$Action"

                        [Options]
                        ProductID="$ProductID"
                        SiteCode="$SiteCode"
                        SiteName="$Sitename"
                        SMSInstallDir="$SMSInstallDir"
                        SDKServer="$SDKServer"
                        RoleCommunicationProtocol="$RoleCommunicationProtocol"
                        ClientsUsePKICertificate="$ClientsUsePKICertificate"
                        PrerequisiteComp="$PrerequisiteComp"
                        PrerequisitePath="$PrerequisitePath"
                        ManagementPoint="$ManagementPoint"
                        ManagementPointProtocol="$ManagementPointProtocol"
                        DistributionPoint="$DistributionPoint"
                        DistributionPointProtocol="$DistributionPointProtocol"
                        DistributionPointInstallIIS="$DistributionPointInstallIIS"
                        AdminConsole="$AdminConsole"
                        JoinCEIP="$JoinCEIP"

                        [SQLConfigOptions]
                        SQLServerName="$SQLServerName"
                        DatabaseName="$DatabaseName"
                        SQLSSBPort="$SQLSSBPort"

                        [CloudConnectorOptions]
                        CloudConnector="$CloudConnector"
                        CloudConnectorServer="$CloudConnectorServer"
                        UseProxy="$UseProxy"
                        ProxyName="$ProxyName"
                        ProxyPort="$ProxyPort"

                        [SystemCenterOptions]
                        SysCenterId="$SysCenterId"

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

                        # start the SCCM installer
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
                        Write-Verbose "Setup of SCCM completed." -Verbose
                        }
                    }

                    default { write-host -ForegroundColor red "Not Finding any valid Roles or Features!" }
                }
            
            }
            

            Install-FeaturesAndRoles -Role $using:Role

        }
        
        if ($Role -match "AD-DC-*" -and $VM.HasJoinedDomain -eq $False) {
            $VM.HasJoinedDomain = $true
            $VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
            $VMList = Get-Content -Path "$ConfigFolder\inventory.json" | ConvertFrom-Json
            Start-Sleep -Seconds 2
        }
        start-sleep -Seconds 5
    }
    $VMListIndex++
}