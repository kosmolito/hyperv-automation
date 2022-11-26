. .\variables.ps1
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
       while ((Invoke-Command -VMName $PreviousVM.VMName -Credential $PreviousVMDomainCredential { ((Resolve-DnsName -Name $using:PreviousVM.VMName[0].Name)) } -ea SilentlyContinue) -notlike $PreviousVM.VMName + "." + $PreviousVMDomainName ) {Start-Sleep -Seconds 10}
       Start-Sleep -Seconds 10
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

        Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose
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
            
                        try
                        {
                            Get-ADComputer -filter *
                        }
                        catch
                        {
                            Write-Host "Waiting for Root DC to be Ready..." -ForegroundColor Yellow
                            while (!($RootDCReady)) {
                                $RootDCReady = (Resolve-DnsName $($VM.DomainName) -ErrorAction SilentlyContinue ).Name
                                start-sleep -Seconds 60
                                }
                            # Start-Sleep -Seconds 60
                            Write-Host "Root DC Ready." -ForegroundColor Yellow

                            
            
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

                            # Add-DhcpServerInDC -DnsName "$($VM.DomainName)" -IPAddress "$($VM.IPAddress)"
                
                            # Add DNS Server, Router Gateway Options in DHCP
                            Set-DhcpServerV4OptionValue -DnsServer "$($VM.IPAddress)" -Router "$($NetworkAddress)1"

                            # Set Up Lease Duration
                            Set-DhcpServerv4Scope -ScopeId "$($VM.IPAddress)" -LeaseDuration 1.00:00:00

                            # Set Up Dns Domain information
                            Set-DhcpServerv4OptionValue -DnsDomain "$($VM.DomainName)" -DnsServer "$($VM.IPAddress)"

                            # Restart DHCP Service
                            Restart-service dhcpserver
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
    }
    $VMListIndex++
}