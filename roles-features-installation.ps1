. .\variables.ps1
foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {


    if (((get-vm $VM.VMName).State) -like "Off") {
        Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $VM.VMName
    }

    $Roles = $VM.Roles

    foreach ($Role in $Roles) {

        $DomainName = $VM.DomainName
        $DomainNetbiosName = $DomainName.split(".")[0].ToUpper()

        if ($VM.MachineType -like "server") {
            if (($VM.HasJoinedDomain)) {
                $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential `
                -ArgumentList $DomainNetbiosName\$DomainAdmin, $DomainPwd

                $Credential = $DomainCredential
            } else {
                $Credential = $ServerLocalCredential
            }
        }

        Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
            Set-Content function:Install-FeaturesAndRoles -Value $using:InstallFeaturesAndRoles
            Write-Host -ForegroundColor green $using:Role
            # $VMList = $using:VMList
            $VM = $using:VM
            $DomainName = $using:DomainName
            $DomainNetbiosName = $using:DomainNetbiosName
            $ForestRecoveryPwd = $using:ForestRecoveryPwd

            if ($VM.Roles -notcontains "AD-DC-ROOT") {
                $ParentDomainName = $VM.DCConfig.ParentDomainName
                $ParentDomainNetbiosName = $ParentDomainName.split(".")[0]
                $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential `
                -ArgumentList $ParentDomainNetbiosName\$using:DomainAdmin, $using:DomainPwd
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
                            Write-Verbose "Configuring New Domain with Name [$DomainName] on VM [$($VM.VMName)]" -Verbose
            
                            Import-Module ADDSDeployment
                            Install-ADDSDomainController `
                            -NoGlobalCatalog:$false `
                            -CreateDnsDelegation:$false `
                            -Credential $DomainCredential `
                            -CriticalReplicationOnly:$false `
                            -DatabasePath "C:\Windows\NTDS" `
                            -DomainName $VM.DomainName `
                            -InstallDns:$true `
                            -LogPath "C:\Windows\NTDS" `
                            -NoRebootOnCompletion:$false `
                            -ReplicationSourceDC $VM.DCConfig.ReplicationSourceDC `
                            -SiteName "Default-First-Site-Name" `
                            -SysvolPath "C:\Windows\SYSVOL" `
                            -SafeModeAdministratorPassword $ForestRecoveryPwd `
                            -Force:$true
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
            
                            (Get-ADComputer -Filter * | Where-Object {$_.Name -like $($VM.VMName)}).DnsHostName
            
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
                            Set-DhcpServerv4OptionValue -DnsDomain (Get-ADComputer -filter *).DNSHostName -DnsServer $VM.IPAddress
                        }
            
                        catch {
                            Write-Verbose "Active Directory Role could not be found!" -Verbose
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
}