. .\Variables.ps1
Clear-Host
$VM = $VMList | Where-Object {$_.isSelected -eq $true -and $_.Roles -contains "Exchange"}

if ($VM.HasJoinedDomain -eq $false) {
    $Credential = $ServerLocalCredential
} else {
    $Credential = $DomainCredential
}

function Show-Menu {
    param (
        [String]$Title = "Microsoft Exchange 2019 Deployment"
    )
    Clear-Host
    Write-Host -ForegroundColor red "VM Selected"
    $VM | Format-table -Property VMName,DomainName,IPAddress
    Write-Host "================ $Title ================`n"
    Write-Host "  1: Copy over the required files from localhost to [$($VM.VMName)]" -ForegroundColor Green
    Write-Host "  2: Install Microsoft Exchange 2019" -ForegroundColor Green
    Write-Host "  B: Back to Main Menu" -ForegroundColor Green
    Write-Host "  Q: To quit" -ForegroundColor Green
}

Show-Menu
$Selection = Read-Host "Select an option from menu"

switch ($Selection) {

    # Attach necessary files to VM
    "1" 
    {
        if ((Get-VM -VMName $VM.VMName).State -ne "Running") {
            Write-Verbose "Starting [$($VM.VMName)]..." -Verbose
            Start-VM -VMName $VM.VMName
            Start-Sleep -Seconds 2
        }

        Invoke-VMConnectionConfirmation -VMName $VM.VMName -Credential $Credential
        Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $VM.VMName

        $PreReqFiles = Get-ChildItem -Path "$($ConfigFolder)\exchange2019\exchange-prereq"
        foreach ($File in $PreReqFiles) {
            Write-Verbose "Copying [$($File.Name)] to [$($VM.VMName)]..." -Verbose
            Copy-VMFile -Name $VM.VMName -SourcePath $File.FullName -DestinationPath "C:\exchange-prereq\$($File.Name)" -CreateFullPath -FileSource Host -Force
            Write-Verbose "Filed copied successfully." -Verbose
        }

        $Exchange2019ISO = "$($ConfigFolder)\exchange2019\ExchangeServer2019.ISO"
        if ((Get-VMDvdDrive -VMName $VM.VMName).Path -notcontains $Exchange2019ISO) {
            Write-Verbose "Mounting Exchange 2019 ISO to [$($VM.VMName)]..." -Verbose
            Add-VMDvdDrive -VMName $VM.VMName -Path $Exchange2019ISO
        } else {
            Write-Verbose "Exchange 2019 ISO is already mounted on [$($VM.VMName)]." -Verbose
        }
        Invoke-Script -ScriptItem ItSelf
    }

    "2" 
    {  

        if ($VM.HasJoinedDomain -eq $false) {
            Write-Warning "[$($VM.VMName)] is not joined to the domain."
            $Answer = Read-Host "$($VM.VMName) is not joined to the domain. Do you want to join [$($VM.VMName)] to the domain [$($VM.DomainName)]? (y/n)"
            if ($Answer -like "y") {
                & .\join-domain.ps1
            } else {
                Write-Host "Skipping $($VM.Name)"
                Invoke-Script -ScriptItem Main
            }
        }
        
        if ((Get-VM -VMName $VM.VMName).State -ne "Running") {
            Write-Verbose "Starting [$($VM.VMName)]..." -Verbose
            Start-VM -VMName $VM.VMName
            Start-Sleep -Seconds 2
        }        
        
        Invoke-VMConnectionConfirmation -VMName $VM.VMName -Credential $Credential
        $RestartNeeded = Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
        
            $VM = $using:VM
            $LogFolder = "$($env:USERPROFILE)\Desktop\logs"
            if (!(Test-Path $LogFolder)) {
                New-Item -ItemType Directory -Path $LogFolder | Out-Null
            }
            $ExchangePreReqFolder = "C:\exchange-prereq"

            ########################################
            ############## DOTNET 4.8 ##############
        
            # Check if dotnet 4.8 is installed, 528040 is the build number for dotnet 4.8
            $IsDotNet48Installed = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 528040
        
            if (!($IsDotNet48Installed)) {
                Write-Verbose "Installing Dotnet 4.8..." -Verbose
                $LogFile = "$($LogFolder)\DotNET48-Install"
                Start-Process "$($ExchangePreReqFolder)\ndp48.exe" -ArgumentList "/install /quiet /norestart /log $($LogFile)" -NoNewWindow -Wait
                Start-Sleep -Seconds 5
                write-verbose "Dotnet 4.8 installed successfully" -Verbose
            } else {
                write-verbose "Dotnet 4.8 or newer version is already installed" -Verbose 
            }
        
            if ($VM.isCore) {
                $RequiredFeatures = Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering,
                RSAT-Clustering-CmdInterface, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth,
                Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing,
                Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server,
                Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, RSAT-ADDS
                $RequiredFeatures
            } else {
                $RequiredFeatures = Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy,
                RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell,
                WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing,
                Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext,
                Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45,
                Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI,
                Windows-Identity-Foundation, RSAT-ADDS
                $RequiredFeatures
            }
            if ($RequiredFeatures.RestartNeeded -like "yes") {
                Restart-Computer -Force
            }
        
            # Return the value of $RequiredFeatures.RestartNeeded to the parent scriptblock:
            return $RequiredFeatures.RestartNeeded
        }
        
        
        # Wait for the server to restart if required:
        if ($RestartNeeded.Value -like "yes") {
            Write-Verbose "Waiting for the server to restart..."
            Start-Sleep -Seconds 15
        } else {
            Start-Sleep -Seconds 2
        }
        
        
        Invoke-VMConnectionConfirmation -VMName $VM.VMName -Credential $DomainCredential
        Invoke-Command -VMName $VM.VMName -Credential $DomainCredential -ScriptBlock {
        
            $VM = $using:VM
            $DCNetBIOSName = $VM.DomainName.Split(".")[0].ToUpper()
            $LogFolder = "$($env:USERPROFILE)\Desktop\logs"
            if (!(Test-Path $LogFolder)) {
                New-Item -ItemType Directory -Path $LogFolder | Out-Null
            }
            $ExchangePreReqFolder = "C:\exchange-prereq"
        
            # Get the Hard Drive for the Exchange Installation, which is not initialized, partitioned or formatted, 
            # then initialize it, partition it and format it if it is not already initialized, partitioned or formatted:
        
            $VolumeName = "ExchDrive"
            if ((Get-Volume).FileSystemLabel -notcontains $VolumeName) {
                Write-Verbose "Initializing, partitioning and formatting the hard drive for Exchange Installation..." -Verbose
                $ExchHDD = Get-Disk | Where-Object {$_.PartitionStyle -like "RAW"}
                $ExchHDD | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel $VolumeName | Out-Null
            }
            
            # Drive Letter for where the Exchange will be installed
            $ExchDriveLetter = (Get-Volume | Where-Object {$_.FileSystemLabel -like $VolumeName}).DriveLetter
            $ExchangeFolder = "$($ExchDriveLetter):\Microsoft\Exchange Server\V15"


            # Mount the Exchange Installation ISO:
            $ISOVolumeName = "EXCHANGESERVER2019-X64-CU12"

            # Drive Letter for the Exchange Installation ISO
            $ExchISODriveLetter = (Get-Volume | Where-Object {$_.DriveType -like "CD-ROM" -and $_.FileSystemLabel -like $ISOVolumeName}).DriveLetter
        
            #############################################
            ############## VISUAL C++ 2013 ##############
        
            # Check if Visual C++ 2013 is installed
            $IsVisualC2013Installed = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue).Installed -eq 1
        
            if (!($IsVisualC2013Installed)) {
                $LogFile = "$($LogFolder)\visualcplusplus.log"
                Write-Verbose "Installing Visual C++ 2013..." -Verbose
                start-process "$($ExchangePreReqFolder)\vcredist_x64.exe" -ArgumentList "/install /quiet /norestart /log $($LogFile)" -NoNewWindow -Wait
                Start-Sleep -Seconds 2
            } else {
                Write-Verbose "Visual C++ 2013 is already installed." -Verbose
        }
        
            #########################################
            ############## URL Rewrite ##############
        
                # Check if URL Rewrite is installed
                $IsRewriteInstalled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9BCA2118-F753-4A1E-BCF3-5A820729965C}" -ErrorAction SilentlyContinue).DisplayVersion
                if ($IsRewriteInstalled -notlike "7.2.1993") {
                    $LogFile = "$($LogFolder)\rewrite.log"
                    Write-Verbose "Installing URL Rewrite..." -Verbose
                    start-process -FilePath msiexec.exe -ArgumentList "/i $($ExchangePreReqFolder)\rewrite_amd64_en-US.msi /quiet /norestart /log $($LogFile)" -NoNewWindow -Wait
                    Write-Verbose "URL Rewrite installed." -Verbose
                } else {
                    Write-Verbose "URL Rewrite is already installed." -Verbose
        }
        

            Set-Location "$($ExchISODriveLetter):\"
            ####################################################################
            ############## Unified Communications Managed API 4.0 ##############
        
            # Check if Unified Communications Managed API 4.0 is installed
            $IsUCMAv4Installed = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ED98ABF5-B6BF-47ED-92AB-1CDCAB964447}" -ErrorAction SilentlyContinue).DisplayVersion
            if ($IsUCMAv4Installed -notlike "5.0.8308.0") {
                $LogFile = "$($LogFolder)\ucma.htm"
                Write-Verbose "Installing Unified Communications Managed API 4.0..." -Verbose
                Start-Process "$($ExchISODriveLetter):\UCMARedist\setup.exe" -ArgumentList "/q /log $($LogFile)" -NoNewWindow -Wait
                Start-Sleep -Seconds 2
            } else {
                Write-Verbose "Unified Communications Managed API 4.0 is already installed." -Verbose
            }
        
        
            $ExchangeADObjects = (get-adObject -Filter * | Where-Object {$_.DistinguishedName -match "Exchange"}).Count
        
            # Check if "Exchange" AD Objects exists already and if not (at least 24 objects), run /PrepareSchema & /PrepareAD
            if ($ExchangeADObjects -lt 24) {
                Write-Verbose "Running /PrepareSchema..." -Verbose
                .\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareSchema
                Start-Sleep -Seconds 5
                Write-Verbose "/PrepareSchema completed." -Verbose
        
                Write-Verbose "Running /PrapareAD..." -Verbose
                .\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAD /OrganizationName:$($DCNetBIOSName)
                Start-Sleep -Seconds 5
                Write-Verbose "/PrepareAD completed." -Verbose
            } else {
                Write-Verbose "/PrepareSchema & /PrepareAD are already completed." -Verbose
            }
        
            # Check if Exchange Server 2019 is installed already and if not, install it
            try {
                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction stop
                Write-Verbose "Exchange Server 2019 is already installed." -Verbose
            }
            catch {
                $LogFile = "$($LogFolder)\exchange-server-installation.log"
                Write-Verbose "Installing Exchange Server 2019..." -Verbose
                .\setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /Role:Mailbox /InstallWindowsComponents /OrganizationName:$($DCNetBIOSName) /TargetDir:$($ExchangeFolder) /LogFolderPath:$($LogFile)
                Write-Verbose "Exchange Server 2019 installed successfully." -Verbose
                Write-Verbose "Restarting [$($VM.VMName)]..."
                Restart-Computer -Force
            }
        }
    Invoke-Script -ScriptItem ItSelf
    }
    "Q" 
    {
        # Quit the program
        exit 
    }
    
    "B" 
    {
        # Go back to Main Menu
        Invoke-Script -ScriptItem Main -PauseBefore $false
    }
    
    Default 
    { 
    Write-Host "Wrong Selection!" -ForegroundColor Red
    Invoke-Script -ScriptItem ItSelf
    }
    }
