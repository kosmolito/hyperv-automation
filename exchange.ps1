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
        }
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
