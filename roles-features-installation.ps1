. .\variables.ps1
foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {
    if ($VM.MachineType -like "server") {
        if (($VM.HasJoinedDomain)) {
            $Credential = $DomainCredential
        } else {
            $Credential = $ServerLocalCredential
        }
    }

    if (((get-vm $VM.VMName).State) -like "Off") {
        Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $VM.VMName
    }

    $Roles = $VM.Roles
    foreach ($Role in $Roles) {
        Write-Host -ForegroundColor green $Role
        Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
            Set-Content function:Install-FeaturesAndRoles -Value $using:InstallFeaturesAndRoles
            $VMList = $using:VMList
            $VM = $using:VM
            $DomainName = $using:DomainName
            $DomainNetbiosName = $using:DomainNetbiosName
            $ForestRecoveryPwd = $using:ForestRecoveryPwd
            $DomainCredential = $using:DomainCredential

            if (($using:Role -match "AD-Domain-Services-*") -and ((Get-WindowsFeature -Name AD-Domain-Services).InstallState) -notlike "Installed") {
                Install-FeaturesAndRoles -Role $using:Role
                shutdown.exe /r
                Start-Sleep -Seconds 30
            } else { Install-FeaturesAndRoles -Role $using:Role }
        }

        if ($Role -match "AD-Domain-Services-*" -and $VM.HasJoinedDomain -eq $False) {
            $VM.HasJoinedDomain = $true
            $VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"
            $VMList = Get-Content -Path "$PSScriptRoot\$HostName-inventory.json" | ConvertFrom-Json
        }
    }
}