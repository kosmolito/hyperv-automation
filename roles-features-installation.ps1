. .\variables.ps1
foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {


    if (((get-vm $VM.VMName).State) -like "Off") {
        Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $VM.VMName
    }

    $Roles = $VM.Roles

    foreach ($Role in $Roles) {

        if ($VM.MachineType -like "server") {
            if (($VM.HasJoinedDomain)) {
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
            $VMList = $using:VMList
            $VM = $using:VM
            $DomainName = $using:DomainName
            $DomainNetbiosName = $using:DomainNetbiosName
            $ForestRecoveryPwd = $using:ForestRecoveryPwd
            $DomainCredential = $using:DomainCredential
            Install-FeaturesAndRoles -Role $using:Role

        }
        
        if ($Role -match "AD-Domain-Services-*" -and $VM.HasJoinedDomain -eq $False) {
            $VM.HasJoinedDomain = $true
            $VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
            $VMList = Get-Content -Path "$ConfigFolder\inventory.json" | ConvertFrom-Json
            Start-Sleep -Seconds 2
        }
    }
}