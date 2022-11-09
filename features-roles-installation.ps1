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

    foreach ($Role in $Roles) {

        Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
            Set-Content function:Install-FeaturesAndRoles -Value $using:InstallFeaturesAndRoles
            $VM = $using:VM
            $DomainName = $using:DomainName
            $DomainNetbiosName = $using:DomainNetbiosName
            $ForestRecoveryPwd = $using:ForestRecoveryPwd
            Install-FeaturesAndRoles -Role $using:Role
        }
    }
}