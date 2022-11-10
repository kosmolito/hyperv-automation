. .\variables.ps1
foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {

    if ($VM.HasJoinedDomain) {
        Write-Verbose "[$($VM.VMName)] is already joined to a domain" -Verbose
    } else {
        if ($VM.MachineType -like "server") {$Credential = $ServerLocalCredential} 
        else {$Credential = $ClientCredential}

    if ($VM.Roles -contains "AD-Domain-Services") {
        Write-Host -ForegroundColor yellow $VM.VMName "is a DC. skipping.."
    } else {
        
        Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}
        Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose

        Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
            $HasJoinedDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            if (!$HasJoinedDomain) {
                Write-Verbose "Joining [$($using:VM.VMName)] to [$($using:DomainName)]  " -Verbose
                Add-Computer -DomainName $using:DomainName -Credential $using:DomainCredential -Restart
                Write-Verbose "Restarting [$($using:VM.VMName)]" -Verbose
            }
        }
    }

    }
$VM.HasJoinedDomain = $True
}
$VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"
Write-Verbose "Joining process completed." -Verbose
