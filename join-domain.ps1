. .\variables.ps1

$VMList | Where-Object {$_.isSelected -eq $true} | Foreach-Object -Parallel {
    if (((get-vm $_.VMName).State) -like "Off") {
        Write-Verbose "[$($_.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $_.VMName
    }
}

foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {


    if ($VM.HasJoinedDomain) {
        Write-Verbose "[$($VM.VMName)] is already joined to a domain" -Verbose
    } else {
        if ($VM.MachineType -like "server") {$Credential = $ServerLocalCredential} 
        else {$Credential = $ClientCredential}

    if ($VM.Roles -contains "AD-DC-ROOT") {
        Write-Host -ForegroundColor yellow $VM.VMName "is a Root DC. skipping.."
    } else {
        
        Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}
        Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose

       Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
            $HasJoinedDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            if (!$HasJoinedDomain) {

                $DomainName = $using:VM.DomainName
                $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainName\$using:DomainAdmin, $using:DomainPwd
                    Write-Verbose "Joining [$($using:VM.VMName)] to [$($DomainName)]..." -Verbose
                    Add-Computer -DomainName $DomainName -Credential $DomainCredential -Restart -ErrorAction stop
                    Write-Verbose "Restarting [$($using:VM.VMName)]" -Verbose
            }
        }

        # Only Change the value of the Last code runned without error
        if ($?) {
            $VM.HasJoinedDomain = $True
        }
        }

    }
}
$VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
Write-Verbose "Joining process completed." -Verbose
Pause
& $PSScriptRoot\main.ps1
