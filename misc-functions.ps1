. .\Variables.ps1


$VMSelected = $VMList | Where-Object {$_.isSelected -eq $true}

if ($VMSelected.Count -gt 1) {
    Write-Host " Warning! You have selected more than 1 AD/DC, please retry!" -ForegroundColor Yellow
    $Selection = Read-Host "(b for back)"
    switch ($Selection) {
        "b" { & $PSScriptRoot\main.ps1 }
        Default { exit }
    }

}

$DomainName = $VMSelected.DomainName
$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainName\$DomainAdmin,$DomainPwd

function Show-Menu {
    param (
        [string]$Title = "Misc. Functions"
    )
    Clear-Host
    Write-Host -ForegroundColor red "Existing VM Selected To Configure"
    $VMSelected | Format-table -Property VMName,DomainName,IPAddress,DNSAddress,NetworkSwitches
    Write-Host "================ $Title ================"
    
    Write-Host "1: DC/AD Replication Sync" -ForegroundColor Green
    Write-Host "2: Add an alternative UPN Suffix" -ForegroundColor Green
    Write-Host "3: Demote a DC" -ForegroundColor Green
    Write-Host "B:" "Back to main menu" -ForegroundColor Green
    Write-Host "Q: To quit" -ForegroundColor Green
}

Show-Menu
$selection = Read-Host "Please make a selection"


$VMSelected | Foreach-Object -Parallel {
    if (((get-vm $_.VMName).State) -like "Off") {
        Write-Verbose "[$($_.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $_.VMName
    }
}
switch ($selection)
    {
        
    "1"
    {

        Write-Verbose "Waiting for PowerShell to connect [$($VMSelected.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VMSelected.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {

        Write-Verbose "Syncing Domain Controllers...." -Verbose
        try {

            (Get-ADDomainController -Filter *).Name | Foreach-Object { repadmin /syncall $_ (Get-ADDomain).DistinguishedName /AdeP }
            Write-Verbose "Syncing Completed." -Verbose
        }
        catch {
            {Write-Verbose "Syncing Error." -Verbose}
        }

        }
        Pause
       & $PSScriptRoot\misc-functions.ps1
    }
        
    "2"
    {

        $AlternativeUPNSuffix = Read-Host -Prompt "Speficy alternative UPN suffix eg. test.com"

        Write-Verbose "Waiting for PowerShell to connect [$($VMSelected.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VMSelected.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {
        
        Write-Verbose "Adding alternative UPN [$($using:AlternativeUPNSuffix)]..." -Verbose
        Get-ADForest | Set-ADForest -UPNSuffixes @{add=$($using:AlternativeUPNSuffix)}
        Write-Verbose "UPN Alternative added." -Verbose

        }
        Pause
        & $PSScriptRoot\misc-functions.ps1
    }

    "3"
    {
        Clear-Host
        $AvailableDC = $VMList | Where-Object {($_.Roles -match "AD-DC") -and ($_.DomainName -like $VMSelected.DomainName) -and ($_.VMName -notlike $VMSelected.VMName)}
        Write-Host "Available DC to have FSMO role" -ForegroundColor green
        $AvailableDC | Format-Table VMName,DomainName,Roles | Out-Host
        $NewFSMORoleSelected = Read-Host "Specify VM Name to be Root DC"
        $NewFSMOVM = $AvailableDC | Where-Object {$_.VMName -like $NewFSMORoleSelected}


        Write-Host "WARNING! [$($VMSelected.VMName)] will be DEMOTED and [$($NewFSMOVM.VMName)] will be set as Root DC" -ForegroundColor Red | Out-Host

        $DemoteConfirmation = Read-Host "Do you really want to DEMOTE the machine(s)? (yes/no)"

        if ($DemoteConfirmation -notlike "yes") {
            Write-Host -ForegroundColor red "Sorry I did not get correct confirmation!"
            Pause
            & $PSScriptRoot\misc-functions.ps1
        } elseif ($VMSelected.count -ne 1) {
            Write-Host -ForegroundColor red "One ONE VM can be selected for this operation!"
            Pause
            & $PSScriptRoot\misc-functions.ps1
        } else {


        Write-Verbose "Waiting for PowerShell to connect [$($VMSelected.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Start-Sleep -Seconds 1}
        Write-Verbose "PowerShell Connected to VM [$($VMSelected.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {

            # Changing the DNS Server ipv4 address
            Write-Verbose "Changing DNS Address in the DHCP Scope to [$($using:NewFSMOVM.IPAddress)]." -Verbose
            Set-DhcpServerv4OptionValue -DnsServer "$($using:NewFSMOVM.IPAddress)"

            try {
                Write-Verbose "Pre FSMO Syncing Domain Controllers...." -Verbose
                (Get-ADDomainController -Filter *).Name | Foreach-Object { repadmin /syncall $_ (Get-ADDomain).DistinguishedName /AdeP }

                Write-Verbose "Changing FSMO Role to [$($using:NewFSMOVM.VMName)].." -Verbose
                Move-ADDirectoryServerOperationMasterRole -Identity $($using:NewFSMOVM.VMName) -OperationMasterRole DomainNamingMaster,PDCEmulator,RIDMaster,SchemaMaster,InfrastructureMaster -confirm:$false -ErrorAction Stop
                Start-Sleep -Seconds 2

                Write-Verbose "Post FSMO Syncing Domain Controllers...." -Verbose
                (Get-ADDomainController -Filter *).Name | Foreach-Object { repadmin /syncall $_ (Get-ADDomain).DistinguishedName /AdeP }
                Write-Verbose "Syncing Completed." -Verbose
            }
            catch {
                Write-Error $Error[0]
            }

            # Only run this code if the code above runned successfully
            if ($?) {
                try {
                    Write-Verbose "Demoting DC [$($using:VMSelected.VMName)]..." -Verbose
                    Import-Module ADDSDeployment
                    Uninstall-ADDSDomainController `
                    -DemoteOperationMasterRole:$true `
                    -RemoveDnsDelegation:$false `
                    -DnsDelegationRemovalCredential $using:DomainCredential `
                    -localadministratorpassword $using:DomainPwd `
                    -norebootoncompletion:$false `
                    -Force:$true -ErrorAction Stop
                }
                catch {
                    Write-Error $Error[0]
                }
            }

        }

        Write-Verbose "Waiting for PowerShell to connect [$($NewFSMOVM.VMName)] " -Verbose
        while ((Invoke-Command -VMName $NewFSMOVM.VMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Start-Sleep -Seconds 1}
        Write-Verbose "PowerShell Connected to VM [$($NewFSMOVM.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $NewFSMOVM.VMName -Credential $DomainCredential -ScriptBlock {

            Write-Verbose "Cleaning DNS Records of the OLD/Demoted DC [$($using:VMSelected.VMName)]..." -Verbose

            Get-DnsServerResourceRecord -ZoneName $($using:VMSelected.DomainName) | `
            Where-Object {$_.RecordData.IPv4Address -eq $($using:VMSelected.IPAdress) `
            -or $_.RecordData.NameServer -eq "$($using:VMSelected.VMName).$($using:VMSelected.DomainName)." `
            -or $_.RecordData.DomainName -eq "$($using:VMSelected.VMName).$($using:VMSelected.DomainName)."} | `
            Remove-DnsServerResourceRecord -ZoneName $($using:VMSelected.DomainName) -force

            Write-Verbose "Cleaning Process Finished." -Verbose
        }

        Pause
        & $PSScriptRoot\misc-functions.ps1

        }

    }

    "b" 
    { 
        & $PSScriptRoot\main.ps1
        exit
    }

    "q" { exit }

    }