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
        [string]$Title = 'User Creation Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    
    Write-Host "1: Replication Sync"
    Write-Host "2: Add an alternative UPN Suffix"
    Write-Host "3: empty"
    Write-Host "B:" "Back to main menu"
    Write-Host "Q: To quit."
}

Show-Menu
$selection = Read-Host "Please make a selection"
switch ($selection)
    {
        
    '1' 
    {

        Write-Verbose "Waiting for PowerShell to connect [$($VMSelected.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VMSelected.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {

        Write-Verbose "Syncing Domain Controllers...." -Verbose
        (Get-ADDomainController -Filter *).Name | Foreach-Object { repadmin /syncall $_ (Get-ADDomain).DistinguishedName /AdeP }
        Write-Verbose "Syncing Completed." -Verbose
        }
       & $PSScriptRoot\misc-functions.ps1
    } 
        
    '2' 
    {

        $AlternativeUPNSuffix = Read-Host -Prompt "Speficy alternative UPN suffix eg. test.com"

        Write-Verbose "Waiting for PowerShell to connect [$($VMSelected.VMName)] " -Verbose
        while ((Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

        Write-Verbose "PowerShell Connected to VM [$($VMSelected.VMName)]. Moving On...." -Verbose
        Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {
        
        Write-Verbose "Adding alternative UPN [$($using:AlternativeUPNSuffix)]..." -Verbose
        Get-ADForest | Set-ADForest -UPNSuffixes @{add=$($using:AlternativeUPNSuffix)}
        Write-Verbose "UPN Alternative added." -Verbose

        }

        & $PSScriptRoot\misc-functions.ps1
    }

    '3'
    {

    }

    "b" 
    { 
        & $PSScriptRoot\main.ps1
        exit
    }

    "q" { exit }

    }