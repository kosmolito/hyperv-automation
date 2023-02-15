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

    "1" 
    {
    }

    "2" 
    {  
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
