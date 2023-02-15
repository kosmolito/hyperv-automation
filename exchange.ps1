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
