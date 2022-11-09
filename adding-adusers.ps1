. .\Variables.ps1

$VMName = Read-Host -Prompt "Please enter the name of AD Machine"

if (((get-vm $VMName).State) -like "Off") {
    Write-Verbose "[$($VMName)] is turned off. Starting Machine..." -Verbose
    Start-vm -Name $VMName
}

Write-Verbose "Waiting for PowerShell to connect [$VMName] " -Verbose
while ((Invoke-Command -VMName $VMName -Credential $DomainCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}
Write-Verbose "PowerShell Connected to VM [$VMName]. Moving On...." -Verbose


Invoke-Command -VMName $VMName -Credential $DomainCredential -ScriptBlock {
    Set-Content function:Add-TheADUser -Value $using:AddTheADUser
    Write-Verbose "User creation process starting..." -Verbose
    foreach ($User in $using:UserList) {
    Add-TheADUser `
    -FirstName $User.FirstName -LastName $User.LastName -UserPassword $User.UserPassword -OU $User.OU `
    -DomainName $User.DomainName -SecurityGroups $User.SecurityGroups
    }
    Write-Verbose "User creation process finished." -Verbose
}