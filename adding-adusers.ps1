. .\variables.ps1

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
    Write-Host -ForegroundColor red "Selected VM"
    $VMSelected | Format-table -Property VMName,DomainName,Roles
    Write-Host "================ $Title ================"
    
    Write-Host "1: importing the users from the domain-users.csv" -ForegroundColor Green
    Write-Host "2: Specifying the .csv file to import." -ForegroundColor Green
    Write-Host "3: Random generate users" -ForegroundColor Green
    Write-Host "B:" "Back to main menu" -ForegroundColor Green
    Write-Host "Q: To quit." -ForegroundColor Green

}

Show-Menu
$selection = Read-Host "Please make a selection"
switch ($selection)
    {
        
    '1' { 
        # Do nothing and get the user info from variable.ps1 file
        if (($UserList.DomainName -like $null) -or ($UserList.DomainName -like "") ) {
            $UserDomainName = Read-Host "No Domain Found! Specify the domain/upn eg. mstile.se"
            $UserList = $UserList | Select-Object *, @{n=”DomainName”;e={$UserDomainName}}
        }
     } 
        
    '2' 
    {
    $NewCsvFile =  Read-Host -Prompt "Specify the location of .csv file"
    if(!(test-path $NewCsvFile)) {
        Write-Host "The file does not exist. Exiting!" -ForegroundColor red 
        exit
    } elseif ($NewCsvFile -match "^(?!.*\.csv$).*$") {
        Write-Host "The file you have provided is not a CSV file. Exiting!"-ForegroundColor red
        exit
    } else { 
        $UserList = import-csv -path $NewCsvFile

        if (($UserList.DomainName -like $null) -or ($UserList.DomainName -like "") ) {
            $UserDomainName = Read-Host "No Domain Found! Specify the domain/upn eg. mstile.se"
            $UserList = $UserList | Select-Object *, @{n=”DomainName”;e={$UserDomainName}}
        }
    }
    }

    '3'
    {
    $RandomNameList = Import-Csv "$PSScriptRoot\example-resource\random-names.csv"
    [ValidateRange(1, 500)]$UserAmount = Read-Host -Prompt "How many users are to be created? (Max 500)"
    $DomainName = Read-Host -Prompt "Insert the UPN/Domain eg. mstile.se"
    $UserPassword = Read-Host -Prompt "Insert the password for the users" -MaskInput
    $RAWGeneralSecurityGroup = Read-Host -Prompt "Insert general security group name, eg. Public"
    $RAWSecurityGroups = Read-Host -Prompt "Insert other security groups separated by a comma, eg. Sales,Ekonomi"
    $SecurityGroup = $RAWSecurityGroups.split(",")
    $RawOU = Read-Host -Prompt "Insert the name of the OUs separated by a comma eg. site1_users,site2_users"
    $OU = $RawOU.split(",")
    
    $RandomCsvFilePath = "$PSScriptRoot\random-generated-users.csv"
    if (test-path ($RandomCsvFilePath)) {
    Remove-Item -Path $RandomCsvFilePath
    }
    
    for ($i = 0; $i -lt $UserAmount; $i++) {
        $RandomFirstName = Get-Random -Maximum $RandomNameList.Count
        $RandomLastName = Get-Random -Maximum $RandomNameList.Count
        $RandomSecurityGroup = Get-Random -Maximum $SecurityGroup.Count
        $RandomOU = Get-Random -Maximum $OU.Count
            [PsCustomObject]@{
            FirstName = $RandomNameList.FirstName[$RandomFirstName]
            LastName = $RandomNameList.LastName[$RandomLastName]
            DomainName = $DomainName
            UserPassword = $UserPassword
            SecurityGroups = "SEC_$($RAWGeneralSecurityGroup)" + "," + "SEC_$($SecurityGroup[$RandomSecurityGroup])"
            OU = $OU[$RandomOU]
            } | Export-Csv -Path $RandomCsvFilePath -Append -Encoding ASCII
        $UserList = import-csv -Path $RandomCsvFilePath
        }
    $UserList = Import-Csv -Path $RandomCsvFilePath
    }

    "b" 
    { 
        & $PSScriptRoot\main.ps1
        exit
    }

    "q" { exit }
    }



# $VMName = Read-Host -Prompt "Please enter the name of AD Machine"
if (((get-vm $VMSelected.VMName).State) -like "Off") {
    Write-Verbose "[$($VMSelected.VMName)] is turned off. Starting Machine..." -Verbose
    Start-vm -Name $VMSelected.VMName
}



Write-Verbose "Waiting for PowerShell to connect [$($VMSelected.VMName)] " -Verbose
while ((Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}
Write-Verbose "PowerShell Connected to VM [$($VMSelected.VMName)]. Moving On...." -Verbose

Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {
    Set-Content function:Add-TheADUser -Value $using:AddTheADUser
    Write-Verbose "User creation process starting..." -Verbose
    $i = 1
    foreach ($User in $using:UserList) {
        try {

            Add-TheADUser `
            -FirstName $User.FirstName -LastName $User.LastName -UserPassword $User.UserPassword -OU $User.OU `
            -DomainName $User.DomainName -SecurityGroups $User.SecurityGroups -ErrorAction Stop
            Write-Host ($user.FirstName + "." + $user.LastName) "created: $($i) of $($UserList) total"  -ForegroundColor Green
            $i++
            
        }
        catch {
            Write-Error $Error[0]
        }

    }
    Write-Verbose "User creation process finished." -Verbose
}