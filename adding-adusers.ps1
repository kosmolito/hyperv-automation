. .\variables.ps1

function Show-Menu {
    param (
        [string]$Title = 'User Creation Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    
    Write-Host "1: importing the users from the domain-users.csv"
    Write-Host "2: Specifying the .csv file to import."
    Write-Host "3: Random generate users"
    Write-Host "Q: To quit."
}

$File1 = "c:\file1.csv"
$File1 -match "^(?!.*\.csv$).*$"

Show-Menu
$selection = Read-Host "Please make a selection"
switch ($selection)
    {
        
    '1' { } # Do nothing and get the user info from variable.ps1 file
        
    '2' 
    {
    $NewCsvFile =  Read-Host -Prompt "Specify the location of .csv file"
    if(!(test-path $NewCsvFile)) {
        Write-Host "The file does not exist. Exiting!" -ForegroundColor red 
        exit
    } elseif ($NewCsvFile -match "^(?!.*\.csv$).*$") {
        Write-Host "The file you have provided is not a CSV file. Exiting!"-ForegroundColor red
        exit
    } else { $UserList = import-csv -path $NewCsvFile }
    }

    '3' 
    {
    $RandomNameList = Import-Csv "$PSScriptRoot\random-names.csv"
    [ValidateRange(1, 500)]$UserAmount = Read-Host -Prompt "How many users are to be created? (Max 500)"
    $UserPassword = Read-Host -Prompt "Insert the password for the users"
    $RAWGeneralSecurityGroup = Read-Host -Prompt "Insert general security group name, eg. Public"
    $RAWSecurityGroups = Read-Host -Prompt "Insert other security groups separated by a comma, eg. Sales,Ekonomi"
    $SecurityGroup = $RAWSecurityGroups.split(",")
    $RawOU = Read-Host -Prompt "Insert the name of the OUs separated by a comma eg. site1_users,site2_users"
    $OU = $RawOU.split(",")
    
    $FilePath = "$PSScriptRoot\random-generated-users.csv"
    if (test-path ($FilePath)) {
    Remove-Item -Path $FilePath
    }
    
    for ($i = 0; $i -lt $UserAmount; $i++) {
        $RandomFirstName = Get-Random -Maximum $RandomNameList.Count
        $RandomLastName = Get-Random -Maximum $RandomNameList.Count
        $RandomSecurityGroup = Get-Random -Maximum $SecurityGroup.Count
        $RandomOU = Get-Random -Maximum $OU.Count
            [PsCustomObject]@{
            FirstName = $RandomNameList.FirstName[$RandomFirstName]
            LastName = $RandomNameList.LastName[$RandomLastName]
            UserPassword = $UserPassword
            SecurityGroups = "SEC_$($RAWGeneralSecurityGroup)" + "," + "SEC_$($SecurityGroup[$RandomSecurityGroup])"
            OU = $OU[$RandomOU]
            } | Export-Csv -Path $FilePath -Append -Encoding ASCII
        $UserList = import-csv -Path $FilePath
        }
    $UserList = Import-Csv -Path $FilePath
    }

    "q" { exit }
    }

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
    -DomainName $using:Credentials.DomainName -SecurityGroups $User.SecurityGroups
    Write-Host ($user.FirstName + "." + $user.LastName) "created." -ForegroundColor Green
    }
    Write-Verbose "User creation process finished." -Verbose
}