. .\variables.ps1
Get-ElevatedInfo
$VMSelected = $VMList | Where-Object {$_.isSelected -eq $true}

if ($VMSelected.Count -gt 1) {
    Write-Host " Warning! You have selected more than 1 AD/DC, please retry!" -ForegroundColor Yellow
    $Selection = Read-Host "(b for back)"
    switch ($Selection) {
        "b" { Invoke-Script -ScriptItem Main -PauseBefore $false }
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
    Write-Host "3: Random generate users" -ForegroundColor green
    Write-Host "4: Import from last random generate file" -ForegroundColor Green
    Write-Host "B: Back to main menu" -ForegroundColor Green
    Write-Host "Q: To quit." -ForegroundColor Green

}

Show-Menu
$selection = Read-Host "Please make a selection"
switch ($selection)
    {
        
    "1" { 
        # Do nothing and get the user info from variable.ps1 file
        if (($null -like $UserList.DomainName) -or ($UserList.DomainName -like "") ) {
            $UserDomainName = Read-Host "No Domain Found! Specify the domain/upn eg. mstile.se"
            $UserList = $UserList | Select-Object *, @{n=”DomainName”;e={$UserDomainName}}
        }
     }
        
    "2"
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

        if (($null -like $UserList.DomainName) -or ($UserList.DomainName -like "") ) {
            $UserDomainName = Read-Host "No Domain Found! Specify the domain/upn eg. mstile.se"
            $UserList = $UserList | Select-Object *, @{n=”DomainName”;e={$UserDomainName}}
        }
    }
    }

    "3"
    {
    $RandomNameList = Import-Csv "$PSScriptRoot\example-resource\random-names.csv"
    [ValidateRange(1, 500)]$UserAmount = Read-Host -Prompt "How many users are to be created? (Max 500)"
    $DomainName = Read-Host -Prompt "Insert the UPN/Domain ex. mstile.se"
    $RawOU = Read-Host -Prompt "Insert the name of the OUs separated by a comma"
    $OU = $RawOU.split(",")
    $UserPassword = Read-Host -Prompt "Insert the password for the users" -MaskInput
    $RAWGeneralSecurityGroup = Read-Host -Prompt "Insert general security group name, ex. Public"
    $RAWSecurityGroups = Read-Host -Prompt "Insert other security groups separated by a comma, ex. Sales,Ekonomi"
    $SecurityGroup = $RAWSecurityGroups.split(",")

    $RandomCsvFilePath = "$ConfigFolder\random-generated-users.csv"
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
            SecurityGroups = ("SEC_" + $RAWGeneralSecurityGroup) + $(if ($SecurityGroup[$RandomSecurityGroup] -notlike "") { ",SEC_" +  $($SecurityGroup[$RandomSecurityGroup])})
            OU = $OU[$RandomOU]


            } | Export-Csv -Path $RandomCsvFilePath -Append -Encoding ASCII
        $UserList = import-csv -Path $RandomCsvFilePath
        }
    $UserList = Import-Csv -Path $RandomCsvFilePath
    }

    "4" {
        
        if (!(test-path "$ConfigFolder\random-generated-users.csv")) {
            Write-Error -Message "No file found!"
            Invoke-Script -ScriptItem ItSelf
        } else {
            $UserList = import-csv -path "$ConfigFolder\random-generated-users.csv"
            if (($null -like $UserList.DomainName) -xor ($UserList.DomainName -like "") ) {
                $UserDomainName = Read-Host "No Domain Found! Specify the domain/upn eg. mstile.se"
                $UserList = $UserList | Select-Object *, @{n=”DomainName”;e={$UserDomainName}}
            }
        }

     }

    "b" 
    { 
        Invoke-Script -ScriptItem Main -PauseBefore $False
        exit
    }

    "q" { exit }
    }



# $VMName = Read-Host -Prompt "Please enter the name of AD Machine"
if (((get-vm $VMSelected.VMName).State) -like "Off") {
    Write-Verbose "[$($VMSelected.VMName)] is turned off. Starting Machine..." -Verbose
    Start-vm -Name $VMSelected.VMName
}



Invoke-VMConnectionConfirmation -VMName $VMSelected.VMName -Credential $DomainCredential
Invoke-Command -VMName $VMSelected.VMName -Credential $DomainCredential -ScriptBlock {

    function Add-TheADUser {
        [CmdletBinding()]
        param($FirstName,$LastName,$UserPassword,$OU,$DomainName,$SecurityGroups)
    
        $FullName = $FirstName + " " + $LastName
        $username = ("$($FirstName)".ToLower() + "." + "$($LastName)".ToLower())
    
        # Converting non [a-z] charactor for the username to [a-z]
        # The string has been converted to Char array and the each char is been checked.
        # If its find å ä or ö it will convert to [a-z] letters.
        # TempUsername has $null value at the beginning. Char are been added to the variable on every loop.
        $TempUserName = $null
        foreach ($Char in $UserName.ToCharArray()) {
            switch -Regex ($Char) {
                [åäæ] { $Char = "a" }
                [öø] { $Char = "o" }
            }
            $TempUserName += $Char
        }
        $UserName = $TempUserName
    
        $UserPassword = ConvertTo-SecureString $UserPassword -AsPlainText -Force
        $SecurityGroups = $SecurityGroups.split(",")
        $DomainDistinguishedName = (get-addomain).distinguishedname

        #(get-addomain).distinguishedname

        $UserOU = "Users"    
        if (-not (Get-ADOrganizationalUnit -Filter 'name -like $OU'))
            { New-ADOrganizationalUnit -Name $OU -Path "$DomainDistinguishedName" -ProtectedFromAccidentalDeletion $false }

        # Creat OU for Sec groups
        $SecurityGroupOU = "SEC_Groups"
        if (-not (Get-ADOrganizationalUnit -Filter 'name -like $SecurityGroupOU'))
        { New-ADOrganizationalUnit -Name $SecurityGroupOU -Path "$DomainDistinguishedName" -ProtectedFromAccidentalDeletion $false }
        
        if (-not (Get-ADOrganizationalUnit -filter 'name -like $UserOU' | Where-Object {$_.DistinguishedName -match "OU=$OU,$DomainDistinguishedName"}) ) 
                    { New-ADOrganizationalUnit -Name $UserOU -Path "OU=$OU,$DomainDistinguishedName" -ProtectedFromAccidentalDeletion $false }
        $UserOUPath = "OU=$UserOU,OU=$OU,$DomainDistinguishedName"

        # Adding One extra SEC Group for each OU to easier NTFS target
        $SecurityGroups = $SecurityGroups + "SEC_$OU"

        $TempSecGroups = $null
        foreach ($Group in $SecurityGroups) {
            if (!($Group -match "^SEC_")) {
                $Group = "SEC_" + $Group
            }
            [array]$TempSecGroups = $TempSecGroups + $Group
        }
        
        $SecurityGroups = $TempSecGroups

        foreach ($SecurityGroup in $SecurityGroups) {
            if (-not (Get-ADGroup -Filter 'Name -like $SecurityGroup')) 
            { New-ADGroup -Name $SecurityGroup -GroupCategory Security -GroupScope Global -Path "OU=$SecurityGroupOU,$DomainDistinguishedName" }    
        }
    
        New-AdUser -AccountPassword $UserPassword `
        -GivenName $FirstName `
        -Surname $LastName `
        -DisplayName $FullName `
        -Name $FullName `
        -SamAccountName $username `
        -UserPrincipalName $username"@"$DomainName `
        -PasswordNeverExpires $true `
        -Path $UserOUPath `
        -Enabled $true
    
        # -Path "ou=$OU,$(([ADSI]`"").distinguishedName)" `
        foreach ($SecurityGroup in $SecurityGroups) {
            Add-ADGroupMember -Identity $SecurityGroup -Members $username
        }
    }


    Write-Verbose "User creation process starting..." -Verbose
    $i = 1
    foreach ($User in $using:UserList) {
        try {

            Add-TheADUser `
            -FirstName $User.FirstName -LastName $User.LastName -UserPassword $User.UserPassword -OU $User.OU `
            -DomainName $User.DomainName -SecurityGroups $User.SecurityGroups -ErrorAction Stop
            Write-Host ($user.FirstName + "." + $user.LastName) "created: $($i) of $($using:UserList.Count) total"  -ForegroundColor Green
            $i++
            
        }
        catch {
            Write-Host ($user.FirstName + "." + $user.LastName) -ForegroundColor Red
            Write-Error $Error[0]
        }

    }
    Write-Verbose "User creation process finished." -Verbose
}
Invoke-Script -ScriptItem ItSelf