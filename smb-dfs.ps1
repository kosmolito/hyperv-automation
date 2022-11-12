. .\variables.ps1

$FileSrvSelection = "Enter the name of the file server"
$VM = $VMList | Where-Object {($_.VMName -Like $FileSrvSelection) -and ($_.Roles -contains "FS-DFS-Namespace")}
while ($VM.Count -ne 1) {
    $FileSrvSelection = Read-Host "The information you provided is not correct. Please enter the name of the file server"
    $VM = $VMList | Where-Object VMName -Like $FileSrvSelection
}

if ($VM.MachineType -like "server") {
    if (($VM.HasJoinedDomain)) {
        $Credential = $DomainCredential
    } else {
        $Credential = $ServerLocalCredential
    }
}

if (((get-vm $VM.VMName).State) -like "Off") {
    Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
    Start-vm -Name $VM.VMName
}

Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose
Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
    $DomainName = $using:DomainName
    $VM = $using:VM

    ##########################################################################################################
    ############################## Making Storage Pool of Disks and Virtal Disk ##############################

    $StoragePoolName = $DomainNetbiosName +"Data"
    $DriveFriendlyName = "shared-drive"
    # Check the Disk that can be pooled
    $PhysicalNonOSDisk = (Get-PhysicalDisk -CanPool $True)

    if ($PhysicalNonOSDisk.Count -gt 0) {
    # Creating new Storage pool with
    New-StoragePool -FriendlyName $StoragePoolName -StorageSubsystemFriendlyName "Windows Storage*" `
    -PhysicalDisks $PhysicalNonOSDisk -ResiliencySettingNameDefault Mirror -ProvisioningTypeDefault Fixed -Verbose

    # Making New Virutal Disk with Name shared-drive, making disk as mirror
    New-VirtualDisk -FriendlyName $DriveFriendlyName -StoragePoolFriendlyName $StoragePoolName -ResiliencySettingName Mirror -UseMaximumSize -ProvisioningType Fixed

    Get-VirtualDisk –FriendlyName $DriveFriendlyName | Get-Disk | Initialize-Disk –Passthru | New-Partition –AssignDriveLetter –UseMaximumSize | Format-Volume
    }

    ##########################################################################################################
    ######################################## Folders and Permissions #########################################

    # Shot the ACL / Permissions for the folder
    # (Get-Acl -Path $FolderPath).Access | Format-Table -Autosize

    # Folders needed: DFS (for root folder), public, Ekonomi, Sales, 
    # Folders needed: DFS (for root folder), public, Ekonomi, Sales,
    [array]$DFSRootFolder = $VM.NonOSDriveLetter + $VM.DFSRootFolder
    [array]$DFSPublicFolder = $VM.NonOSDriveLetter + $VM.DFSPublicFolder
    [array]$SMBFolders = $DFSRootFolder + $DFSPublicFolder
    [array]$NonSMBFolders = "$DFSPublicFolder\sales","$DFSPublicFolder\ekonomi","$DFSPublicFolder\bd"
    [array]$AllFolders = $SMBFolders + $NonSMBFolders

    foreach ($Folder in $AllFolders) {
        if (Test-Path($Folder)) {
            Write-Host -ForegroundColor Yellow "$Folder folder already exist!"
        } else {
            New-Item -Path $folder -ItemType Directory | Out-Null
        }
    }

    # Making SMB Shares and Disabling the inheritance, also removing the builtin\users
    foreach ($Folder in $SMBFolders) {
        $FolderName = $Folder.Split("\")[1]
        $FolderPath = $Folder
        $SMBStatus = Get-SmbShare -Name $FolderName -ErrorAction SilentlyContinue
        if($FolderPath -like $SMBStatus.Path) {
            write-host -ForegroundColor Yellow "$Folder folder is shared already!"
        } else {
            New-SmbShare -Name $FolderName -Path $Folder -FolderEnumerationMode AccessBased | Out-Null
        }

        Start-Sleep -Seconds 1

        # Disabling The inheritance
        $Acl = Get-Acl -Path $FolderPath
        $isProtected = $true
        $preserveInheritance = $true
        $Acl.SetAccessRuleProtection($isProtected, $preserveInheritance)
        Set-Acl -Path $FolderPath -AclObject $acl

        # Removing the builtin Users from the folder
        $Acl = Get-Acl -Path $FolderPath
        $Acl.Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users"} | ForEach-Object { $acl.RemoveAccessRuleSpecific($_) }
        Set-Acl $FolderPath $Acl

        # Grant Permission to the Domain Users, in this  case only ReadAndExecute
        # The permission is only applied to this folder/object and not subfolders,
        # if the permission will be for subfolders, change the inheritance to "ContainerInherit, ObjectInherit"
        $identity = "$DomainNetbiosName\SEC_Public"
        $rights = 'ReadAndExecute,Synchronize' #Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
        $inheritance = "none"#'ContainerInherit, ObjectInherit' #Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
        $propagation = 'None' #Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
        $type = 'allow' #Other options: [enum]::GetValues('System.Security.AccessControl.AccessControlType')
        $ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($identity,$rights,$inheritance,$propagation,$type)
        $Acl = Get-Acl -Path $FolderPath
        $Acl.AddAccessRule($ACE)
        Set-Acl -Path $FolderPath -AclObject $Acl
    }

    Start-Sleep -Seconds 1

    ##########################################################################################################
    ############################################# DFS NameSpace ##############################################

    $DFSRootFolderName = $DFSRootFolder.split("\")[1]
    $DFSPublicFolderName = $DFSPublicFolder.split("\")[1]
    # Create DFS Root Folder
    if ((test-path "\\$DomainName\share")) {
       Write-Host -ForegroundColor yellow "DfnsNameSpace Root \\$DomainName\share already exist"
    } else { New-DfsnRoot -Path "\\$DomainName\share" -TargetPath "\\$($VM.VMName)\$DFSRootFolderName" -Type DomainV2 -EnableAccessBasedEnumeration $true }

    # Create New folder under the root folder
    if ((test-path "\\$DomainName\share\$DFSPublicFolderName")) {
        Write-Host -ForegroundColor yellow "DfnsNameSpace folder \\$DomainName\share\$DFSPublicFolderName already exist"
     } else { New-DfsnFolder -Path "\\$DomainName\share\$DFSPublicFolderName" -TargetPath "\\$($VM.VMName)\$DFSPublicFolderName" -EnableTargetFailback $True }
}