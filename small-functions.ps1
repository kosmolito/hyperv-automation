. .\variables.ps1
##########################################################################################################
############################## Making Storage Pool of Disks and Virtal Disk ##############################
##########################################################################################################
$StoragePoolName = $DomainNetbiosName +"Data"
$DriveFriendlyName = "shared-drive"
# Check the Disk that can be pooled
$PhysicalNonOSDisk = (Get-PhysicalDisk -CanPool $True)


# Creating new Storage pool with
New-StoragePool -FriendlyName $StoragePoolName -StorageSubsystemFriendlyName "Windows Storage*" `
-PhysicalDisks $PhysicalNonOSDisk -ResiliencySettingNameDefault Mirror -ProvisioningTypeDefault Fixed -Verbose

# Making New Virutal Disk with Name shared-drive, making disk as mirror
New-VirtualDisk -FriendlyName $DriveFriendlyName -StoragePoolFriendlyName $StoragePoolName -ResiliencySettingName Mirror -UseMaximumSize -ProvisioningType Fixed

Get-VirtualDisk –FriendlyName $DriveFriendlyName | Get-Disk | Initialize-Disk –Passthru | New-Partition –AssignDriveLetter –UseMaximumSize | Format-Volume
##########################################################################################################


##########################################################################################################
######################################## Folders and Permissions #########################################
##########################################################################################################

# Shot the ACL / Permissions for the folder
# (Get-Acl -Path $FolderPath).Access | Format-Table -Autosize

# Folders needed: DFS (for root folder), public, Ekonomi, Sales, 
# Folders needed: DFS (for root folder), public, Ekonomi, Sales, 
[array]$DFSRootFolder = $VM.DriveLetter + $VM.DFSRootFolder
[array]$DFSPublicFolder = $VM.DriveLetter + $VM.DFSPublicFolder
[array]$SMBFolders = $DFSRootFolder + $DFSPublicFolder
[array]$NonSMBFolders = "$DFSPublicFolder\sales","$DFSPublicFolder\ekonomi","$DFSPublicFolder\bd"
[array]$AllFolders = $SMBFolders + $NonSMBFolders
$AllFolders

foreach ($Folder in $AllFolders) {
    if (Test-Path($Folder)) {
        Write-Host -ForegroundColor Yellow "$Folder folder already exist!"
    } else {
        New-Item -Path $folder -ItemType Directory
    }
}

# Making SMB Shares and Disabling the inheritance, also removing the builtin\users
foreach ($Folder in $SMBFolders) {
    $FolderName = $Folder.Split("\")[1]
    $FolderPath = $Folder
    $SMBStatus = Get-SmbShare -Name $FolderName
    if($FolderPath -like $SMBStatus.Path) {
        write-host -ForegroundColor Yellow "$Folder folder is shared already!"
    } else {
        New-SmbShare -Name $FolderName -Path $Folder -FolderEnumerationMode AccessBased
    }

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
    $identity = "mstile\SEC_Public"
    $rights = 'ReadAndExecute,Synchronize' #Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
    $inheritance = "none"#'ContainerInherit, ObjectInherit' #Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
    $propagation = 'None' #Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
    $type = 'allow' #Other options: [enum]::GetValues('System.Security.AccessControl.AccessControlType')
    $ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($identity,$rights,$inheritance,$propagation,$type)
    $Acl = Get-Acl -Path $FolderPath
    $Acl.AddAccessRule($ACE)
    Set-Acl -Path $FolderPath -AclObject $Acl
}


##########################################################################################################
############################################# DFS NameSpace ##############################################
##########################################################################################################

# Create DFS Root Folder
New-DfsnRoot -Path "\\$DomainName\share" -TargetPath "\\$VM.VMName\dfsroot" -Type DomainV2 -EnableAccessBasedEnumeration $true

# Create New folder under the root folder
New-DfsnFolder -Path "\\$DomainName\share\public" -TargetPath "\\FIL01\public" -EnableTargetFailback $True