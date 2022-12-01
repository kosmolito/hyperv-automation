. .\variables.ps1


$VM = $VMList | Where-Object { ($_.isSelected -eq $true) }
if ($VM.Count -lt 1) {
    read-host "No VM with file-server role found. Exiting!"
    exit
    & $PSScriptRoot\main.ps1
} else {

    if ($VM.MachineType -like "server" -and ($VM.HasJoinedDomain)) {
        $DomainName = $VM.DomainName
        $DomainNetbiosName = $DomainName.split(".")[0].ToUpper()
        $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential `
        -ArgumentList $DomainNetbiosName\$DomainAdmin, $DomainPwd

        $Credential = $DomainCredential
    } else {
        $Credential = $ServerLocalCredential
    }

    if (((get-vm $VM.VMName).State) -like "Off") {
        Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $VM.VMName
    }
    $MyOUFolders = Read-Host -Prompt "Specify the OU folder Names ex. Stockholm,Goteborg"
    $MyOUFolders = $MyOUFolders.split(',')
    $MyDepartmentFolders = Read-Host -Prompt "Specify the Department Folder Names, ex. Sales,Ekonomi"
    $MyDepartmentFolders = $MyDepartmentFolders.split(',')
    $PublicSecurityGroupName = Read-Host -Prompt "Specify the Public Security Group Name"
    Write-Verbose "Waiting for PowerShell to connect [$($VM.VMName)] " -Verbose
    while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

    Write-Verbose "PowerShell Connected to VM [$($VM.VMName)]. Moving On...." -Verbose
    Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {
        $VM = $using:VM
        $UserList = $using:UserList
        $DomainName = $using:DomainName
        $DomainNetbiosName = $using:DomainNetbiosName
        

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

        # Show the ACL / Permissions for the folder
        # (Get-Acl -Path $FolderPath).Access | Format-Table -Autosize


        while (!(test-path($VM.NonOSDriveLetter))) {
            $VM.NonOSDriveLetter = Read-Host "The Drive Letter Does not Exist.`nSpecify The Drive letter"
            $VM.NonOSDriveLetter
        }

        foreach ($Folder in $($VM.DFSPublicFolders)) {
            [array]$DFSFolders += $VM.NonOSDriveLetter + $Folder
        }

        [array]$DFSRootFolder = $VM.NonOSDriveLetter + $VM.DFSRootFolder
        $DFSPublicFolder = $DFSFolders[0]
        [array]$SMBFolders = $DFSRootFolder + $DFSFolders


        $NonSMBFolders = $null
        foreach ($Folder in $using:MyOUFolders) {
            [array]$NonSMBFolders = $NonSMBFolders + ($DFSPublicFolder + "\" + $Folder)
            foreach ($f in $using:MyDepartmentFolders) {
                [array]$NonSMBFolders = $NonSMBFolders + ($DFSPublicFolder + "\" + $Folder + "\" + $f)
            }
        }
      
        # [array]$NonSMBFolders = "$DFSPublicFolder\sales","$DFSPublicFolder\ekonomi","$DFSPublicFolder\bd"
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
                New-SmbShare -Name $FolderName -Path $Folder -FolderEnumerationMode AccessBased -FullAccess "Everyone" | Out-Null
            }

            Start-Sleep -Seconds 1
            $DomainAdmins = "$DomainNetbiosName\Domain Admins"
            $identity = "$DomainNetbiosName\$using:PublicSecurityGroupName"

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

            # Special permission for folder-redirection folder
            if (($FolderName -like "folder-redirection")) {


                $Acl = get-acl $FolderPath
                $acl.SetAccessRuleProtection($isProtected,$preserveInheritance)

                #   Set required NTFS permissions to folder
                #   CREATOR OWNER - Full Control (Apply onto: Subfolders and Files Only) 
                $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
                $propagation = [system.security.accesscontrol.PropagationFlags]"InheritOnly"
                $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                $acl.AddAccessRule($accessrule)

                # System - Full Control (Apply onto: This Folder, Subfolders and Files)
                $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
                $propagation = [system.security.accesscontrol.PropagationFlags]"NoPropagateInherit"
                $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                $acl.AddAccessRule($accessrule)

                # Domain Admins - Full Control (Apply onto: This Folder Only)
                $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($DomainAdmins, "FullControl", "Allow")
                $acl.AddAccessRule($accessrule)

                # Everyone - Create Folder/Append Data, List Folder/Read Data, Traverse Folders/Execute File (Apply onto: This Folder Only) 
                $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($identity, "CreateDirectories, ListDirectory, Traverse", "Allow")
                $acl.AddAccessRule($accessrule)

                # Apply permissions to folder
                set-acl -aclobject $acl $FolderPath
            }

            if (($FolderName -like "bg-image")) {


            # Grant Permission to the Domain Users, in this  case only ReadAndExecute
            # The permission is applied to this folder/object and sub subfolders
            $rights = 'ReadAndExecute,Synchronize' #Other options: [enum]::GetValues('System.Security.AccessControl.FileSystemRights')
            $inheritance = "ContainerInherit, ObjectInherit"#'ContainerInherit, ObjectInherit' #Other options: [enum]::GetValues('System.Security.AccessControl.Inheritance')
            $propagation = 'None' #Other options: [enum]::GetValues('System.Security.AccessControl.PropagationFlags')
            $type = 'allow' #Other options: [enum]::GetValues('System.Security.AccessControl.AccessControlType')
            $ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($identity,$rights,$inheritance,$propagation,$type)
            $Acl = Get-Acl -Path $FolderPath
            $Acl.AddAccessRule($ACE)
            Set-Acl -Path $FolderPath -AclObject $Acl

            }



            # Grant Permission to the Domain Users, in this  case only ReadAndExecute
            # The permission is only applied to this folder/object and not subfolders,
            # if the permission will be for subfolders, change the inheritance to "ContainerInherit, ObjectInherit"
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

        if ($VM.Roles -match "FS-DFS-Namespace") {
            $DFSRootFolderName = $DFSRootFolder.split("\")[1]
            # Create DFS Root Folder
            if ((test-path "\\$DomainName\share")) {
            Write-Host -ForegroundColor yellow "DfnsNameSpace Root \\$DomainName\share already exist"
            } else { New-DfsnRoot -Path "\\$DomainName\share" -TargetPath "\\$($VM.VMName)\$DFSRootFolderName" -Type DomainV2 -EnableAccessBasedEnumeration $True -GrantAdminAccounts $DomainAdmins }

            # Create New folders under the root folder
            foreach ($Folder in $($DFSFolders)) {
                $DFSFolderName = $Folder.split("\")[1]
                if ((test-path "\\$DomainName\share\$DFSFolderName")) {
                    Write-Host -ForegroundColor yellow "DfnsNameSpace folder \\$DomainName\share\$DFSFolderName already exist"
                } else { New-DfsnFolder -Path "\\$DomainName\share\$DFSFolderName" -TargetPath "\\$($VM.VMName)\$DFSFolderName" -EnableTargetFailback $True }
            }
    }
    }
}