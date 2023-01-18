. .\variables.ps1
Get-ElevatedInfo
Clear-Host
if (($ConfigFile.Hostname -contains $HostName)) {
    $VMPath = ($ConfigFile | Where-Object {$_.HostName -like $HostName}).VMPath
    $ServerTemplateCorePath = ($ConfigFile | Where-Object {$_.HostName -like $HostName}).ServerTemplateCorePath
    $ServerTemplateGuiPath = ($ConfigFile | Where-Object {$_.HostName -like $HostName}).ServerTemplateGuiPath
    $ClientTemplatePath = ($ConfigFile | Where-Object {$_.HostName -like $HostName}).ClientTemplatePath
} 
# If there Multiple host with the same Hostnames, the selection will be done here
elseif (($ConfigFile.Hostname -match $HostName).count -gt 1) {
    Clear-Host
    Write-Host "There are multiple Host with the same Names"
    $ConfigFile | Where-Object {$_.HostName -like $HostName} | ForEach-Object {$index=0} {$_; $index++} | Format-List -Property @{Label="Index";Expression={$index}},HostName,VMPath,ServerTemplateCorePath,ServerTemplateGuiPath,ClientTemplatePath
    [int32]$HostSelection = Read-Host "Select ONE of the option above"
    $VMPath = ($ConfigFile | Where-Object {$_.HostName -like $HostName})[$HostSelection].VMPath
    $ServerTemplateCorePath = ($ConfigFile | Where-Object {$_.HostName -like $HostName})[$HostSelection].ServerTemplateCorePath
    $ServerTemplateGuiPath = ($ConfigFile | Where-Object {$_.HostName -like $HostName})[$HostSelection].ServerTemplateGuiPath
    $ClientTemplatePath = ($ConfigFile | Where-Object {$_.HostName -like $HostName})[$HostSelection].ClientTemplatePath
    Clear-Host
    ($ConfigFile | Where-Object {$_.HostName -like $HostName})[$HostSelection] | Format-List HostName,VMPath,ServerTemplateCorePath,ServerTemplateGuiPath,ClientTemplatePath
} else {

    Write-Host -ForegroundColor red "Cannot find VM Path or Template Path"
    $TempHostName = $HostName
    $TempVMPath = Read-Host "Enter the path where you want to store your VM"
    while (!(test-path $TempVMPath)) {
        Write-Host -ForegroundColor red "The folder does not exist!"
        $TempVMPath = Read-Host "Enter the path where you want to store your VM"
    }
    
    $TempServerTemplateCorePath = Read-Host "Enter .vhdx TEMPLATE path for server19 CORE (Enter for none)"
    while (!(test-path $TempServerTemplateCorePath) -xor ($TempServerTemplateCorePath -like "")) {
        Write-Host -ForegroundColor red "The file does not exist!"
        $TempServerTemplateCorePath = Read-Host "Enter .vhdx TEMPLATE path for server19 CORE (Enter for none)"
    }
    
    $TempServerTemplateGuiPath = Read-Host "Enter .vhdx TEMPLATE path for server19 Desktop Experience (Enter for none)"
        while (!(test-path $TempServerTemplateGuiPath) -xor ($TempServerTemplateGuiPath -like "")) {
        Write-Host -ForegroundColor red "The file does not exist!"
        $TempServerTemplateGuiPath = Read-Host "Enter .vhdx TEMPLATE path for server19 Desktop Experience (Enter for none)"
    }
    
    $TempClientTemplatePath = Read-Host "Enter .vhdx TEMPLATE path for Windows 10 (Enter for none)"
    while (!(test-path $TempClientTemplatePath) -xor ($TempClientTemplatePath -like "")) {
        Write-Host -ForegroundColor red "The file does not exist!"
        $TempClientTemplatePath = Read-Host "Enter .vhdx TEMPLATE path for Windows 10 (Enter for none)"
    }


    # Creating a Temporary Object to store the iformation and later on save it to menu.json file for persistence
    $TempHost = [ordered]@{
        HostName = $TempHostName
        VMPath = $TempVMPath
        ServerTemplateCorePath = $TempServerTemplateCorePath
        ServerTemplateGuiPath = $TempServerTemplateGuiPath
        ClientTemplatePath = $TempClientTemplatePath
        VMSwitchedConfigured = $False
        VHDType = "Differencing"
        DefaultNonDifferencingVHDDisk = "60GB"
    }
    $ConfigFile = [array]$ConfigFile + [array]$TempHost
    $ConfigFile | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\config.json"
    Start-Sleep -Seconds 1
}


if (($ConfigFile | Where-Object HostName -like $HostName).VMSwitchedConfigured -eq $false) {
    $NetworkSwitchCount = 0
    foreach ($VM in $VMList) {
        if ((Get-VMSwitch).Name -like $VM.NetworkSwitches) {
            [array]$VM.NetworkSwitches += $VM.NetworkSwitches
            $NetworkSwitchCount ++
            }
    }

    # If there are no matching VM Switch run, make a selection of existing ones in the system
    if ($NetworkSwitchCount -lt 1) {
        Write-Host "Cannot find virtual switchname(s) [$($VM.NetworkSwitches)] in the system!" -ForegroundColor Yellow | Out-Host
        if ((Get-VMSwitch).Count -gt 0) {
            Write-Host "List of your existing VM Switches:" (Get-VMSwitch).Name -ForegroundColor green | Out-Host
        }
        [string]$TempNetworkSwitchs = Read-Host "Enter the the name of your VM network switch"

        # If the provided VM Switch Name is not in the existing switches, it will create a new one
        if ((Get-VMSwitch).Name -notcontains $TempNetworkSwitchs) {
            Write-Host "Cannot find virtual switchname $($TempNetworkSwitchs). Creating new virtual switch..." -ForegroundColor Yellow | Out-Host
            New-VMSwitch -Name $TempNetworkSwitchs -SwitchType Private | Out-Null
        }
        
        # Assigning A
        foreach ($Switch in $TemplateMachines) {
            [array]$Switch.NetworkSwitches = $TempNetworkSwitchs
        }

        foreach ($Switch in $VMList) {
            [array]$Switch.NetworkSwitches = $TempNetworkSwitchs
        }
    $TemplateMachines | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\template-machines.json"
    }

($ConfigFile | Where-Object HostName -like $HostName).VMSwitchedConfigured = $True
$ConfigFile | ConvertTo-Json | Out-File -Path "$ConfigFolder\config.json"
}
$MyConfig = $ConfigFile | Where-Object {$_.HostName -like $HostName}
$VMPath = ($MyConfig).VMPath
$ServerTemplateCorePath = ($MyConfig).ServerTemplateCorePath
$ServerTemplateGuiPath = ($MyConfig).ServerTemplateGuiPath
$ClientTemplatePath = ($MyConfig).ClientTemplatePath
$VHDType = ($MyConfig).VHDType
$DiskSize = ($MyConfig).DefaultNonDifferencingVHDDisk

foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {
    Write-Verbose "Starting VM Creation Process...." -Verbose

    if ($VM.MachineType -like "server") {
        if ($VM.isCore -eq $true) { $TemplatePath = $ServerTemplateCorePath } 
        else { $TemplatePath = $ServerTemplateGuiPath }
    } else { $TemplatePath = $ClientTemplatePath }

    #Set the parent VHDX as Read-Only for protection
    Set-ItemProperty -Path $TemplatePath -Name IsReadOnly -Value $true

    # Check if the folder already exist in 
    If ((Test-Path ($VMPath + "\" + $VM.VMName)) -eq $true){
        $VMPath + "\" + $VM.VMName
        Write-host -ForegroundColor Red $VM.VMName "Folder Already Exist"
    exit
    }

    # Check if the Parent/template Disk Exist
    If ((Test-Path ($TemplatePath)) -eq $false){
        $TemplatePath
        Write-host -ForegroundColor Red $VM.VMName "COULD NOT FIND TEMPLATE. EXITING."
    exit
    }

    # Provision New VM
    if ($VHDType -notlike "Differencing") {
        $VHD = New-VHD -Path ($VMPath + "\" + $VM.VMName + "\" + $VM.VMName + ".vhdx") -ParentPath $TemplatePath -SizeBytes $DiskSize -Dynamic
    } else {
        $VHD = New-VHD -Path ($VMPath + "\" + $VM.VMName + "\" + $VM.VMName + ".vhdx") -ParentPath $TemplatePath -Differencing
    }

    Write-Verbose "Deploying VM [$($VM.VMName)]" -Verbose
    new-vm -Name $VM.VMName -Path $VMPath  -VHDPath $VHD.Path -BootDevice VHD -Generation 2

    $VM.VMId = (get-vm $VM.VMName).VMId.Guid
    $VM.CreationTime = $LogDateTime
    Set-VMProcessor $VM.VMName -Count $VM.ProcessorCount
    Set-VMMemory $VM.VMName -DynamicMemoryEnabled $true -MinimumBytes $VM.MemoryMinimum -StartupBytes $VM.MemoryStartup -MaximumBytes $VM.MemoryMaximum
    Set-VM -Name $VM.VMName -CheckpointType Disabled
    Set-VMFirmware $VM.VMName -EnableSecureBoot Off

    Remove-VMNetworkAdapter -VMName $VM.VMName -Name "Network Adapter"
    foreach ($NetworkSwitch in $VM.NetworkSwitches) {
        Add-VMNetworkAdapter -VMName $VM.VMName -Name "Network Adapter" -SwitchName $NetworkSwitch
    }

    $VM.HasJoinedDomain = $False

    # If both index 0 and index 1 on the machine is filled, create the hard-drives then
    if ($($VM.NonOSHardDrivs[0]) -and $($VM.NonOSHardDrivs[1]) ) {
        Write-Verbose "Creating Non OS VHD.... for $($VM.VMName)" -Verbose
        $HardDriveAmount = [int32]$VM.NonOSHardDrivs[0]
        $HardDriveSize = [UInt64]$VM.NonOSHardDrivs[1]

        for ($i = 0; $i -lt $HardDriveAmount; $i++) {
            ($VMPath + "\" + $VM.VMName + "\" + $VM.VMName + "DATA" + $i + ".vhdx")
            $NonOSHardDrive = New-VHD -Path ($VMPath + "\" + $VM.VMName + "\" + $VM.VMName + "DATA" + $i + ".vhdx") -SizeBytes $HardDriveSize -Dynamic
            Write-Verbose "Attaching [$($NonOSHardDrive.Path)] Disk to [$($VM.VMName)]" -Verbose
            Add-VMHardDiskDrive -VMName $VM.VMName -Path $NonOSHardDrive.Path
        }
    }

    # [array]$VM.HardDrives = $Null
    $TemVM = Get-VM -Name $VM.VMName
    foreach ($HardDrive in $TemVM) {
        $VM.HardDrives = [array]$TemVM.HardDrives.Path
    }
}

$VMList | ConvertTo-Json | Out-File -FilePath "$ConfigFolder\inventory.json"
Write-Verbose "VM Creation Process Completed." -Verbose