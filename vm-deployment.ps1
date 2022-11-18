. .\variables.ps1

if (($menu[2].Hostname -contains $HostName)) {
    $VMPath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).VMPath
    $ServerTemplateCorePath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).ServerTemplateCorePath
    $ServerTemplateGuiPath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).ServerTemplateGuiPath
    $ClientTemplatePath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).ClientTemplatePath
} 
# If there Multiple host with the same Hostnames, the selection will be done here
elseif (($menu[2].Hostname -match $HostName).count -gt 1) {
    Clear-Host
    Write-Host "There are multiple Host with the same Names"
    $Menu[2] | Where-Object {$_.HostName -like $HostName} | ForEach-Object {$index=0} {$_; $index++} | Format-List -Property @{Label="Index";Expression={$index}},HostName,VMPath,ServerTemplateCorePath,ServerTemplateGuiPath,ClientTemplatePath
    [int32]$HostSelection = Read-Host "Select ONE of the option above"
    $VMPath = ($Menu[2] | Where-Object {$_.HostName -like $HostName})[$HostSelection].VMPath
    $ServerTemplateCorePath = ($Menu[2] | Where-Object {$_.HostName -like $HostName})[$HostSelection].ServerTemplateCorePath
    $ServerTemplateGuiPath = ($Menu[2] | Where-Object {$_.HostName -like $HostName})[$HostSelection].ServerTemplateGuiPath
    $ClientTemplatePath = ($Menu[2] | Where-Object {$_.HostName -like $HostName})[$HostSelection].ClientTemplatePath
    Clear-Host
    ($Menu[2] | Where-Object {$_.HostName -like $HostName})[$HostSelection] | Format-List HostName,VMPath,ServerTemplateCorePath,ServerTemplateGuiPath,ClientTemplatePath
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
    $TempHost = @{
        HostName = $TempHostName
        VMPath = $TempVMPath
        ServerTemplateCorePath = $TempServerTemplateCorePath
        ServerTemplateGuiPath = $TempServerTemplateGuiPath
        ClientTemplatePath = $TempClientTemplatePath
    }
    $Menu[2] = [array]$Menu[2] + [array]$TempHost
    $Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu.json"
    Start-Sleep -Seconds 1
}

$VMPath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).VMPath
$ServerTemplateCorePath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).ServerTemplateCorePath
$ServerTemplateGuiPath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).ServerTemplateGuiPath
$ClientTemplatePath = ($Menu[2] | Where-Object {$_.HostName -like $HostName}).ClientTemplatePath

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
    $VHD = New-VHD -Path ($VMPath + "\" + $VM.VMName + "\" + $VM.VMName + ".vhdx") -ParentPath $TemplatePath -Differencing

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

$VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"
Write-Verbose "VM Creation Process Completed." -Verbose