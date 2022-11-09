. .\Variables.ps1
foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {
    Write-Verbose "Starting VM Creation Process...." -Verbose
    switch ($HostName) {

        "DESKWIN10PRO"
        {
            $VMPath = "C:\hyper-v"
            if ($VM.MachineType -like "server") {
                if ($VM.Core -like "yes") { $TemplatePath = "D:\hyper-v\TEMPLATES\sysprep-srv19-core.vhdx" } 
                else { $TemplatePath = "D:\hyper-v\TEMPLATES\sysprep-srv19.vhdx"}
            } else { $TemplatePath = "D:\hyper-v\TEMPLATES\sysprep-win10pro.vhdx" }
        }
        "pc"
        {
            $VMPath = "D:\hyper-v"
            if ($VM.MachineType -like "server") {
                if ($VM.Core -like "yes") { $TemplatePath = "D:\hyper-v\TEMPLATES\srv-19\sysprep-srv19-core.vhdx" } 
                else { $TemplatePath = "D:\hyper-v\TEMPLATES\srv-19\sysprep-srv19.vhdx"}
            } else { $TemplatePath = "D:\hyper-v\TEMPLATES\win-10-pro\sysprep_win10pro.vhdx" }
        }

        default 
        {
            Write-Host -ForegroundColor red "cannot locate Path and Templates. Exiting!"
        }
    }

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