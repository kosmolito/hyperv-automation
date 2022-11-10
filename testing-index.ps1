# $Menu = "From TEMPLATE FILE","Interactive Mode"

# $Menu | format-table
# $MenuSelection = Read-Host "Please select ONE of the option"

# "AD-Domain-Services",
# "DNS",
# "DHCP",
# "DirectAccess-VPN"

# $TempVM = @{
#     VMName = [string]"AD01"
#     VMId = [string]""
#     CreationTime = ""
#     DeletionTime = ""
#     isCore = $false
#     MachineType = [string]"server"
#     Roles = [array]
#     HasJoinedDomain = $false
#     Path = [string]""
#     HardDrives = [array]""
#     NonOSHardDrivs = [array]""
#     ComputerName = [string]""
#     ProcessorCount = [int32]2
#     MemoryStartup = 2147483648
#     MemoryMinimum = 2147483648
#     MemoryMaximum = 4294967296
#     CheckpointType = [int32]2
#     NetworkSwitches = [array]"pfLAN1"
#     IPAddress = [string]"192.168.10.10"
#     DefGateway = [string]"192.168.10.1"
#     DNSAddress = [array]"127.0.0.1"
#     SubMaskBit = "24"
#     isSelected = $true
#   }





# switch ($MenuSelection) {
#     "0" {  }
#     "1" 
#     {
#         $MenuSelection = Read-Host "What Type of Machines server/client"
#         $TempVM.MachineType = $MenuSelection
#         $TempVM.MachineType | Out-Host
#         $MenuSelection = Read-Host "Amount of server machines"
#         $MenuSelection = Read-Host "Will the server(s) have GUI? default (yes)"
#         $MenuSelection = Read-Host "Name of server(s) separated by coma (,)"
#         $MenuSelection = Read-Host "Amount of client machines"




#     }
# }

$Menu = Get-Content -Path "$PSScriptRoot\menu copy.json" | ConvertFrom-Json
$HostName = "DESKWIN10PRO11"

# $VM = @{
#     VMPath = ""

# }

# If the HostName matches the items in menu.json file, take these file/folder information for VM and Template Path
if (($menu[2].Hostname -match $HostName).count -eq 1) {
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
}

else {
    Write-Host -ForegroundColor red "Cannot find VM Path or Template Path"
    $TempHostName = $HostName
    $TempVMPath = Read-Host "Enter the path where you want to store your VM"
    while (!(test-path ($TempVMPath))) {
        Write-Host -ForegroundColor red "The folder does not exist!"
        $TempVMPath = Read-Host "Enter the path where you want to store your VM"
    }

    $TempServerTemplateCorePath = Read-Host "Enter .vhdx TEMPLATE path for server19 CORE (Enter for none)"
    while (!(test-path ($TempVMPath)) -or $TempServerTemplateCorePath -notlike "" ) {
        Write-Host -ForegroundColor red "The file does not exist!"
        $TempServerTemplateCorePath = Read-Host "Enter .vhdx TEMPLATE path for server19 CORE (Enter for none)"
    }

    $TempServerTemplateGuiPath = Read-Host "Enter .vhdx TEMPLATE path for server19 Desktop Experience (Enter for none)"
    while (!(test-path ($TempVMPath)) -or $TempServerTemplateGuiPath -notlike "" ) {
        Write-Host -ForegroundColor red "The file does not exist!"
        $TempServerTemplateGuiPath = Read-Host "Enter .vhdx TEMPLATE path for server19 Desktop Experience (Enter for none)"
    }

    $TempClientTemplatePath = Read-Host "Enter .vhdx TEMPLATE path for Windows 10 (Enter for none)"
    while (!(test-path ($TempVMPath)) -or $TempClientTemplatePath -notlike "" ) {
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
    Write-Host -ForegroundColor red "Before"
    $Menu[2]
    Write-Host -ForegroundColor red "After"
    $Menu[2] = [array]$Menu[2] + [array]$TempHost
    $Menu | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\menu copy.json"
}

# switch ($HostName) {

#     "DESKWIN10PRO"
#     {
#         $VMPath = "C:\hyper-v"
#         if ($VM.MachineType -like "server") {
#             if ($VM.Core -like "yes") { $TemplatePath = "D:\hyper-v\TEMPLATES\sysprep-srv19-core.vhdx" } 
#             else { $TemplatePath = "D:\hyper-v\TEMPLATES\sysprep-srv19.vhdx"}
#         } else { $TemplatePath = "D:\hyper-v\TEMPLATES\sysprep-win10pro.vhdx" }
#     }
#     "pc"
#     {
#         $VMPath = "D:\hyper-v"
#         if ($VM.MachineType -like "server") {
#             if ($VM.Core -like "yes") { $TemplatePath = "D:\hyper-v\TEMPLATES\srv-19\sysprep-srv19-core.vhdx" } 
#             else { $TemplatePath = "D:\hyper-v\TEMPLATES\srv-19\sysprep-srv19.vhdx"}
#         } else { $TemplatePath = "D:\hyper-v\TEMPLATES\win-10-pro\sysprep_win10pro.vhdx" }
#     }

#     default 
#     {
#         Write-Host -ForegroundColor red "cannot locate Path and Templates. Exiting!"
#     }
# }