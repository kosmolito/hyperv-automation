. .\variables.ps1
$VMList = Get-Content -Path "$PSScriptRoot\$HostName-inventory.json" | ConvertFrom-Json
foreach ($VM in $VMList | Where-Object {$_.isSelected -eq $true}) {
    Write-Verbose "Network Configuration Process Starting..." -Verbose

    if (((get-vm $VM.VMName).State) -like "Off") {
        Write-Verbose "[$($VM.VMName)] is turned off. Starting Machine..." -Verbose
        Start-vm -Name $VM.VMName
    }

    if ($VM.MachineType -like "server") {
        $Credential = $ServerLocalCredential
    } else {
        $Credential = $ClientCredential
    }


    # We wait until PowerShell is working within the guest VM before moving on.
    Write-Verbose "Waiting for PowerShell to start on VM [$($VM.VMName)]" -Verbose
    while ((Invoke-Command -VMName $VM.VMName -Credential $Credential {“Test”} -ea SilentlyContinue) -ne “Test”) {Start-Sleep -Seconds 1}

    Write-Verbose "PowerShell responding on VM [$($VM.VMName)]. Moving On...." -Verbose

    # Changing IP-Subnet-DefGateWay-HostName inside VM // InterfaceAlias can be found by making use of the Get-NetIPAddress Cmdlet
    Invoke-Command -VMName $VM.VMName -Credential $Credential -ScriptBlock {

        $HostName = hostname
        $IPVType = "IPv4" 
        if ($using:VM.IPAddress -notlike "DHCP") {
            # Retrieve the network adapter
            $Netadapter = Get-NetAdapter | Where-Object {$_.Status -eq "up"}
            # Remove existing IP config from the adapter.
                If (($Netadapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
                $Netadapter | Remove-NetIPAddress -AddressFamily $IPVType -Confirm:$false
                }
                If (($Netadapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
                $Netadapter | Remove-NetRoute -AddressFamily $IPVType -Confirm:$false
                }
            # Config of the IP and gateway
            $Netadapter | New-NetIPAddress `
            -AddressFamily $IPVType `
            -IPAddress $using:VM.IPAddress `
            -PrefixLength $using:VM.SubMaskBit `
            -DefaultGateway $using:VM.DefGateway | Out-Null
            # Config the DNS
            $Netadapter | Set-DnsClientServerAddress -ServerAddresses $using:VM.DNSAddress
            Write-Verbose "Ip address for VM [$($using:VM.VMName)] is set to:" -Verbose 
            $Netadapter | Get-NetIPAddress | Select-Object IPv4Address
        }

        # Disabling IPV6
        if (($NetAdapter | Get-NetAdapterBinding -ComponentID "ms_tcpip6").Enabled -eq $true ) {
            $NetAdapter | set-NetAdapterBinding -ComponentID "ms_tcpip6" -Enabled $False
        }

        # If the hostname is not same as in the csv file, change the hostname, otherwise skip the HostName change
        if ($HostName -eq $using:VM.VMName) {
            Write-Verbose "the new name [$($using:VM.VMName)] is the same as the current name [$($HostName)]. Skipping.." -Verbose
        } else {
            Write-Verbose "Updating Hostname for VM [$($using:VM.VMName)]..." -Verbose
            Rename-Computer -NewName $using:VM.VMName -Restart
        }

    }
    Write-Verbose "Network Configuration Completed for VM [$($VM.VMName)]." -Verbose
}
$VMList | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\$HostName-inventory.json"