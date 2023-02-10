. .\variables.ps1
Clear-Host
Write-Host -ForegroundColor red "Current Configuration"
$MyConfig = $ConfigFile | Where-Object {$_.HostName -like $HostName}
$MyConfig | Format-List HostName,VMPath,ServerTemplateCorePath,ServerTemplateGuiPath,ClientTemplatePath,JSONTemplateFile,VHDType | Out-Host

function Show-Menu {
    param (
        [string]$Title = "Config Change"
    )
    Write-Host "================ $Title ================"
    
    Write-Host "1: Change VM Path" -ForegroundColor Green
    Write-Host "2: Change SRV (core) Template .VHDX Path" -ForegroundColor Green
    Write-Host "3: Change SRV (GUI) Template .VHDX Path" -ForegroundColor Green
    Write-Host "4: Change CLIENT Template .VHDX Path" -ForegroundColor Green
    Write-Host "5: Change VHD Type (Dynamic/Differencing)" -ForegroundColor Green
    Write-Host "6: Change JSON Template File" -ForegroundColor Green
    Write-Host "B: Back to main menu" -ForegroundColor Green
    Write-Host "Q: To quit" -ForegroundColor Green
}

Show-Menu
$Selection = Read-Host "Select an option"

switch ($Selection) {

    "1" 
    {
        $Option = Read-Host "specify the folder where you want to save VM"
        if ( (Get-Item $Option -ErrorAction SilentlyContinue).Attributes -notlike "Directory" ) {
            Write-Host -ForegroundColor Yellow "[$($Option)] is not a folder!"
        } else {
            $MyConfig.VMPath = $Option
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
        }
    }

    "2" 
    { 
        $Option = Read-Host "specify the path to the .vhdx file for the server template (Core)"
        if (!(Test-Path $Option -ErrorAction SilentlyContinue)) {
            write-host -ForegroundColor Yellow "The file does not exist!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } elseif ((Get-Item $Option -ErrorAction SilentlyContinue).Extension -notlike ".vhdx") {
            Write-Host -ForegroundColor Yellow "Only .vhdx files are accepted!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } else {
            $MyConfig.ServerTemplateCorePath = $Option
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Invoke-Script -ScriptItem ItSelf
            exit
        }

    }

    "3" 
    {  
        $Option = Read-Host "specify the path to the .vhdx file for the server template (GUI)"
        if (!(Test-Path $Option -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Yellow "The file does not exist!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } elseif ((Get-Item $Option -ErrorAction SilentlyContinue).Extension -notlike ".vhdx") {
            Write-Host -ForegroundColor Yellow "Only .vhdx files are accepted!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } else {
            $MyConfig.ServerTemplateGuiPath = $Option
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Invoke-Script -ScriptItem ItSelf
            exit
        }
    }

    "4" 
    {  
        $Option = Read-Host "specify the path to the .vhdx file for the client template"
        if (!(Test-Path $Option -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Yellow "The file does not exist!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } elseif ((Get-Item $Option -ErrorAction SilentlyContinue).Extension -notlike ".vhdx") {
            Write-Host -ForegroundColor Yellow "Only .vhdx files are accepted!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } else {
            $MyConfig.ClientTemplatePath = $Option
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Invoke-Script -ScriptItem ItSelf
            exit
        }
    }

    "5" 
    {
        $VHDTypes = [PSCustomObject]@{ Type = "Differencing" },[PSCustomObject]@{ Type = "Dynamic" }

        $VHDTypes | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Type | Out-Host
        $Option = Read-Host "Select VHD Type option from above (0/1)"
        
        if ($Option -like "b") {
            Invoke-Script -ScriptItem ItSelf -PauseBefore $false
            exit
        }
        
        if ($Option -notmatch "\d") {
            "Only Numbers allowed"
        } elseif ( ($Option -gt ($VHDTypes.Count - 1)) -or ($Option -lt 0) ) {
            Write-Host -ForegroundColor Yellow "Selection Out of index!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } else {
            $MyConfig.VHDType = $VHDTypes[$Option].Type
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Invoke-Script -ScriptItem ItSelf
            exit
        }
    }

    "6" 
    {
        Clear-Host
        Write-Host "Current Template File" 
        Write-Host "$(($ConfigFile | Where-Object {$_.HostName -like $HostName}).JSONTemplateFile)`n" -ForegroundColor Green
        $JSONTemplateList = Get-ChildItem -Path $ConfigFolder | Where-Object {$_.Name -Match ".json$" -and $_.Name -like "*template*"}
        Write-Host -ForegroundColor red "Template Files to Select" -NoNewline
        $JSONTemplateList | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Name | Out-Host
        $TemplateSelection = Read-Host "Select a Template from the list (B for back)"

        if ($TemplateSelection -like "B") {
            Invoke-Script -ScriptItem ItSelf -PauseBefore $false
            exit
        }
        $TemplateSelection = [int32]$TemplateSelection
        if (($JSONTemplateSelection -cle -1) -xor ($JSONTemplateSelection -gt ($JSONTemplateList.Count -1)) ) {
            Write-Host -ForegroundColor Yellow "Wrong option entered!"
            Invoke-Script -ScriptItem ItSelf
        } else {
            ($ConfigFile | Where-Object {$_.HostName -like $HostName}).JSONTemplateFile = ($JSONTemplateList[$TemplateSelection]).FullName
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Write-Host "The template is set to: $(($ConfigFile | Where-Object {$_.HostName -like $HostName}).JSONTemplateFile)" -ForegroundColor green
            Invoke-Script -ScriptItem Main
        }
    }

    "b" { Invoke-Script -ScriptItem Main -PauseBefore $false;exit } 
    
    "e" { exit }

    Default {}
}