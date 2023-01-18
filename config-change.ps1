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
        if ( (Get-Item $Option).Attributes -notlike "Directory" ) {
            Write-Error "[$($Option)] is not a folder!"
        } else {
            $MyConfig.VMPath = $Option
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
        }
    }

    "2" 
    { 
        if (!(Test-Path $Option)) {
            Write-Error "The File does not exist!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } elseif ((Get-Item $Option).Extension -notlike ".vhdx") {
            Write-Error "Only .vhdx files are accepted!"
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
        if (!(Test-Path $Option)) {
            Write-Error "The File does not exist!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } elseif ((Get-Item $Option).Extension -notlike ".vhdx") {
            Write-Error "Only .vhdx files are accepted!"
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
        if (!(Test-Path $Option)) {
            Write-Error "The File does not exist!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } elseif ((Get-Item $Option).Extension -notlike ".vhdx") {
            Write-Error "Only .vhdx files are accepted!"
            Invoke-Script -ScriptItem ItSelf
            exit
        } else {
            $MyConfig.ClientTemplatePath = $Option
            $ConfigFile | ConvertTo-Json | Out-File "$ConfigFolder\config.json"
            Invoke-Script -ScriptItem ItSelf
            exit
        }
    }

    Default {}
}