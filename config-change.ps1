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
