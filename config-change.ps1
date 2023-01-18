. .\variables.ps1
Clear-Host
Write-Host -ForegroundColor red "Current Configuration"
$MyConfig = $ConfigFile | Where-Object {$_.HostName -like $HostName}
$MyConfig | Format-List HostName,VMPath,ServerTemplateCorePath,ServerTemplateGuiPath,ClientTemplatePath,JSONTemplateFile,VHDType | Out-Host
