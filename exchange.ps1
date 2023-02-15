. .\Variables.ps1
Clear-Host
$VM = $VMList | Where-Object {$_.isSelected -eq $true -and $_.Roles -contains "Exchange"}
