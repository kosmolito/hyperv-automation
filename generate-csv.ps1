$FirstName = Get-Content first-names.txt
$LastName = Get-Content last-names.txt
$howmany = Read-Host -Prompt "How many users are to be created?"
$UserPassword = Read-Host -Prompt "Insert the password for the users:"
$RAWOU = Read-Host -Prompt "Insert the name of the OUs separated by comma:"
$OU = $RAWOU -split ","
$RAWSecurityGroups = Read-Host -Prompt "Insert security groups separated by a comma:"
$SecurityGroup = $RAWSecurityGroups -split ","

Remove-Item -Path generated.csv
Add-Content -Path generated.csv -Value '"FirstName","LastName","UserPassword","SecurityGroups","OU"'

for ($i = 0; $i -lt $howmany; $i++)
{
	$firstrandom = Get-Random -Maximum $FirstName.Count
	$lastrandom = Get-Random -Maximum $LastName.Count
	$secrandom = Get-Random -Maximum $SecurityGroup.Count
	$ourandom = Get-Random -Maximum $OU.Count
	##Write-Host ("firstname=" + $FirstName[$firstrandom] + " lastname=" + $LastName[$lastrandom] + " userpassword=" + $UserPassword + " securitygroup=" + $SecurityGroup[$secrandom] + " ou=" + $OU)
	[PsCustomObject]@{
		FirstName = $FirstName[$firstrandom]
		LastName = $LastName[$lastrandom]
		UserPassword = $UserPassword
		SecurityGroups = $SecurityGroup[$secrandom]
		OU = $OU[$ourandom]
	} | Export-Csv -Path generated.csv -Append -Encoding ASCII 
}