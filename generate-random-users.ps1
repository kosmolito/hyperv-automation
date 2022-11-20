$RandomNameList = Import-Csv "$PSScriptRoot\random-names.csv"
$UserAmount = Read-Host -Prompt "How many users are to be created?"
$UserPassword = Read-Host -Prompt "Insert the password for the users:"
$RawOU = Read-Host -Prompt "Insert the name of the OUs separated by a comma:"
$OU = $RawOU -split ","
$RAWSecurityGroups = Read-Host -Prompt "Insert security groups separated by a comma:"
$SecurityGroup = $RAWSecurityGroups -split ","
$RandomCsvFilePath = "$PSScriptRoot\example-resource\random-generated-users.csv"

if (test-path ($RandomCsvFilePath)) {
Remove-Item -Path $RandomCsvFilePath
}

for ($i = 0; $i -lt $UserAmount; $i++) {
	$RandomFirstName = Get-Random -Maximum $RandomNameList.Count
	$RandomLastName = Get-Random -Maximum $RandomNameList.Count
	$RandomSecurityGroup = Get-Random -Maximum $SecurityGroup.Count
	$RandomOU = Get-Random -Maximum $OU.Count
		[PsCustomObject]@{
		FirstName = $RandomNameList.FirstName[$RandomFirstName]
		LastName = $RandomNameList.LastName[$RandomLastName]
		UserPassword = $UserPassword
		SecurityGroups = $SecurityGroup[$RandomSecurityGroup]
		OU = $OU[$RandomOU]
		} | Export-Csv -Path $RandomCsvFilePath -Append -Encoding ASCII
	}