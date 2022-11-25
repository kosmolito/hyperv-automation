$RandomNameList = Import-Csv "$PSScriptRoot\example-resource\random-names.csv"
[ValidateRange(1, 500)]$UserAmount = Read-Host -Prompt "How many users are to be created? (Max 500)"
$DomainName = Read-Host -Prompt "Insert the UPN/Domain eg. mstile.se"
$UserPassword = Read-Host -Prompt "Insert the password for the users" -MaskInput
$RAWGeneralSecurityGroup = Read-Host -Prompt "Insert general security group name, eg. Public"
$RAWSecurityGroups = Read-Host -Prompt "Insert other security groups separated by a comma, eg. Sales,Ekonomi"
$SecurityGroup = $RAWSecurityGroups.split(",")
$RawOU = Read-Host -Prompt "Insert the name of the OUs separated by a comma eg. site1_users,site2_users"
$OU = $RawOU.split(",")

$RandomCsvFilePath = "$PSScriptRoot\random-generated-users.csv"
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
		DomainName = $DomainName
		UserPassword = $UserPassword
		SecurityGroups = "SEC_$($RAWGeneralSecurityGroup)" + "," + "SEC_$($SecurityGroup[$RandomSecurityGroup])"
		OU = $OU[$RandomOU]
		} | Export-Csv -Path $RandomCsvFilePath -Append -Encoding ASCII
	$UserList = import-csv -Path $RandomCsvFilePath
	}
$UserList = Import-Csv -Path $RandomCsvFilePath