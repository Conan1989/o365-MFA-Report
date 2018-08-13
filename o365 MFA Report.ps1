#Requires -Modules 'MSOnline'
$ErrorActionPreference = 'Stop'

$OutputFilePath = 'C:\inetpub\example\something.HTML'

$userO365 = 'service.account@your.o365'
$passO365 = Get-Content -Path 'C:\SafePlace\SecureString.txt' | ConvertTo-SecureString
$credO365 = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($userO365, $passO365)

Connect-MsolService -Credential $credO365

# should probably MFA guests too
$allMSOL = Get-MsolUser -All | Where-Object -FilterScript {
  $PSItem.UserType        -ne 'Guest' -and
  $PSItem.BlockCredential -ne $true
}

$tableSummary = New-Object System.Data.DataTable
$tableSummary.Columns.Add('DisplayName', 'String')
$tableSummary.Columns.Add('UPN', 'String')
$tableSummary.Columns.Add('IsLicensed', 'Boolean')
$tableSummary.Columns.Add('MFAState', 'String')
$tableSummary.Columns.Add('DefaultStrongAuthenticationMethodType', 'String')
$tableSummary.Columns.Add('StrongAuthenticationUserDetailsPhoneNumber', 'String')
$tableSummary.Columns.Add('Department', 'String')
$tableSummary.Columns.Add('Office', 'String')

ForEach ($userMSOL in $allMSOL) {
  $row = $tableSummary.NewRow()  
  $row.DisplayName                                = ($userMSOL.DisplayName)
  $row.UPN                                        = ($userMSOL.UserPrincipalName)
  $row.IsLicensed                                 = ($userMSOL.IsLicensed)
  $row.MFAState                                   = ($userMSOL.StrongAuthenticationRequirements.State)
  $row.DefaultStrongAuthenticationMethodType      = ($userMSOL.StrongAuthenticationMethods | Where-Object -FilterScript {$PSItem.IsDefault -eq $true}).MethodType
  $row.StrongAuthenticationUserDetailsPhoneNumber = ($userMSOL.StrongAuthenticationUserDetails.PhoneNumber)
  $row.Department                                 = ($userMSOL.Department)
  $row.Office                                     = ($userMSOL.Office)

  $tableSummary.Rows.Add($row)
}


[string]$htmlSummary = "
<PRE>
Time                 : $((Get-Date).DateTime)
MFA Enabled          : $(($tableSummary | Where-Object -FilterScript {![string]::IsNullOrWhiteSpace($PSItem.DefaultStrongAuthenticationMethodType)}).Count)
MFA Disabled         : $(($tableSummary | Where-Object -FilterScript {[string]::IsNullOrWhiteSpace($PSItem.DefaultStrongAuthenticationMethodType)}).Count)
OneWaySMS            : $(($tableSummary | Where-Object -FilterScript {$PSItem.DefaultStrongAuthenticationMethodType -eq 'OneWaySMS'}).Count)
PhoneAppNotification : $(($tableSummary | Where-Object -FilterScript {$PSItem.DefaultStrongAuthenticationMethodType -eq 'PhoneAppNotification'}).Count)
PhoneAppOTP          : $(($tableSummary | Where-Object -FilterScript {$PSItem.DefaultStrongAuthenticationMethodType -eq 'PhoneAppOTP'}).Count)
TwoWayVoiceMobile    : $(($tableSummary | Where-Object -FilterScript {$PSItem.DefaultStrongAuthenticationMethodType -eq 'TwoWayVoiceMobile'}).Count)
</PRE>
"

$tableSummary | Sort-Object -Property ('Office', 'Department', 'DisplayName') |
  ConvertTo-Html -PreContent $htmlSummary -Title 'o365 MFA Status' -Property ('DisplayName', 'UPN', 'IsLicensed', 'MFAState', 'DefaultStrongAuthenticationMethodType', 'Department', 'Office') |
  Out-File -FilePath $OutputFilePath -Force -Encoding utf8


# to do
# if DefaultStrongAuthenticationMethodType ne $null; enforce MFA
# https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates


