#requires -version 5.1
#requires -module ActiveDirectory

return "This is a walk-through demo file"

#add RSAT Active Directory
Add-WindowsCapability -name rsat.ActiveDirectory* -online
Import-Module ActiveDirectory
Get-Command -module ActiveDirectory
#READ THE HELP!!!

#region FSMO
Function Get-FSMOHolders {
   [cmdletbinding()]
   Param([string]$Domain = (Get-ADDomain).DistinguishedName)

   $ADDomain = Get-ADDomain -Identity $Domain
   $ADForest = $ADDomain | Get-ADForest
   [PSCustomObject]@{
      Domain               = $ADDomain.Name
      Forest               = $ADForest.Name
      PDCEmulator          = $ADDomain.PDCEmulator
      RIDMaster            = $ADDomain.RIDMaster
      InfrastructureMaster = $ADdomain.InfrastructureMaster
      SchemaMaster         = $ADForest.SchemaMaster
      DomainNamingMaster   = $ADForest.DomainNamingMaster
   }
} #end Get-FSMOHolders

#endregion

#region Empty OU

#use the AD PSDrive
Get-ChildItem 'AD:\DC=Company,DC=Pri'

Get-ADOrganizationalUnit -Filter * |
ForEach-Object {
   $ouPath = Join-Path -path "AD:\" -ChildPath $_.distinguishedName
   $test = Get-ChildItem -path $ouPath -Recurse |
   Where-Object ObjectClass -ne 'organizationalunit'
   if (-Not $Test) {
      $_.distinguishedname
   }
}

#endregion

#region Create new users

#parameters to splat to New-ADUser
$params = @{
   Name              = "Thomas Anderson"
   DisplayName       = "Thomas Anderson"
   SamAccountName    = "tanderson"
   UserPrincipalName = "tanderson@company.com"
   PassThru          = $True
   GivenName         = "Tom"
   Surname           = "Anderson"
   Description       = "the one"
   Title             = "Senior Web Developer"
   Department        = "IT"
   AccountPassword   = (ConvertTo-SecureString -String "P@ssw0rd" -Force -AsPlainText)
   Path              = "OU=IT,DC=Company,DC=Pri"
   Enabled           = $True
}

#splat the hashtable
New-ADUser @params

# remove-aduser -Identity tanderson

#import

Import-Csv .\100NewUsers.csv | Select-Object -first 1
$secure = ConvertTo-SecureString -String "P@ssw0rdXyZ" -AsPlainText -Force

#I'm not taking error handling for duplicate names into account
$newParams = @{
   changePasswordAtLogon = $True
   path                  = "OU=Imported,OU=Employees,DC=company,DC=pri"
   accountpassword       = $secure
   Enabled               = $True
   PassThru              = $True
}
Import-Csv .\100NewUsers.csv | New-ADUser @newParams

# Get-Aduser -Filter * -SearchBase $newParams.path | Remove-ADUser -confirm:$false

#endregion

#region Find inactive user accounts

#this demo is only getting the first 10 accounts
$paramHash = @{
   AccountInactive = $True
   Timespan        = (New-TimeSpan -Days 120)
   SearchBase      = "OU=Employees,DC=company,DC=pri"
   UsersOnly       = $True
   ResultSetSize   = "10"
}

Search-ADAccount @paramHash | Select-Object Name, LastLogonDate, SamAccountName, DistinguishedName

#endregion

#region Find inactive computer accounts

#definitely look at help for this command

Search-ADAccount -ComputersOnly -AccountInactive

#endregion

#region Find empty groups

#can't use -match in the filter
$paramHash = @{
   filter     = "Members -notlike '*'"
   Properties = "Members", "Created", "Modified", "ManagedBy"
   SearchBase = "DC=company,DC=pri"
}

Get-ADGroup @paramHash |
Select-Object Name, Description,
@{Name = "Location"; Expression = {$_.DistinguishedName.split(",", 2)[1]}},
Group*, Modified, ManagedBy |
Sort-Object Location |
Format-Table -GroupBy Location -Property Name, Description, Group*, Modified, ManagedBy

#filter out User and Builtin
#can't seem to filter on DistinguishedName
$paramHash = @{
   filter     = "Members -notlike '*'"
   Properties = "Members", "Modified", "ManagedBy"
   SearchBase = "DC=company,DC=pri"
}

Get-ADGroup @paramhash | Where-Object {$_.DistinguishedName -notmatch "CN=(Users)|(BuiltIn)"} |
Select-Object DistinguishedName, Name, Modified, ManagedBy

<#
This is kinda the opposite. These are groups with any type of member
#>
$data = Get-ADGroup -filter * -Properties Members, Created, Modified |
Select-Object Name, Description,
@{Name = "Location"; Expression = {$_.DistinguishedName.split(",", 2)[1]}},
Group*, Created, Modified,
@{Name = "MemberCount"; Expression = {$_.Members.count}} |
Sort-Object MemberCount -Descending

$data | Group-Object MemberCount

#endregion

#region Enumerate Nested Group Membership

#show nested groups
psedit .\get-adnested.ps1

$group = "Master Dev"
Get-ADNested $group | Select-Object Name, Level, ParentGroup, @{Name = "Top"; Expression = {$group}}

#list allmembers
Get-ADGroupMember -Identity $group -Recursive |
Select-Object Distinguishedname, samAccountName

#endregion

#region List User Group Memberships

$roy = Get-ADUser -Identity "rgbiv" -Properties *

#this only shows direct membership
$roy.MemberOf

psedit .\Get-ADMemberOf.ps1

. .\Get-ADMemberOf.ps1

$roy | Get-ADMemberOf -verbose | Select-Object Name, DistinguishedName -Unique

#endregion

#region Password Age Report

$params = @{
   filter     = "Enabled -eq 'true'"
   Properties = "PasswordLastSet", "PasswordNeverExpires"
}

#get maximum password age.
#This doesn't take fine tuned password policies into account
$maxDays = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days

#skip user accounts under CN=Users
Get-ADUser @params |
Where-Object {-Not $_.PasswordExpired -and $_.DistinguishedName -notmatch "CN\=Users"} |
Select-Object DistinguishedName, Name, PasswordLastSet, PasswordNeverExpires,
@{Name = "PasswordAge"; Expression = {(Get-Date) - $_.PasswordLastSet}},
@{Name = "PassExpires"; Expression = {$_.passwordLastSet.addDays($maxDays)}} |
Sort-Object PasswordAge -Descending

#create an html report
psedit .\PasswordReport.ps1

Invoke-Item .\PasswordReport.htm

#endregion

#region Domain Controller Health

$dcs = (Get-ADDomain).ReplicaDirectoryServers

#services
#my domain controllers also run DNS
# the legacy way
# Get-Service adws,dns,ntds,kdc -ComputerName $dcs | Select-Object Machinename,Name,Status

Get-CimInstance -ClassName Win32_Service -filter "name='adws' or name='dns' or name='ntds' or name='kdc'" -ComputerName $dcs |
Select-Object SystemName, Name, State

#eventlog
Get-EventLog -list -computername DOM1

#remoting speeds this up
$data = Invoke-Command {
   #ignore errors if nothing is found
   Get-EventLog -LogName 'Active Directory Web Services' -EntryType Error, Warning -Newest 10 -ErrorAction SilentlyContinue
} -computer $dcs

<# demo alternative

$data = Invoke-Command {
Get-EventLog -LogName 'Active Directory Web Services' -Newest 10
} -computer $dcs

#>

#formatted in the console
$data | Sort-Object PSComputername, TimeGenerated -Descending |
Format-Table -GroupBy PSComputername -Property TimeGenerated, EventID, Message -wrap

#how about a Pester-base health test?

psedit .\ADHealth.tests.ps1

Invoke-Pester .\ADHealth.tests.ps1

#endregion