#requires -version 5.1
#requires -module ActiveDirectory

return "This is a walk-through demo file"

# https://github.com/jdhitsolutions/ADTop10Tasks


Clear-Host

#add RSAT Active Directory
# Add-WindowsCapability -name rsat.ActiveDirectory* -online
Get-WindowsCapability -name rsat.ActiveDirectory* -online
Import-Module ActiveDirectory
Get-Command -module ActiveDirectory

#READ THE HELP!!!

#region FSMO

Get-ADDomain

Get-ADForest

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

Get-FSMOHolders

#endregion

#region Empty OU

#use the AD PSDrive
Get-PSDrive AD
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

#the column headings match parameter New-ADUser parameter names
Import-Csv .\100NewUsers.csv | Select-Object -first 1

$secure = ConvertTo-SecureString -String "P@ssw0rdXyZ" -AsPlainText -Force

#I'm not taking error handling for duplicate names into account
$newParams = @{
   ChangePasswordAtLogon = $True
   Path                  = "OU=Imported,OU=Employees,DC=company,DC=pri"
   AccountPassword       = $secure
   Enabled               = $True
   PassThru              = $True
}

Import-Csv .\100NewUsers.csv | New-ADUser @newParams

<#
Get-Aduser -Filter * -SearchBase $newParams.path |
Remove-ADUser -confirm:$false
#>

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
   @{Name = "Location"; Expression = { $_.DistinguishedName.split(",", 2)[1] } },
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

Get-ADGroup @paramhash |
Where-Object { $_.DistinguishedName -notmatch "CN=(Users)|(BuiltIn)" } |
Select-Object DistinguishedName, Name, Modified, ManagedBy

<#
This is the opposite. These are groups with any type of member.
The example is including builtin and default groups.
#>
$data = Get-ADGroup -filter * -Properties Members, Created, Modified |
   Select-Object Name, Description,
   @{Name = "Location"; Expression = { $_.DistinguishedName.split(",", 2)[1] } },
   Group*, Created, Modified,
   @{Name = "MemberCount"; Expression = { $_.Members.count } } |
   Sort-Object MemberCount -Descending

#I renamed properties from Group-Object to make the result easier to understand
$data | Group-Object MemberCount -NoElement |
Select-Object -property @{Name = "TotalNumberOfGroups"; Expression = { $_.count } },
@{Name = "TotalNumberofGroupMembers"; Expression = { $_.Name } }

<#
TotalNumberOfGroups TotalNumberofGroupMembers
------------------- -------------------------
                  1 8
                  1 6
                  1 5
                  2 4
                  6 3
                  3 2
                  9 1
                 40 0
#>

#endregion

#region Enumerate Nested Group Membership

#show nested groups
psedit .\Get-ADNested.ps1

. .\Get-ADNested.ps1

$group = "Master Dev"
Get-ADNested $group | Select-Object Name, Level, ParentGroup, @{Name = "Top"; Expression = { $group } }

#list all group members recursively
Get-ADGroupMember -Identity $group -Recursive | Select-Object Distinguishedname, samAccountName

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

#parameters for Get-ADUser
$params = @{
   filter     = "Enabled -eq 'true'"
   Properties = "PasswordLastSet", "PasswordNeverExpires"
}

#get maximum password age.
#This doesn't take fine tuned password policies into account
$maxDays = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days

#skip user accounts under CN=Users and those with unexpired passwords
Get-ADUser @params |
Where-Object { -Not $_.PasswordExpired -and $_.DistinguishedName -notmatch "CN\=Users" } |
Select-Object DistinguishedName, Name, PasswordLastSet, PasswordNeverExpires,
@{Name = "PasswordAge"; Expression = { (Get-Date) - $_.PasswordLastSet } },
@{Name = "PassExpires"; Expression = { $_.passwordLastSet.addDays($maxDays) } } |
Sort-Object PasswordAge -Descending

#create an html report
psedit .\PasswordReport.ps1

Invoke-Item .\PasswordReport.html

#get an OU
$params = @{
   SearchBase  = "OU=Employees,DC=company,dc=pri"
   FilePath    = ".\employees.html"
   ReportTitle = "Staff Password Report"
   Server      = "SRV4"
   Verbose     = $True
}

.\PasswordReport.ps1 @params | Invoke-Item

#endregion

#region Domain Controller Health

Clear-Host

$dcs = (Get-ADDomain).ReplicaDirectoryServers

#services
#my domain controllers also run DNS
# the legacy way
# Get-Service adws,dns,ntds,kdc -ComputerName $dcs | Select-Object Machinename,Name,Status

$cim = @{
   ClassName    = "Win32_Service"
   filter       = "name='adws' or name='dns' or name='ntds' or name='kdc'"
   ComputerName = $dcs
}
Get-CimInstance @cim | Select-Object SystemName, Name, State

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

#how about a Pester-based health test?

psedit .\ADHealth.tests.ps1

Clear-Host

#make sure I'm using v4.10 of Pester. My test is not compatible with Pester 5.0.
Get-Module Pester | Remove-Module
Import-Module Pester -RequiredVersion 4.10.1 -force

Invoke-Pester .\ADHealth.tests.ps1

#You could automate running the test and taking action on failures

#endregion