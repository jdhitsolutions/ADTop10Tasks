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
Param([string]$Domain=(Get-ADDomain).DistinguishedName)

$ADDomain = Get-ADDomain -Identity $Domain 
$ADForest = $ADDomain | Get-ADForest
[PSCustomObject]@{
Domain=$ADDomain.Name
Forest=$ADForest.Name
PDCEmulator=$ADDomain.PDCEmulator
RIDMaster=$ADDomain.RIDMaster
InfrastructureMaster=$ADdomain.InfrastructureMaster
SchemaMaster=$ADForest.SchemaMaster
DomainNamingMaster=$ADForest.DomainNamingMaster
}


} #end Get-FSMOHolders

#endregion

#region Empty OU

#use the AD PSDrive
 dir 'AD:\DC=Company,DC=Pri'
 
 Get-ADOrganizationalUnit -Filter * | 
 ForEach-Object { 
 $ouPath = Join-Path -path "AD:\" -ChildPath $_.distinguishedName
 $test = Get-Childitem -path $ouPath -Recurse | Where-Object ObjectClass -ne 'organizationalunit'
 if (-Not $Test) {
    $_.distinguishedname
 }
 }

#endregion

#region Create new users


#parameters to splat to New-ADUser
$params=@{
Name="Thomas Anderson"
DisplayName="Thomas Anderson"
SamAccountName="tanderson"
UserPrincipalName="tanderson@company.com"
PassThru=$True
GivenName="Tom"
Surname="Anderson"
Description="the one"
Title="Senior Web Developer"
Department="IT"
AccountPassword = (ConvertTo-SecureString -String "P@ssw0rd" -Force -AsPlainText)
Path= "OU=IT,DC=Company,DC=Pri"
Enabled=$True
}

#splat the hashtable
New-ADUser @params

# remove-aduser -Identity tanderson

#import

Import-csv .\100NewUsers.csv | Select -first 1
$secure = ConvertTo-SecureString -String "P@ssw0rdXyZ" -AsPlainText -Force

#I'm not taking error handling for duplicate names into account
$newParams = @{
changePasswordAtLogon = $True 
path = "OU=Imported,OU=Employees,DC=company,DC=pri" 
accountpassword = $secure 
Enabled = $True 
PassThru = $True
}
Import-CSV .\100NewUsers.csv | New-ADUser @newParams

# Get-aduser -Filter * -SearchBase $newParams.path | Remove-ADUser -confirm:$false -WhatIf

#endregion

#region Find inactive user accounts

#this demo is only getting the first 10
$paramHash = @{
 AccountInactive = $True
 Timespan = (New-Timespan -Days 120)
 SearchBase = "OU=Employees,DC=company,DC=pri"
 UsersOnly = $True
 ResultSetSize = "10"
}

Search-ADAccount @paramHash | Select-Object Name,LastLogonDate,SamAccountName,DistinguishedName

#endregion

#region Find inactive computer accounts

Search-ADAccount -ComputersOnly -AccountInactive

#endregion

#region Find empty groups

#can't use -match in the filter
$paramHash = @{
 filter = "Members -notlike '*'"
 Properties = "Members","Created","Modified","ManagedBy"
 SearchBase = "DC=company,DC=pri"
}

Get-ADGroup @paramHash |
Select-Object Name,Description,
@{Name="Location";Expression={$_.DistinguishedName.split(",",2)[1]}},
Group*,Modified,ManagedBy |
Sort-Object Location |
Format-Table -GroupBy Location -Property Name,Description,Group*,Modified,ManagedBy

#filter out User and Builtin
#can't seem to filter on DistinguishedName
$paramHash = @{
 filter = "Members -notlike '*'"
 Properties = "Members","Modified","ManagedBy"
 SearchBase = "DC=company,DC=pri"
}

Get-ADGroup @paramhash  | Where-object {$_.DistinguishedName -notmatch "CN=(Users)|(BuiltIn)"} |
Select-object DistinguishedName,Name,Modified,ManagedBy

#kinda the opposite
#getting groups members report
#these are groups with any type of member
$data = Get-ADGroup -filter * -Properties Members,Created,Modified |
Select Name,Description,
@{Name="Location";Expression={$_.DistinguishedName.split(",",2)[1]}},
Group*,Created,Modified,
@{Name="MemberCount";Expression={$_.Members.count}} |
Sort MemberCount -Descending

$data | Group-Object MemberCount

#endregion

#region Enumerate Nested Group Membership

#show nested groups
psedit .\get-adnested.ps1

$group = "Master Dev"
Get-ADNested $group | Select-Object Name,Level,ParentGroup,@{Name="Top";Expression={$group}}

#list allmembers
Get-ADGroupMember -Identity $group -Recursive | 
Select-Object Distinguishedname,samAccountName

#endregion

#region List User Group Memberships

$roy = Get-ADUser -Identity "rgbiv" -Properties *

#this only shows direct membership
$roy.MemberOf

psedit .\Get-ADMemberOf.ps1

. .\Get-ADMemberOf.ps1

$roy | Get-ADMemberOf -verbose | Select-Object Name,DistinguishedName -Unique

#endregion

#region Password Age Report

$ReportTitle = "Password Age Report"
#this must be left justified        
$head = @"
<Title>$ReportTitle</Title>
<style>
body { background-color:#FFFFFF;
       font-family:Tahoma;
       font-size:12pt; }
td, th { border:1px solid black; 
         border-collapse:collapse; }
th { color:white;
     background-color:black; }
table, tr, td, th { padding: 2px; margin: 0px }
tr:nth-child(odd) {background-color: lightgray}
table { width:95%;margin-left:5px; margin-bottom:20px;}
</style>
<br>
<H1>$ReportTitle</H1>
"@

Get-Aduser @paramHash | Where {-Not $_.PasswordExpired} |
Select DistinguishedName,Name,PasswordLastSet,
@{Name="PasswordAge";Expression={(Get-date) - $_.PasswordLastSet}},
@{Name="PassExpires";Expression={$_.passwordLastSet.addDays($maxDays)}} |
Sort PasswordAge -Descending |
ConvertTo-Html -Title $ReportTitle -Head $head |
Out-File c:\work\PasswordAgeReport.htm -Encoding ascii

invoke-item c:\work\passwordagereport.htm

#endregion

#region Domain Controller Health

$dcs = (Get-ADDomain).ReplicaDirectoryServers

#services
#my domain controllers also run DNS
get-service adws,dns -ComputerName $dcs | Select Machinename,Name,Status

#eventlog
get-eventlog -list -computername chi-dc04

#remoting speeds this up
$data = Invoke-Command {
Get-eventlog -LogName 'Active Directory Web Services' -EntryType Error,Warning -Newest 10 
} -computer $dcs

$data | sort PSComputername,TimeGenerated -Descending |
Format-Table -GroupBy PSComputername -Property TimeGenerated,EventID,Message -wrap

#or create an HTML report
$ReportTitle = "ADWS Log Report"

#the here string must be left justified        
$head = @"
<Title>$ReportTitle</Title>
<style>
body { background-color:#FFFFFF;
       font-family:Tahoma;
       font-size:12pt; }
td, th { border:1px solid black; 
         border-collapse:collapse; }
th { color:white;
     background-color:black; }
table, tr, td, th { padding: 2px; margin: 0px }
tr:nth-child(odd) {background-color: lightgray}
table { width:95%;margin-left:5px; margin-bottom:20px;}
</style>
<br>
<H1>$ReportTitle</H1>
"@

#create fragments for each domain controller
$grouped = $data | Group PSComputername -AsHashTable

#initialize an array to hold html fragments
$fragments=@()

$grouped.GetEnumerator() | Foreach {
$DC = $_.name.ToUpper()
$fragments+= $_.value | Select TimeGenerated,EventID,EntryType,Message | 
ConvertTo-Html -Fragment -PreContent "<H3>$DC</H3>"
}

ConvertTo-Html -Title $ReportTitle -Head $head -Body $fragments -PostContent "<h6><I>$(Get-Date)</I></h6>" |
Out-File c:\work\adlog.htm -Encoding ascii

invoke-item c:\work\adlog.htm

#checking NTDS

invoke-command {dir c:\windows\ntds } -computername $dcs |
Select PSComputername,LastWriteTime,Length,Name |
Out-GridView -Title "NTDS Files"

#endregion