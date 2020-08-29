#requires -version 5.1
#requires -module ActiveDirectory

#This has not been tested against a very large number of user accounts

[cmdletbinding()]
Param(
    [Parameter(HelpMessage = "Specify the distinguished name of container like OU=Employees,DC=Company,DC=pri. The default is the entire domain.")]
    [string]$SearchBase,
    [ValidateNotNullorEmpty()]
    [string]$ReportTitle = "Password Age Report",
    [ValidateNotNullorEmpty()]
    [string]$FilePath = "PasswordReport.html",
    [PSCredential]$Credential,
    [alias("dc")]
    [string]$Server
)

Write-Verbose "Starting $($MyInvocation.MyCommand)"
Write-Host "Building password report...please wait." -ForegroundColor yellow

$UserParams = @{
    filter     = "Enabled -eq 'true'"
    Properties = "PasswordLastSet", "PasswordNeverExpires"
}

#this could be set from a parameter value, or derived using Get-ADDomain
$pwParams = @{
    identity = "company.pri"
}

if ($SearchBase) {
    Write-Verbose "Searching $searchbase"
    $UserParams.add("SearchBase", $SearchBase)
}
if ($Server) {
    Write-Verbose "Querying domain controller $server"
    $UserParams.add("Server", $Server)
    $pwParams.Add("Server", $Server)
}

if ($Credential) {
    Write-Verbose "Connecting as $($Credential.UserName)"
    $UserParams.add("Credential", $Credential)
    $pwParams.add("Credential", $Credential)
}

Write-Verbose "Getting max password age"
#get maximum password age.
#This doesn't take fine-tuned password policies into account
$maxDays = (Get-ADDefaultDomainPasswordPolicy @pwParams -OutVariable ad).MaxPasswordAge.Days

Write-Verbose "...$maxdays"

#convert the data into XML to add a class attribute so that
#accounts with non-expiring passwords stand out
Write-Verbose "Getting AD User information"
[xml]$html = Get-ADUser @userparams |
Where-Object {-Not $_.PasswordExpired -and $_.DistinguishedName -notmatch "CN\=Users"} |
Select-Object -property DistinguishedName, Name, PasswordLastSet, PasswordNeverExpires,
@{Name = "PasswordAge"; Expression = {(Get-Date) - $_.PasswordLastSet}},
@{Name = "PassExpires"; Expression = {$_.passwordLastSet.addDays($maxDays)}} |
Sort-Object PasswordAge -Descending | ConvertTo-Html -Fragment

Write-Verbose "Processing data"
for ($i = 1; $i -lt $html.table.tr.count; $i++) {
    if ($html.table.tr[$i].td[3] -eq "True") {
        $html.table.tr[$i].ChildNodes[3].SetAttribute("class", "alert")
    }
}

$head = @"
<Title>$ReportTitle</Title>
<style>
body { background-color:#FFFFFF;
       font-family:Tahoma;
       font-size:12pt;
    }
td, th { border:1px solid black;
         border-collapse:collapse;
        }
th { color:white;
     background-color:black;
    }
table, tr, td, th {
    padding: 2px;
    margin: 0px
}
tr:nth-child(odd) {background-color: lightgray}
table {
    width:95%;
    margin-left:5px;
    margin-bottom:20px;
    }
.footer {
    font-size:10pt;
    color:green;
    font-style:italic;
}
.alert { color:red; }
</style>
<br>
<H1>$ReportTitle</H1>
"@

$foot = @"
<p> User accounts with no password values need to change their password at next logon.</p>
<p class='footer'>Report run $(Get-Date) by $($env:userdomain)\$($env:username)</p>
"@

if ($SearchBase) {
    $search = "<h3>$SearchBase</h3>"
}
else {
 $search = "<h3>$($ad.distinguishedname)</h3>"
}
$body =@"
$search

$($html.InnerXml)
"@
$convert = @{
    Title       = $ReportTitle
    Head        = $head
    PostContent = $foot
    Body        = $body #$html.innerxml
}

Write-Verbose "Creating HTML file $filepath"
ConvertTo-Html @convert | Out-File -filepath $FilePath -Encoding utf8

Get-Item -Path $filepath

Write-Verbose "Finished $($myinvocation.MyCommand)"