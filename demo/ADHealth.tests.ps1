#requires -version 5.1
#requires -Module ActiveDirectory, DNSClient,NetTCPIP

<#

Use Pester to test Active Directory

This test has not been validated to work with Pester 5.x.

This test is designed for the Company.pri domain and should be run
from a domain member under domain admin credentials.

usage: Invoke-Pester ADHealth.tests.ps1
#>

$myDomain = Get-ADDomain
$myforest = Get-ADForest

$DomainControllers = $myDomain.ReplicaDirectoryServers

$GlobalCatalogServers = $myForest.GlobalCatalogs

Write-Host "[$(Get-Date)] Testing $($myDomain.DistinguishedName)" -ForegroundColor DarkGreen -BackgroundColor Gray

Describe Active-Directory {

    Context "Domain" {
        It "Domain Admins should have 3 members" {
            (Get-ADGroupMember -Identity "Domain Admins" | Measure-Object).Count | Should Be 3
        }

        It "Enterprise Admins should have 1 member" {
            (Get-ADGroupMember -Identity "Enterprise Admins" | Measure-Object).Count | Should Be 1
        }

        It "The Administrator account should be enabled" {
            (Get-ADUser -Identity Administrator).Enabled | Should Be $True
        }

        It "The PDC emulator should be $($myDomain.PDCEmulator)" {
            (Get-CimInstance -Class Win32_ComputerSystem -ComputerName $myDomain.PDCEmulator).Roles -contains "Primary_Domain_Controller" | Should Be $True
        }
        It "The default Users container should be CN=Users,$($myDomain.distinguishedname)" {
            $myDomain.usersContainer | Should Be "CN=Users,$($myDomain.distinguishedname)"
        }
    } #context

    Context "Forest" {
        It "The AD Forest functional level should be Window Server 2016" {
            $myforest.Forestmode | Should Be "Windows2016Forest"
        }

        It "Should only have 1 site" {
            $myforest.sites.count | Should Be 1
        }
    } #context

} #describe AD

Foreach ($DC in $DomainControllers) {

    Describe $DC {

        Context Network {
            It "Should respond to a ping" {
                Test-Connection -ComputerName $DC -Count 2 -Quiet | Should Be $True
            }

            #test open ports
            $ports = 53, 389, 445, 5985, 9389
            foreach ($port in $ports) {
                It "Port $port should be open" {
                    (Test-NetConnection -Port $port -ComputerName $DC).TCPTestSucceeded | Should Be $True
                }
            } #foreach port

            #test for GC if necessary
            if ($GlobalCatalogServers -contains $DC) {
                It "Should be a global catalog server" {
                    (Test-NetConnection -Port 3268 -ComputerName $DC).TCPTestSucceeded | Should Be $True
                }
            }

            #DNS name should resolve to same number of domain controllers
            It "should resolve the domain name $env:userdnsdomain" {
                (Resolve-DnsName -Name $env:userdnsdomain -DnsOnly -NoHostsFile -server $domaincontrollers[0] | Measure-Object).Count | Should Be $DomainControllers.count
            }
        } #context

        Context Services {
            $services = "ADWS", "DNS", "Netlogon", "KDC"
            foreach ($service in $services) {
                It "$Service service should be running" {
                    (Get-CimInstance -classname Win32_service -filter "Name='$Service'" -ComputerName $DC).State | Should Be 'Running'
                }
            }

        } #services

        Context Disk {
            $disk = Get-CimInstance -Class Win32_logicaldisk -filter "DeviceID='c:'" -ComputerName $DC
            It "Should have at least 20% free space on C:" {
                ($disk.freespace/$disk.size)*100 | Should BeGreaterThan 20
            }
            $log = Get-CimInstance -Class win32_nteventlogfile -filter "logfilename = 'security'" -ComputerName $DC
            It "Should have at least 10% free space in Security log" {
                ($log.filesize/$log.maxfilesize)*100 | Should BeLessThan 90
            }
        } #disk

        Context Shares {
            $shares = "Netlogon", "sysvol"
            foreach ($share in $shares) {
                It "Should have a share called $share" {
                    Test-Path "\\$DC\$share" | Should Be $True
                }
            } #foreach
            if ((Get-WindowsFeature -computername $DC -Name AD-Certificate).installed) {
                It "Should have a CertEnroll share" {
                    Test-Path "\\$DC\CertEnroll" | Should Be $True
                }
            }
        } #shares
    } #describes

} #foreach

