#requires -version 5.1
#requires -module ActiveDirectory

Function Get-ADNested {
    [cmdletbinding()]
    [Outputtype("Microsoft.ActiveDirectory.Management.ADPrincipal")]
    Param(
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            HelpMessage = "Enter the name of an Active Directory group."
        )]
        [string]$Identity,
        [int]$Level = 0
    )

    Begin {
        Write-Verbose "Starting $($myinvocation.MyCommand) at level $level"
    }
    Process {
        Write-Verbose "Getting nested group membership for $identity"
        Try {
            Write-Verbose "Calling Get-ADGroupMember"
            $out = Get-ADGroupMember -Identity $Identity -ErrorAction Stop |
            Where-Object { $_.objectClass -eq 'Group' }
        }
        Catch {
            Write-Error $_
        }
        if ($out) {
            #add properties to the groups to indicate their parent
            #and what level
            Write-Verbose "Adding additional properties $($out.name)"
            $Level++
            $out | Add-Member -MemberType NoteProperty -Name ParentGroup -Value $identity -Force
            $out | Add-Member -MemberType NoteProperty -Name Level -Value $Level -Force
            $out

            #recursively call the function
            Write-Verbose "Calling Get-ADNested"
            $out | Get-ADNested -Level $level

        } #if $out
    } #Process

    End {
        Write-Verbose "Ending $($myinvocation.MyCommand)"
    }
} #end function

<#
Sample

$group = "Chicago Sales Staff"

Get-ADNested $group | Select Name,Level,ParentGroup,@{Name="Master";Expression={$group}}

Name                                  Level ParentGroup           Master
----                                  ----- -----------           ------
Chicago Sales Users                       1 Chicago Sales Staff   Chicago Sales Staff
Chicago Sales Mana...                     1 Chicago Sales Staff   Chicago Sales Staff
Chicago Sales Interns                     2 CN=Chicago Sales U... Chicago Sales Staff
EmptyGroup                                3 CN=Chicago Sales I... Chicago Sales Staff

#>



