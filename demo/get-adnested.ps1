#requires -version 5.1
#requires -module ActiveDirectory

Function Get-ADNested {
    [cmdletbinding()]

    Param(
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline
        )]
        [string]$Identity,
        [int]$Level = 0
    )

    Begin {
        Write-Verbose "Starting $($myinvocation.MyCommand)"
    }
    Process {
        Write-Verbose $identity
        Try {
        $out = Get-ADGroupMember -Identity $Identity -ErrorAction Stop |
        Where-Object {$_.objectClass -eq 'Group'}
        }
        Catch {
            Write-Error $_
        }
        if ($out) {
            #add properties to the groups to indicate their parent
            #and what level
            $Level++
            $out | Add-Member -MemberType NoteProperty -Name ParentGroup -Value $identity -Force
            $out | Add-Member -MemberType NoteProperty -Name Level -Value $Level -Force
            $out

            #recursively call the function
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



