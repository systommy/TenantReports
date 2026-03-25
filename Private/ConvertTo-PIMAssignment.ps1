function ConvertTo-PIMAssignment {
    <#
    .SYNOPSIS
        Converts a PIM schedule object to a standardized assignment object.
    .NOTES
        Internal helper for Get-TntPIMReport. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [object]$Schedule,

        [Parameter(Mandatory)]
        [object]$Role,

        [Parameter(Mandatory)]
        [ValidateSet('PIM Eligible', 'PIM Active')]
        [string]$AssignmentType
    )

    $PrincipalType = if ($Schedule.Principal.AdditionalProperties.'@odata.type') {
        $Schedule.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
    } else {
        'Unknown'
    }

    # Get PrincipalName - check direct property first, then AdditionalProperties
    $PrincipalName = $Schedule.Principal.DisplayName
    if (-not $PrincipalName) {
        $PrincipalName = $Schedule.Principal.AdditionalProperties.displayName
    }

    # If still empty, retrieve from Graph API based on principal type
    if (-not $PrincipalName -and $Schedule.PrincipalId) {
        try {
            switch ($PrincipalType) {
                'group' {
                    $Group = Get-MgGroup -GroupId $Schedule.PrincipalId -Property DisplayName -ErrorAction SilentlyContinue
                    $PrincipalName = $Group.DisplayName
                }
                'servicePrincipal' {
                    $ServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Schedule.PrincipalId -Property DisplayName -ErrorAction SilentlyContinue
                    $PrincipalName = $ServicePrincipal.DisplayName
                }
            }
        } catch {
            Write-Verbose "Unable to retrieve name for $PrincipalType $($Schedule.PrincipalId): $($_.Exception.Message)"
        }
    }

    [PSCustomObject]@{
        AssignmentId       = $Schedule.Id
        RoleId             = $Role.Id
        RoleName           = $Role.DisplayName
        RoleType           = if ($Role.IsBuiltIn) { 'Built-in' } else { 'Custom' }
        PrincipalId        = $Schedule.PrincipalId
        PrincipalName      = $PrincipalName
        PrincipalUPN       = $Schedule.Principal.AdditionalProperties.userPrincipalName
        PrincipalType      = $PrincipalType
        AssignmentType     = $AssignmentType
        CreatedDateTime    = $Schedule.CreatedDateTime
        ExpirationDateTime = $Schedule.ScheduleInfo.Expiration.EndDateTime
    }
}