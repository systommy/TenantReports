function Resolve-GraphObjectNames {
    <#
    .SYNOPSIS
        Batch-resolves Microsoft Graph object GUIDs to display names.

    .DESCRIPTION
        Internal helper that eliminates N+1 query patterns by batch-fetching groups,
        service principals, and applications, returning ID-to-DisplayName lookup hashtables.

        For groups and service principals, if the count exceeds BatchSizeThreshold the function
        fetches all objects in a single call and filters locally. Below the threshold it makes
        individual calls (cheaper for small sets).

        Well-known Microsoft application IDs are resolved from a local cache without API calls.

    .PARAMETER GroupIds
        Array of group object IDs to resolve.

    .PARAMETER ServicePrincipalIds
        Array of service principal object IDs to resolve.

    .PARAMETER ApplicationIds
        Array of application (service principal) AppIds to resolve via filter.

    .PARAMETER BatchSizeThreshold
        When object count exceeds this value, fetch all objects instead of individual calls.
        Default: 10

    .OUTPUTS
        System.Management.Automation.PSCustomObject with GroupLookup, SPLookup, AppLookup hashtables.

    .EXAMPLE
        $Resolved = Resolve-GraphObjectNames -GroupIds @($Id1, $Id2)
        $GroupName = $Resolved.GroupLookup[$Id1]

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Internal helper function for batch GUID resolution.

    .LINK
        https://systom.dev
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string[]]$GroupIds,

        [Parameter()]
        [string[]]$ServicePrincipalIds,

        [Parameter()]
        [string[]]$ApplicationIds,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$BatchSizeThreshold = 10
    )

    $GroupLookup = @{}
    $SPLookup    = @{}
    $AppLookup   = @{}

    # Well-known Microsoft application IDs (no API call needed)
    $WellKnownApps = @{
        '00000002-0000-0000-c000-000000000000' = 'Azure AD Graph (Legacy)'
        '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
        '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
        '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        '00000004-0000-0ff1-ce00-000000000000' = 'Office 365 Lync Online'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Service Management'
        'c5393580-f805-4401-95e8-94b7a6ef2fc2' = 'Office 365 Management APIs'
        '0000000c-0000-0000-c000-000000000000' = 'Azure AD'
    }

    # --- Groups ---
    if ($GroupIds -and $GroupIds.Count -gt 0) {
        $UniqueGroupIds = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$GroupIds,
            [StringComparer]::OrdinalIgnoreCase
        )
        Write-Verbose "Resolving $($UniqueGroupIds.Count) group GUIDs..."

        if ($UniqueGroupIds.Count -gt $BatchSizeThreshold) {
            # Batch: fetch all groups, filter locally
            Write-Verbose 'Using batch approach for groups (threshold exceeded)'
            $AllGroups = Get-MgGroup -All -Property Id, DisplayName -ErrorAction SilentlyContinue
            foreach ($Group in $AllGroups) {
                if ($UniqueGroupIds.Contains($Group.Id)) {
                    $GroupLookup[$Group.Id] = $Group.DisplayName
                }
            }
        } else {
            foreach ($GroupId in $UniqueGroupIds) {
                try {
                    $Group = Get-MgGroup -GroupId $GroupId -Property Id, DisplayName -ErrorAction SilentlyContinue
                    if ($Group) { $GroupLookup[$GroupId] = $Group.DisplayName }
                } catch {
                    Write-Verbose "Could not resolve group: $GroupId"
                }
            }
        }
    }

    # --- Service Principals (by object ID) ---
    if ($ServicePrincipalIds -and $ServicePrincipalIds.Count -gt 0) {
        $UniqueSPIds = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$ServicePrincipalIds,
            [StringComparer]::OrdinalIgnoreCase
        )
        Write-Verbose "Resolving $($UniqueSPIds.Count) service principal GUIDs..."

        if ($UniqueSPIds.Count -gt $BatchSizeThreshold) {
            Write-Verbose 'Using batch approach for service principals (threshold exceeded)'
            $AllSPs = Get-MgServicePrincipal -All -Property Id, DisplayName -ErrorAction SilentlyContinue
            foreach ($SP in $AllSPs) {
                if ($UniqueSPIds.Contains($SP.Id)) {
                    $SPLookup[$SP.Id] = $SP.DisplayName
                }
            }
        } else {
            foreach ($SPId in $UniqueSPIds) {
                try {
                    $SP = Get-MgServicePrincipal -ServicePrincipalId $SPId -Property Id, DisplayName -ErrorAction SilentlyContinue
                    if ($SP) { $SPLookup[$SPId] = $SP.DisplayName }
                } catch {
                    Write-Verbose "Could not resolve service principal: $SPId"
                }
            }
        }
    }

    # --- Applications (by AppId, resolved via service principal filter) ---
    if ($ApplicationIds -and $ApplicationIds.Count -gt 0) {
        $UniqueAppIds = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$ApplicationIds,
            [StringComparer]::OrdinalIgnoreCase
        )
        Write-Verbose "Resolving $($UniqueAppIds.Count) application GUIDs..."

        foreach ($AppId in $UniqueAppIds) {
            if ($WellKnownApps.ContainsKey($AppId)) {
                $AppLookup[$AppId] = $WellKnownApps[$AppId]
            } else {
                try {
                    $ServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -Property AppId, DisplayName -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($ServicePrincipal) {
                        $AppLookup[$AppId] = $ServicePrincipal.DisplayName
                    }
                } catch {
                    Write-Verbose "Could not resolve application: $AppId"
                }
            }
        }
    }

    [PSCustomObject]@{
        GroupLookup = $GroupLookup
        SPLookup    = $SPLookup
        AppLookup   = $AppLookup
    }
}
