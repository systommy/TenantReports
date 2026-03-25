function Resolve-InteractiveContext {
    <#
    .SYNOPSIS
        Resolves TenantId and ClientId from an active MgGraph connection when using Interactive authentication.

    .DESCRIPTION
        This internal helper function ensures TenantId and ClientId variables are populated when using
        Interactive authentication. In Interactive mode, these values aren't provided by the user but
        are needed for cache keys, report metadata, and other internal operations.

        The function returns a hashtable with TenantId and ClientId values, either from the provided
        parameters or from the active MgGraph context.

    .PARAMETER TenantId
        The TenantId parameter from the calling function. May be empty in Interactive mode.

    .PARAMETER ClientId
        The ClientId parameter from the calling function. May be empty in Interactive mode.

    .PARAMETER ConnectionInfo
        The connection state object returned by Connect-TntGraphSession.

    .EXAMPLE
        $Context = Resolve-InteractiveContext -TenantId $TenantId -ClientId $ClientId -ConnectionInfo $ConnectionInfo
        $TenantId = $Context.TenantId
        $ClientId = $Context.ClientId

    .OUTPUTS
        Hashtable with TenantId and ClientId keys.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        This is an internal helper function for the TenantReports module.

    .LINK
        https://systom.dev
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [AllowEmptyString()]
        [string]$ClientId,

        [Parameter()]
        [PSCustomObject]$ConnectionInfo
    )

    process {
        $ResolvedTenantId = $TenantId
        $ResolvedClientId = $ClientId

        # Try to get values from ConnectionInfo first
        if ($ConnectionInfo) {
            if ([string]::IsNullOrEmpty($ResolvedTenantId) -and $ConnectionInfo.TenantId) {
                $ResolvedTenantId = $ConnectionInfo.TenantId
                Write-Verbose "Resolved TenantId from connection: $ResolvedTenantId"
            }
            if ([string]::IsNullOrEmpty($ResolvedClientId) -and $ConnectionInfo.ClientId) {
                $ResolvedClientId = $ConnectionInfo.ClientId
                Write-Verbose "Resolved ClientId from connection: $ResolvedClientId"
            }
        }

        # Fall back to MgGraph context if still empty
        if ([string]::IsNullOrEmpty($ResolvedTenantId) -or [string]::IsNullOrEmpty($ResolvedClientId)) {
            $MgContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($MgContext) {
                if ([string]::IsNullOrEmpty($ResolvedTenantId) -and $MgContext.TenantId) {
                    $ResolvedTenantId = $MgContext.TenantId
                    Write-Verbose "Resolved TenantId from MgContext: $ResolvedTenantId"
                }
                if ([string]::IsNullOrEmpty($ResolvedClientId) -and $MgContext.ClientId) {
                    $ResolvedClientId = $MgContext.ClientId
                    Write-Verbose "Resolved ClientId from MgContext: $ResolvedClientId"
                }
            }
        }

        @{
            TenantId = $ResolvedTenantId
            ClientId = $ResolvedClientId
        }
    }
}
