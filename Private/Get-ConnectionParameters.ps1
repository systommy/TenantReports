function Get-ConnectionParameters {
    <#
    .SYNOPSIS
        Extracts connection parameters from bound parameters.

    .DESCRIPTION
        Internal helper function that filters PSBoundParameters to extract only
        valid connection parameters (TenantId, ClientId, ClientSecret, CertificateThumbprint, etc.).

    .PARAMETER BoundParameters
        The $PSBoundParameters hashtable from the calling function.

    .EXAMPLE
        $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
        $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

    .OUTPUTS
        Hashtable containing only valid connection parameters.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Internal function for reducing code duplication.

    .LINK
        https://systom.dev
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    $ConnectionParams = @{}
    foreach ($Param in $BoundParameters.GetEnumerator()) {
        if ($Param.Key -in $script:ValidConnectionParams) {
            $ConnectionParams[$Param.Key] = $Param.Value
        }
    }

    $ConnectionParams
}
