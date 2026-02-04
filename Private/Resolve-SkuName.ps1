function Resolve-SkuName {
    <#
    .SYNOPSIS
        Resolves a Microsoft 365 SKU GUID to a friendly product name.

    .DESCRIPTION
        Looks up a SKU GUID in the provided hashtable and returns the friendly product name.
        If the SKU is not found, returns the original GUID.

    .PARAMETER SkuId
        The SKU GUID to resolve.

    .PARAMETER SkuHashTable
        A hashtable mapping SKU GUIDs to friendly product names.

    .OUTPUTS
        System.String
        The friendly product name or the original GUID if not found.

    .NOTES
        Author: Tom de Leeuw
        Module: TenantReports
    #>
    param(
        [Parameter(Mandatory)]
        [string]$SkuId,

        [Parameter(Mandatory)]
        [hashtable]$SkuHashTable
    )

    if ($SkuHashTable.ContainsKey($SkuId)) {
        return $SkuHashTable[$SkuId]
    } else {
        return $SkuId
    }
}
