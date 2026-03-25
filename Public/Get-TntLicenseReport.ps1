function Get-TntLicenseReport {
    <#
    .SYNOPSIS
        Retrieves Microsoft 365 license allocation and usage information.

    .DESCRIPTION
        This function connects to Microsoft Graph and retrieves detailed subscription and license
        information for the Microsoft 365 tenant. It provides insights into license allocation,
        consumption, available capacity, and utilization rates across all subscribed SKUs.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .EXAMPLE
        Get-TntLicenseReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves and displays license allocation information.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: High-level statistics on subscriptions and licenses
        - Licenses: Detailed list of licenses with usage and friendly names

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Organization.Read.All (Application)
        - Directory.Read.All (Application)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tenant')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [Alias('ApplicationId')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Secret', 'ApplicationSecret')]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    begin {
        # Load SKU Translation table for retrieving friendly license names
        $SkuHashTable = @{}
        $SkuTable = Get-SkuTranslationTable
        if ($SkuTable) {
            foreach ($SkuGroup in ($SkuTable | Group-Object GUID)) {
                $SkuHashTable[$SkuGroup.Name] = ($SkuGroup.Group | Select-Object -First 1).Product_Display_Name
            }
        } else {
            Write-Verbose "SKU Translation Table not available."
        }

        Write-Information 'STARTED  : License report retrieval...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Retrieve subscription information
            Write-Verbose 'Retrieving subscription and license information...'
            $SubscribedSkus = Get-MgSubscribedSku -All -ErrorAction Stop

            $LicenseData = $SubscribedSkus.ForEach({
                # Translate SKU ID to friendly name
                $ResolvedName = Resolve-SkuName -SkuId $_.SkuId -SkuHashTable $SkuHashTable
                $FriendlyName = if ($ResolvedName -eq $_.SkuId) {
                    Write-Verbose "SKU $($_.SkuId) not found in translation table. Using SkuPartNumber."
                    $_.SkuPartNumber
                } else {
                    $ResolvedName
                }

                # Build license information object
                [PSCustomObject]@{
                    SkuId             = $_.SkuId
                    SkuPartNumber     = $_.SkuPartNumber
                    FriendlyName      = $FriendlyName
                    CapabilityStatus  = $_.CapabilityStatus
                    ConsumedUnits     = $_.ConsumedUnits
                    PrepaidUnits      = $_.PrepaidUnits.Enabled
                    WarningUnits      = $_.PrepaidUnits.Warning
                    SuspendedUnits    = $_.PrepaidUnits.Suspended
                    AvailableUnits    = if ($_.PrepaidUnits.Enabled) {
                        $_.PrepaidUnits.Enabled - $_.ConsumedUnits
                    } else { 0 }
                    Utilization       = if ($_.PrepaidUnits.Enabled -gt 0) {
                        [math]::Round(($_.ConsumedUnits / $_.PrepaidUnits.Enabled) * 100, 2)
                    } else { 0 }
                    ServicePlansCount = $_.ServicePlans.Count
                }
            }) | Sort-Object FriendlyName

            # Calculate summary statistics
            $TotalPrepaid = ($LicenseData | Measure-Object -Property PrepaidUnits -Sum).Sum
            $TotalConsumed = ($LicenseData | Measure-Object -Property ConsumedUnits -Sum).Sum
            $TotalAvailable = ($LicenseData | Measure-Object -Property AvailableUnits -Sum).Sum

            $Summary = [PSCustomObject]@{
                TotalSubscriptions     = if ($LicenseData) { $LicenseData.Count } else { 0 }
                ActiveSubscriptions    = if ($LicenseData) { $LicenseData.Where({ $_.CapabilityStatus -eq 'Enabled' }).Count } else { 0 }
                TotalLicensesPurchased = $TotalPrepaid
                TotalLicensesAssigned  = $TotalConsumed
                TotalLicensesAvailable = $TotalAvailable
            }

            Write-Information "FINISHED : License report - $($Summary.TotalSubscriptions) licenses found" -InformationAction Continue

            [PSCustomObject] @{
                Summary  = $Summary
                Licenses = $LicenseData
            }
        }
        catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntLicenseReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntLicenseReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
