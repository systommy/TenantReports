function Get-TntM365RiskyUserReport {
    <#
    .SYNOPSIS
        Generates a Microsoft 365 risky user report using Azure AD Identity Protection signals.

    .DESCRIPTION
        Connects to Microsoft Graph and retrieves risky user findings, including risk levels, states,
        and detection metadata. The report helps identify accounts that require remediation or policy
        enforcement.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to analyze.

    .PARAMETER ClientId
        The Application (Client) ID of the registered Azure AD application.

    .PARAMETER ClientSecret
        The client secret for the application. Accepts SecureString or plain String.

    .PARAMETER CertificateThumbprint
        The certificate thumbprint for certificate-based authentication. Alternative to ClientSecret.

    .PARAMETER RiskLevel
        Optional list of risk levels (None, Low, Medium, High) to filter results.

    .PARAMETER DaysBack
        Number of days of risk history to include. Defaults to 90 days.

    .PARAMETER MaxRiskyUsers
        Maximum number of risky users to process. Defaults to 1000.

    .EXAMPLE
        Get-TntM365RiskyUserReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Returns complete risky user analysis as a PSCustomObject.

    .EXAMPLE
        Get-TntM365RiskyUserReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -RiskLevel High

        Returns report filtered for High risk users only.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

        Returns an object with the following structure:
        - ReportDate: Timestamp of generation
        - TenantId: The analyzed tenant
        - Summary: Statistics on risky users and detections
        - RiskyUsers: Detailed list of users at risk
        - RiskDetections: Detailed list of risk detection events
        - RiskyServicePrincipals: Detailed list of risky service principals

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - IdentityRiskyUser.Read.All (Application)
        - IdentityRiskEvent.Read.All (Application)
        - IdentityRiskyServicePrincipal.Read.All (Application)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tenant')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
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
        [switch]$Interactive,

        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High')]
        [string[]]$RiskLevel,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysBack = 90,

        [Parameter()]
        [ValidateRange(1, 100000)]
        [int]$MaxRiskyUsers = 1000,

        [Parameter()]
        [switch]$IncludeHistory
    )

    begin {
        # Calculate start date
        $StartDate = (Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Write-Information "Starting risky users report generation for past $($DaysBack) days..." -InformationAction Continue
    }

    process {
        # Interactive authentication is not supported for this function
        # Identity Protection APIs require application permissions (IdentityRiskyUser.Read.All, etc.)
        if ($Interactive) {
            Write-Warning 'Get-TntM365RiskyUserReport requires application permissions and cannot run with interactive authentication.'
            Write-Warning 'The following application permissions are required: IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, IdentityRiskyServicePrincipal.Read.All'
            Write-Warning 'Use -ClientSecret or -CertificateThumbprint authentication instead.'
            return $null
        }

        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            Write-Verbose "Retrieving risky users (max $($MaxRiskyUsers))..."

            # Build filter parameters
            $FilterParams = @{
                Filter = "riskLastUpdatedDateTime ge $($StartDate)"
            }

            if ($RiskLevel) {
                $RiskLevelConditions    = $RiskLevel | ForEach-Object { "RiskLevel eq '$($_.ToLower())'" }
                $RiskLevelFilterString  = "($($RiskLevelConditions -join ' or '))"
                $FilterParams.Filter   += " and $RiskLevelFilterString"
                Write-Verbose "Filtering by riskLevel: $($RiskLevel -join ', ')"
            }

            Write-Verbose "Using filter: $($FilterParams.Filter)"
            $RiskyUserProperties = @(
                'Id',
                'UserDisplayName',
                'UserPrincipalName',
                'RiskLevel',
                'RiskState',
                'RiskDetail',
                'IsProcessing',
                'IsDeleted',
                'LastRiskDetectionDate',
                'DetectedRisks',
                'riskLastUpdatedDateTime'
            )
            
            $RiskyUsers = Get-MgRiskyUser -All @FilterParams -Top $MaxRiskyUsers -ErrorAction SilentlyContinue | Select-Object $RiskyUserProperties
            Write-Verbose "Found $($RiskyUsers.Count) risky users."

            # Process Risky Users data for report, including fetching risk event types
            $RiskyUsersReport = foreach ($RiskyUser in $RiskyUsers) {
                $RiskEventTypes = @()
                if ($IncludeHistory) {
                    try {
                        $RiskyUserHistory = Get-MgRiskyUserHistory -RiskyUserId $RiskyUser.Id -ErrorAction SilentlyContinue
                        if ($RiskyUserHistory) {
                            $RiskEventTypes = ($RiskyUserHistory.Activity | Select-Object -ExpandProperty RiskEventTypes | Select-Object -Unique) -join ', '
                        }
                    } catch {
                        Write-Warning "Could not retrieve risk history for user $($RiskyUser.UserPrincipalName): $($_.Exception.Message)"
                        $RiskEventTypes = 'Error retrieving history'
                    }
                }

                [PSCustomObject]@{
                    UserId                  = $RiskyUser.Id
                    DisplayName             = $RiskyUser.UserDisplayName
                    UserPrincipalName       = $RiskyUser.UserPrincipalName
                    RiskLevel               = $RiskyUser.RiskLevel
                    RiskState               = $RiskyUser.RiskState
                    RiskDetail              = $RiskyUser.RiskDetail
                    LastRiskDetectionDate   = $RiskyUser.LastRiskDetectionDate
                    RiskEventTypes          = $RiskEventTypes
                    IsProcessing            = $RiskyUser.IsProcessing
                    IsDeleted               = $RiskyUser.IsDeleted
                    RiskLastUpdatedDateTime = $RiskyUser.RiskLastUpdatedDateTime
                }
            }

            # Collect Risk Detections
            Write-Verbose "Retrieving risk detections..."
            $FilterString   = "LastUpdatedDateTime ge $($StartDate)"
            $RiskDetections = Get-MgRiskDetection -All -Filter $FilterString -ErrorAction SilentlyContinue
            
            $RiskDetectionsReport = foreach ($RiskDetection in $RiskDetections) {
                [PSCustomObject]@{
                    'Id'                      = $RiskDetection.id
                    'RiskDetectionDateTime'   = $RiskDetection.DetectedDateTime
                    'RiskLevel'               = $RiskDetection.riskLevel
                    'RiskState'               = $RiskDetection.riskState
                    'RiskDetail'              = $RiskDetection.riskDetail
                    'RiskType'                = $RiskDetection.riskEventType
                    'UserId'                  = $RiskDetection.userId
                    'UserDisplayName'         = $RiskDetection.userDisplayName
                    'UserPrincipalName'       = $RiskDetection.userPrincipalName
                    'RiskLastUpdatedDateTime' = $RiskDetection.LastUpdatedDateTime
                    'RiskEventTypes'          = $RiskDetection.riskEventType
                }
            }

            # Collect risky Service Principals
            Write-Verbose "Retrieving risky service principals..."
            $FilterString           = "riskLastUpdatedDateTime ge $($StartDate)"
            $RiskyServicePrincipals = Get-MgRiskyServicePrincipal -All -Filter $FilterString -ErrorAction SilentlyContinue
            
            $RiskyServicePrincipalReport = foreach ($RiskyService in $RiskyServicePrincipals) {
                [PSCustomObject]@{
                    'Id'                          = $RiskyService.id
                    'AppID'                       = $RiskyService.appId
                    'ServicePrincipalDisplayName' = $RiskyService.DisplayName
                    'RiskLastUpdatedDateTime'     = $RiskyService.RiskLastUpdatedDateTime
                    'RiskLevel'                   = $RiskyService.riskLevel
                    'RiskState'                   = $RiskyService.riskState
                    'ServicePrincipalType'        = $RiskyService.servicePrincipalType
                }
            }

            $Summary = [PSCustomObject]@{
                TotalRiskyUsers                = if ($RiskyUsersReport) { $RiskyUsersReport.Count } else { 0 }
                RiskyUsersConfirmedCompromised = if ($RiskyUsersReport) { ($RiskyUsersReport | Where-Object { $_.RiskDetail -eq 'UserConfirmedCompromised' }).Count } else { 0 }
                RiskyUsersAtHighLevel          = if ($RiskyUsersReport) { ($RiskyUsersReport | Where-Object { $_.RiskLevel -eq 'High' }).Count } else { 0 }
                TotalRiskDetections            = if ($RiskDetectionsReport) { $RiskDetectionsReport.Count } else { 0 }
                TotalRiskyServicePrincipals    = if ($RiskyServicePrincipalReport) { $RiskyServicePrincipalReport.Count } else { 0 }
            }

            Write-Information "Risky users report completed - $($Summary.TotalRiskyUsers) risky users found" -InformationAction Continue

            [PSCustomObject]@{
                ReportDate             = Get-Date
                TenantId               = $TenantId
                Summary                = $Summary
                RiskyUsers             = $RiskyUsersReport | Sort-Object RiskLevel, DisplayName
                RiskDetections         = $RiskDetectionsReport | Sort-Object RiskLevel, RiskDetectionDateTime -Descending
                RiskyServicePrincipals = $RiskyServicePrincipalReport | Sort-Object RiskLevel, ServicePrincipalDisplayName
            }
        }
        catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntM365RiskyUserReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntM365RiskyUserReportError',
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
