function Get-TntIntuneDeviceComplianceReport {
    <#
    .SYNOPSIS
        Generates Microsoft Intune device compliance analysis and reporting.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and generates detailed reports
        about device compliance policies, device compliance states, and policy effectiveness across the
        organization. It provides insights into compliance gaps, policy coverage, platform-specific
        compliance rates, and actionable recommendations for improving device security posture.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER FilterByPlatform
        Filter results by device platform. Valid values are Windows, iOS, Android, macOS.

    .PARAMETER FilterByComplianceState
        Filter results by compliance state. Valid values are Compliant, NonCompliant, InGracePeriod, ConfigManager, Error, Unknown.

    .PARAMETER ExcludeUserDetails
        Switch to skip user detail enrichment (Department, JobTitle, OfficeLocation). By default, user details
        are fetched for each device. Use this switch to improve performance when user details are not needed.

    .PARAMETER MaxDevices
        Maximum number of devices to process. Useful for large tenants. Defaults to 10000.

    .EXAMPLE
        Get-TntIntuneDeviceComplianceReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a comprehensive Intune device compliance report.

    .EXAMPLE
        Get-TntIntuneDeviceComplianceReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -FilterByPlatform Windows -FilterByComplianceState NonCompliant

        Generates a report focused on non-compliant Windows devices.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a comprehensive report object containing:
        - Summary: Statistics on compliance, risk, and platforms
        - DeviceComplianceDetails: Detailed per-device analysis
        - ComplianceByRisk: Devices grouped by risk level
        - NonCompliantDevices: List of non-compliant devices
        - StaleDevicesList: List of stale devices
        - RecentEnrollments: List of recently enrolled devices

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - DeviceManagementConfiguration.Read.All (Application)
        - DeviceManagementManagedDevices.Read.All (Application)
        - Device.Read.All (Application)
        - User.Read.All (Application) (unless ExcludeUserDetails is specified)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tenant')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
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
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS')]
        [string[]]$FilterByPlatform,

        [Parameter()]
        [ValidateSet('Compliant', 'NonCompliant', 'InGracePeriod', 'ConfigManager', 'Error', 'Unknown')]
        [string[]]$FilterByComplianceState,

        [Parameter()]
        [switch]$ExcludeUserDetails,

        [Parameter()]
        [ValidateRange(1, 50000)]
        [int]$MaxDevices = 10000
    )

    begin {
        # Define compliance state mappings and risk levels
        $ComplianceStateMap = @{
            'compliant'     = @{ Risk = 'Low'; Description = 'Device meets all compliance requirements' }
            'noncompliant'  = @{ Risk = 'High'; Description = 'Device fails one or more compliance requirements' }
            'inGracePeriod' = @{ Risk = 'Medium'; Description = 'Device is non-compliant but within grace period' }
            'configManager' = @{ Risk = 'Medium'; Description = 'Device managed by Configuration Manager' }
            'error'         = @{ Risk = 'High'; Description = 'Error evaluating device compliance' }
            'unknown'       = @{ Risk = 'Medium'; Description = 'Compliance state cannot be determined' }
        }

        Write-Information 'Starting Intune device compliance analysis...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Retrieve device compliance policies using Graph SDK
            Write-Verbose 'Retrieving device compliance policies...'
            try {
                $CompliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction Stop
                Write-Verbose "Retrieved $($CompliancePolicies.Count) compliance policies"
            } catch {
                Write-Warning "Failed to retrieve compliance policies: $($_.Exception.Message)"
                $CompliancePolicies = @()
            }

            # Retrieve managed devices with compliance information using Graph SDK
            Write-Verbose "Retrieving managed devices (max $($MaxDevices))..."

            $ManagedDevices = Get-MgDeviceManagementManagedDevice -All -Top $MaxDevices -ErrorAction Stop
            Write-Verbose "Retrieved $($ManagedDevices.Count) managed devices"

            # Pre-fetch all users ONCE before loop
            $UserCache = $null
            Write-Verbose 'Pre-fetching user data for device enrichment...'
            $CacheParams = @{
                TenantId           = $TenantId
                ClientId           = $ClientId
                RequiredProperties = @('Department', 'JobTitle', 'OfficeLocation')
                FetchAll           = $true
            }
            $UserCache = Get-CachedUsers @CacheParams
            Write-Verbose "User cache ready: $($UserCache.UserCount) users (CacheHit: $($UserCache.CacheHit))"

            # Cache current time outside the loop to avoid repeated Get-Date calls
            $Now = [datetime]::Now

            # Process each device for detailed compliance analysis
            $DeviceComplianceDetails = foreach ($Device in $ManagedDevices) {
                # Apply platform filter if specified
                if ($FilterByPlatform -and $Device.OperatingSystem -notin $FilterByPlatform) {
                    continue
                }

                # Apply compliance state filter if specified
                if ($FilterByComplianceState -and $Device.ComplianceState -notin $FilterByComplianceState) {
                    continue
                }

                # Determine device platform
                $DevicePlatform = switch ($Device.OperatingSystem) {
                    { $_ -match 'Windows' } { 'Windows' }
                    { $_ -match 'iOS' } { 'iOS' }
                    { $_ -match 'Android' } { 'Android' }
                    { $_ -match 'macOS' } { 'macOS' }
                    default { $Device.OperatingSystem ?? 'Unknown' }
                }

                # Calculate days since last sync
                $DaysSinceLastSync = if ($Device.LastSyncDateTime) {
                    [math]::Round(($Now - $Device.LastSyncDateTime).TotalDays, 1)
                } else {
                    999
                }

                # Calculate enrollment age
                $EnrollmentAge = if ($Device.EnrolledDateTime) {
                    [math]::Round(($Now - $Device.EnrolledDateTime).TotalDays, 0)
                } else {
                    0
                }

                # Normalize ComplianceState due to some weird issue with the SDK returning a single-element array
                $SafeComplianceState = if ($Device.ComplianceState) { 
                    ($Device.ComplianceState -join ', ').Trim()
                } else { 
                    'Unknown'
                }

                # Determine risk level based on compliance state and other factors
                $RiskLevel = $ComplianceStateMap[$SafeComplianceState].Risk
                if ($DaysSinceLastSync -gt 30) {
                    $RiskLevel = 'High'  # Override if device hasn't synced recently
                }

                # Get user information
                $UserInfo = @{
                    UserPrincipalName = $Device.UserPrincipalName ?? 'Unknown'
                    UserDisplayName   = $Device.UserDisplayName ?? 'Unknown'
                }

                if (-not $ExcludeUserDetails -and $Device.UserPrincipalName) {
                    # O(1) lookup from pre-fetched cache instead of per-device API call
                    $UserDetails = $null
                    if ($UserCache) {
                        $UserDetails = $UserCache.LookupByUPN[$Device.UserPrincipalName]
                    }

                    # Fallback to individual API call if not in cache (handles new users, transient failures)
                    if (-not $UserDetails) {
                        try {
                            $UserDetails = Get-MgUser -UserId $Device.UserPrincipalName -Property Id, DisplayName, Department, JobTitle, OfficeLocation -ErrorAction SilentlyContinue
                        } catch {
                            Write-Verbose "Could not retrieve user details for $($Device.UserPrincipalName)"
                        }
                    }

                    if ($UserDetails) {
                        $UserInfo.Department = $UserDetails.Department ?? 'Not specified'
                        $UserInfo.JobTitle = $UserDetails.JobTitle ?? 'Not specified'
                        $UserInfo.OfficeLocation = $UserDetails.OfficeLocation ?? 'Not specified'
                    }
                }

                # Create detailed device compliance entry
                [PSCustomObject]@{
                    DeviceId              = $Device.Id
                    DeviceName            = $Device.DeviceName ?? 'Unknown'
                    Platform              = $DevicePlatform
                    OperatingSystem       = $Device.OperatingSystem ?? 'Unknown'
                    OSVersion             = $Device.OSVersion ?? 'Unknown'
                    ComplianceState       = $SafeComplianceState ?? 'Unknown'
                    ComplianceDescription = $ComplianceStateMap[$SafeComplianceState].Description
                    RiskLevel             = $RiskLevel
                    DeviceType            = $Device.DeviceType ?? 'Unknown'
                    OwnerType             = ($Device.ManagedDeviceOwnerType -join ', ').Trim() ?? 'Unknown'
                    ManagementAgent       = ($Device.ManagementAgent -join ', ').Trim() ?? 'Unknown'
                    RegistrationState     = ($Device.DeviceRegistrationState -join ', ').Trim() ?? 'Unknown'
                    EnrolledDateTime      = $Device.EnrolledDateTime
                    LastSyncDateTime      = $Device.LastSyncDateTime
                    DaysSinceLastSync     = $DaysSinceLastSync
                    EnrollmentAge         = $EnrollmentAge
                    AzureADDeviceId       = $Device.AzureADDeviceId ?? 'Not available'
                    SerialNumber          = $Device.SerialNumber ?? 'Not available'
                    Model                 = $Device.Model ?? 'Unknown'
                    Manufacturer          = $Device.Manufacturer ?? 'Unknown'
                    UserPrincipalName     = $UserInfo.UserPrincipalName
                    UserDisplayName       = $UserInfo.UserDisplayName
                    UserDepartment        = $UserInfo.Department ?? 'Not retrieved'
                    UserJobTitle          = $UserInfo.JobTitle ?? 'Not retrieved'
                    UserOfficeLocation    = $UserInfo.OfficeLocation ?? 'Not retrieved'
                    IsStaleDevice         = $DaysSinceLastSync -gt 30
                    IsRecentEnrollment    = $EnrollmentAge -le 30
                    RequiresAttention     = $Device.ComplianceState -in @('NonCompliant', 'Error', 'Unknown')
                }
            }

            # Calculate overall compliance summary using single-pass accumulation
            $TotalDevicesProcessed = if ($DeviceComplianceDetails) { $DeviceComplianceDetails.Count } else { 0 }

            # Initialize counters for single-pass accumulation
            $DeviceStats = @{
                CompliantDevices          = 0
                NonCompliantDevices       = 0
                GracePeriodDevices        = 0
                ErrorDevices              = 0
                UnknownStateDevices       = 0
                HighRiskDevices           = 0
                MediumRiskDevices         = 0
                LowRiskDevices            = 0
                WindowsDevices            = 0
                iOSDevices                = 0
                AndroidDevices            = 0
                macOSDevices              = 0
                StaleDevices              = 0
                RecentEnrollments         = 0
                DevicesRequiringAttention = 0
                CorporateDevices          = 0
                PersonalDevices           = 0
            }
            $PlatformCounts = @{}

            if ($DeviceComplianceDetails) {
                foreach ($Device in $DeviceComplianceDetails) {
                    # Compliance state
                    switch ($Device.ComplianceState) {
                        'compliant' { $DeviceStats.CompliantDevices++ }
                        'noncompliant' { $DeviceStats.NonCompliantDevices++ }
                        'inGracePeriod' { $DeviceStats.GracePeriodDevices++ }
                        'error' { $DeviceStats.ErrorDevices++ }
                        'unknown' { $DeviceStats.UnknownStateDevices++ }
                    }

                    # Risk level
                    switch ($Device.RiskLevel) {
                        'High' { $DeviceStats.HighRiskDevices++ }
                        'Medium' { $DeviceStats.MediumRiskDevices++ }
                        'Low' { $DeviceStats.LowRiskDevices++ }
                    }

                    # Platform
                    switch ($Device.Platform) {
                        'Windows' { $DeviceStats.WindowsDevices++ }
                        'iOS' { $DeviceStats.iOSDevices++ }
                        'Android' { $DeviceStats.AndroidDevices++ }
                        'macOS' { $DeviceStats.macOSDevices++ }
                    }

                    # Platform counts for most common
                    if ($Device.Platform) {
                        if (-not $PlatformCounts.ContainsKey($Device.Platform)) {
                            $PlatformCounts[$Device.Platform] = 0
                        }
                        $PlatformCounts[$Device.Platform]++
                    }

                    # Health indicators
                    if ($Device.IsStaleDevice) { $DeviceStats.StaleDevices++ }
                    if ($Device.IsRecentEnrollment) { $DeviceStats.RecentEnrollments++ }
                    if ($Device.RequiresAttention) { $DeviceStats.DevicesRequiringAttention++ }

                    # Ownership
                    switch ($Device.OwnerType) {
                        'company' { $DeviceStats.CorporateDevices++ }
                        'personal' { $DeviceStats.PersonalDevices++ }
                    }
                }
            }

            # Find most common platform
            $MostCommonPlatform = 'None'
            if ($PlatformCounts.Count -gt 0) {
                $MostCommonPlatform = ($PlatformCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key ?? 'Unknown'
            }

            $Summary = [PSCustomObject]@{
                TenantId                  = $TenantId
                ReportGeneratedDate       = Get-Date
                TotalDevicesAnalyzed      = $TotalDevicesProcessed
                TotalCompliancePolicies   = $CompliancePolicies.Count

                # Compliance State Distribution
                CompliantDevices          = $DeviceStats.CompliantDevices
                NonCompliantDevices       = $DeviceStats.NonCompliantDevices
                GracePeriodDevices        = $DeviceStats.GracePeriodDevices
                ErrorDevices              = $DeviceStats.ErrorDevices
                UnknownStateDevices       = $DeviceStats.UnknownStateDevices

                # Calculated Percentages
                ComplianceRate            = if ($TotalDevicesProcessed -gt 0) {
                    [math]::Round(($DeviceStats.CompliantDevices / $TotalDevicesProcessed) * 100, 1)
                } else { 0 }
                NonComplianceRate         = if ($TotalDevicesProcessed -gt 0) {
                    [math]::Round(($DeviceStats.NonCompliantDevices / $TotalDevicesProcessed) * 100, 1)
                } else { 0 }
                GracePeriodRate           = if ($TotalDevicesProcessed -gt 0) {
                    [math]::Round(($DeviceStats.GracePeriodDevices / $TotalDevicesProcessed) * 100, 1)
                } else { 0 }

                # Risk Assessment
                HighRiskDevices           = $DeviceStats.HighRiskDevices
                MediumRiskDevices         = $DeviceStats.MediumRiskDevices
                LowRiskDevices            = $DeviceStats.LowRiskDevices

                # Platform Distribution
                WindowsDevices            = $DeviceStats.WindowsDevices
                iOSDevices                = $DeviceStats.iOSDevices
                AndroidDevices            = $DeviceStats.AndroidDevices
                macOSDevices              = $DeviceStats.macOSDevices

                # Device Health Indicators
                StaleDevices              = $DeviceStats.StaleDevices
                RecentEnrollments         = $DeviceStats.RecentEnrollments
                DevicesRequiringAttention = $DeviceStats.DevicesRequiringAttention

                # Management Statistics
                CorporateDevices          = $DeviceStats.CorporateDevices
                PersonalDevices           = $DeviceStats.PersonalDevices

                # Top Issues
                MostCommonPlatform        = $MostCommonPlatform
            }

            Write-Information "Intune device compliance analysis completed - $($TotalDevicesProcessed) devices analyzed ($($Summary.ComplianceRate)% compliant)" -InformationAction Continue

            [PSCustomObject]@{
                Summary                 = $Summary
                DeviceComplianceDetails = $DeviceComplianceDetails | Sort-Object RiskLevel, ComplianceState, Platform, DeviceName
                ComplianceByRisk        = @{
                    High   = if ($DeviceComplianceDetails) { @($DeviceComplianceDetails.Where({ $_.RiskLevel -eq 'High' })) } else { @() }
                    Medium = if ($DeviceComplianceDetails) { @($DeviceComplianceDetails.Where({ $_.RiskLevel -eq 'Medium' })) } else { @() }
                    Low    = if ($DeviceComplianceDetails) { @($DeviceComplianceDetails.Where({ $_.RiskLevel -eq 'Low' })) } else { @() }
                }
                NonCompliantDevices     = if ($DeviceComplianceDetails) { $DeviceComplianceDetails.Where({ $_.ComplianceState -eq 'noncompliant' }) | Sort-Object RiskLevel -Descending } else { @() }
                StaleDevicesList        = if ($DeviceComplianceDetails) { $DeviceComplianceDetails.Where({ $_.IsStaleDevice }) | Sort-Object DaysSinceLastSync -Descending } else { @() }
                RecentEnrollments       = if ($DeviceComplianceDetails) { $DeviceComplianceDetails.Where({ $_.IsRecentEnrollment }) | Sort-Object EnrolledDateTime -Descending } else { @() }
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntIntuneDeviceComplianceReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntIntuneDeviceComplianceReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
