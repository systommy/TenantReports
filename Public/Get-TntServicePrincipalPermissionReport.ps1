function Get-TntServicePrincipalPermissionReport {
    <#
    .SYNOPSIS
        Generates a report of delegated permission grants for Entra ID service principals and user accounts.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and generates detailed reports about
        delegated permissions granted to service principals and users. It provides security insights and
        compliance information to help identify potential risks and over-privileged applications.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER ExcludeUserConsents
        Switch to exclude individual user consent grants from the report. By default, user consents are included.

    .PARAMETER FilterByRiskLevel
        Filter results by risk level. Valid values are Low, Medium, High, Critical.

    .PARAMETER ExcludeInactiveApps
        Switch to exclude applications that haven't been used recently. By default, inactive apps are included.

    .PARAMETER MaxResults
        Maximum number of service principals to process. Useful for large tenants.

    .EXAMPLE
        Get-TntServicePrincipalPermissionReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a delegated permissions report using client secret authentication.

    .EXAMPLE
        Get-TntServicePrincipalPermissionReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -FilterByRiskLevel Critical

        Generates a report containing only critical risk permissions, including all user consents by default.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a comprehensive report object containing:
        - Summary: Statistics on permission grants and risks
        - CriticalRiskPermissions: Details of critical permissions granted
        - HighRiskPermissions: Details of high-risk permissions granted
        - MediumRiskPermissions: Details of medium-risk permissions granted
        - LowRiskPermissions: Details of low-risk permissions granted
        - AllPermissions: Complete list of processed permission grants

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Directory.Read.All (Application)
        - User.Read.All (Application)
        - AuditLog.Read.All (Application)

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

        # Use interactive authentication (no app registration required).
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [switch]$ExcludeUserConsents,

        [Parameter()]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$FilterByRiskLevel,

        [Parameter()]
        [switch]$ExcludeInactiveApps,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$MaxResults = 2000
    )

    begin {
        # Define risk levels for different permission scopes
        $PermissionRiskLevels = @{
            # Critical Risk Permissions
            'Directory.ReadWrite.All'                = 'Critical'
            'User.ReadWrite.All'                     = 'Critical'
            'Group.ReadWrite.All'                    = 'Critical'
            'RoleManagement.ReadWrite.Directory'     = 'Critical'
            'Application.ReadWrite.All'              = 'Critical'
            'AppRoleAssignment.ReadWrite.All'        = 'Critical'
            'DelegatedPermissionGrant.ReadWrite.All' = 'Critical'

            # High Risk Permissions
            'Directory.Read.All'                     = 'High'
            'User.Read.All'                          = 'High'
            'Group.Read.All'                         = 'High'
            'Mail.ReadWrite'                         = 'High'
            'Files.ReadWrite.All'                    = 'High'
            'Sites.ReadWrite.All'                    = 'High'
            'Calendars.ReadWrite'                    = 'High'

            # Medium Risk Permissions
            'User.Read'                              = 'Medium'
            'Mail.Read'                              = 'Medium'
            'Files.Read.All'                         = 'Medium'
            'Sites.Read.All'                         = 'Medium'
            'Calendars.Read'                         = 'Medium'
            'Contacts.Read'                          = 'Medium'

            # Low Risk Permissions (Default)
            'openid'                                 = 'Low'
            'profile'                                = 'Low'
            'email'                                  = 'Low'
            'offline_access'                         = 'Low'
        }

        # Common Microsoft Graph Resource IDs
        $WellKnownResourceIds = @{
            '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
            '00000002-0000-0000-c000-000000000000' = 'Microsoft Graph (Legacy)'
            '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
            '00000001-0000-0000-c000-000000000000' = 'Microsoft Graph (Classic)'
        }

        Write-Information 'Starting Service Principal permissions report generation...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Initialize collections for report data
            $DelegatedPermissionGrants = [System.Collections.Generic.List[PSObject]]::new()
            $ResourceApplications = @{}

            # Get all service principals
            Write-Verbose 'Retrieving service principals...'
            $AllServicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, CreatedDateTime, SignInAudience, PublisherName, Tags, AppRoleAssignments -ErrorAction Stop

            if ($MaxResults -and $AllServicePrincipals.Count -gt $MaxResults) {
                $AllServicePrincipals = $AllServicePrincipals | Select-Object -First $MaxResults
                Write-Warning "Limited results to $($MaxResults) service principals due to MaxResults parameter"
            }

            Write-Verbose "Found $($AllServicePrincipals.Count) service principals"

            # Build hashtable lookup for O(1) service principal lookups (Performance optimization: Phase 3)
            $ServicePrincipalLookupById = @{}
            foreach ($SP in $AllServicePrincipals) {
                if ($SP.Id) { $ServicePrincipalLookupById[$SP.Id] = $SP }
            }

            # Get all OAuth2 permission grants
            Write-Verbose 'Retrieving OAuth2 permission grants...'
            $AllOAuth2Grants = Get-MgOauth2PermissionGrant -All -Property Id, ClientId, ResourceId, Scope, ConsentType, PrincipalId -ErrorAction Stop

            Write-Verbose "Found $($AllOAuth2Grants.Count) OAuth2 permission grants"

            # Collect unique PrincipalIds for user consent grants (incremental caching)
            $UserConsentPrincipalIds = @($AllOAuth2Grants |
                    Where-Object { $_.ConsentType -eq 'Principal' -and $_.PrincipalId } |
                    Select-Object -ExpandProperty PrincipalId -Unique)

            # Pre-fetch only the specific users needed (incremental mode - NOT all users)
            $UserCache = $null
            if ($UserConsentPrincipalIds.Count -gt 0 -and -not $ExcludeUserConsents) {
                Write-Verbose "Pre-fetching $($UserConsentPrincipalIds.Count) users for consent details (incremental mode)..."
                $CacheParams = @{
                    TenantId = $TenantId
                    ClientId = $ClientId
                    UserIds  = $UserConsentPrincipalIds
                }
                $UserCache = Get-CachedUsers @CacheParams
                Write-Verbose "User cache ready: $($UserCache.UserCount) users (CacheHit: $($UserCache.CacheHit))"
            }

            # Process each OAuth2 grant
            foreach ($Grant in $AllOAuth2Grants) {
                try {
                    # Get client service principal using O(1) hashtable lookup (with null-safety)
                    $ClientServicePrincipal = $null
                    if ($Grant.ClientId) {
                        $ClientServicePrincipal = $ServicePrincipalLookupById[$Grant.ClientId]
                    }
                    if (-not $ClientServicePrincipal) {
                        Write-Verbose "Skipping grant for unknown client: $($Grant.ClientId)"
                        continue
                    }

                    # Get resource service principal (API being accessed)
                    if (-not $ResourceApplications.ContainsKey($Grant.ResourceId)) {
                        $ResourceServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Grant.ResourceId -Property Id, AppId, DisplayName -ErrorAction SilentlyContinue
                        $ResourceApplications[$Grant.ResourceId] = $ResourceServicePrincipal
                    } else {
                        $ResourceServicePrincipal = $ResourceApplications[$Grant.ResourceId]
                    }

                    if (-not $ResourceServicePrincipal) {
                        Write-Verbose "Skipping grant for unknown resource: $($Grant.ResourceId)"
                        continue
                    }

                    # Parse individual scopes
                    $Scopes = if ($Grant.Scope.Count -gt 0) { $Grant.Scope.Split(' ') | Where-Object { $_ } } else { $Grant.Scope }

                    foreach ($Scope in $Scopes) {
                        # Determine risk level
                        $RiskLevel = if ($PermissionRiskLevels.ContainsKey($Scope)) {
                            $PermissionRiskLevels[$Scope]
                        } else {
                            'UNKNOWN' # Default for unknown permissions
                        }

                        # Skip if filtering by risk level
                        if ($FilterByRiskLevel -and $RiskLevel -ne $FilterByRiskLevel) {
                            continue
                        }

                        # Get user information if this is a user consent
                        $PrincipalDisplayName = $null
                        $PrincipalUserPrincipalName = $null
                        if ($Grant.ConsentType -eq 'Principal' -and $Grant.PrincipalId) {
                            # O(1) lookup from pre-fetched cache instead of per-grant API call
                            $User = $null
                            if ($UserCache) {
                                $User = $UserCache.LookupById[$Grant.PrincipalId]
                            }

                            # Fallback to individual API call if not in cache (handles transient failures)
                            if (-not $User) {
                                try {
                                    $User = Get-MgUser -UserId $Grant.PrincipalId -Property DisplayName, UserPrincipalName -ErrorAction SilentlyContinue
                                } catch {
                                    Write-Verbose "Could not retrieve user info for principal: $($Grant.PrincipalId)"
                                }
                            }

                            if ($User) {
                                $PrincipalDisplayName = $User.DisplayName
                                $PrincipalUserPrincipalName = $User.UserPrincipalName
                            }
                        }

                        # Skip user consents if excluded
                        if ($ExcludeUserConsents -and $Grant.ConsentType -eq 'Principal') {
                            continue
                        }

                        # Create report entry
                        $ReportEntry = [PSCustomObject]@{
                            GrantId                    = $Grant.Id
                            ClientApplicationId        = $ClientServicePrincipal.AppId
                            ClientApplicationName      = $ClientServicePrincipal.DisplayName
                            ClientPublisher            = $ClientServicePrincipal.PublisherName
                            ClientCreatedDate          = $ClientServicePrincipal.CreatedDateTime
                            ClientTags                 = ($ClientServicePrincipal.Tags -join '; ')
                            ResourceApplicationId      = $ResourceServicePrincipal.AppId
                            ResourceApplicationName    = $ResourceServicePrincipal.DisplayName
                            ResourceFriendlyName       = if ($WellKnownResourceIds.ContainsKey($ResourceServicePrincipal.AppId)) {
                                $WellKnownResourceIds[$ResourceServicePrincipal.AppId]
                            } else {
                                $ResourceServicePrincipal.DisplayName
                            }
                            Permission                 = $Scope
                            ConsentType                = switch ($Grant.ConsentType) {
                                'AllPrincipals' { 'Admin Consent (All Users)' }
                                'Principal' { 'User Consent' }
                                default { $Grant.ConsentType }
                            }
                            PrincipalId                = $Grant.PrincipalId
                            PrincipalDisplayName       = $PrincipalDisplayName
                            PrincipalUserPrincipalName = $PrincipalUserPrincipalName
                            RiskLevel                  = $RiskLevel
                            GrantStartTime             = $Grant.StartTime
                            GrantExpiryTime            = $Grant.ExpiryTime
                            IsExpired                  = if ($Grant.ExpiryTime) { $Grant.ExpiryTime -lt (Get-Date) } else { $false }
                            DaysUntilExpiry            = if ($Grant.ExpiryTime) {
                                [math]::Round(($Grant.ExpiryTime - (Get-Date)).TotalDays, 0)
                            } else {
                                $null
                            }
                        }

                        $DelegatedPermissionGrants.Add($ReportEntry)
                    }
                } catch {
                    Write-Warning "Error processing grant $($Grant.Id): $($_.Exception.Message)"
                    continue
                }
            }

            # Filter inactive apps if excluded
            if ($ExcludeInactiveApps) {
                Write-Verbose 'Filtering out inactive applications...'
                $DelegatedPermissionGrants = $DelegatedPermissionGrants | Where-Object {
                    -not $_.ClientCreatedDate -or $_.ClientCreatedDate -gt (Get-Date).AddDays(-90)
                }
            }

            # Sort results by risk level and application name
            $SortedResults = $DelegatedPermissionGrants | Sort-Object @{
                Expression = {
                    switch ($_.RiskLevel) {
                        'Critical' { 1 }
                        'High' { 2 }
                        'Medium' { 3 }
                        'Low' { 4 }
                        default { 5 }
                    }
                }
            }, ClientApplicationName, Permission

            Write-Verbose "Generated report with $($SortedResults.Count) permission grants"

            # Generate summary statistics using single-pass accumulation
            $GrantStats = @{
                AdminConsentGrants      = 0
                UserConsentGrants       = 0
                CriticalRiskPermissions = 0
                HighRiskPermissions     = 0
                MediumRiskPermissions   = 0
                LowRiskPermissions      = 0
                ExpiredGrants           = 0
                ExpiringIn30Days        = 0
            }
            $UniqueApplications = @{}
            if ($SortedResults) {
                foreach ($Grant in $SortedResults) {
                    # Consent type counts
                    if ($Grant.ConsentType -like '*Admin*') { $GrantStats.AdminConsentGrants++ }
                    elseif ($Grant.ConsentType -eq 'User Consent') { $GrantStats.UserConsentGrants++ }
                    # Risk level counts
                    switch ($Grant.RiskLevel) {
                        'Critical' { $GrantStats.CriticalRiskPermissions++ }
                        'High' { $GrantStats.HighRiskPermissions++ }
                        'Medium' { $GrantStats.MediumRiskPermissions++ }
                        'Low' { $GrantStats.LowRiskPermissions++ }
                    }
                    # Expiry counts
                    if ($Grant.IsExpired) { $GrantStats.ExpiredGrants++ }
                    if ($null -ne $Grant.DaysUntilExpiry -and $Grant.DaysUntilExpiry -le 30 -and $Grant.DaysUntilExpiry -gt 0) {
                        $GrantStats.ExpiringIn30Days++
                    }
                    # Unique applications
                    if ($Grant.ClientApplicationId) { $UniqueApplications[$Grant.ClientApplicationId] = $true }
                }
            }

            $Summary = [PSCustomObject]@{
                TotalPermissionGrants   = if ($SortedResults) { $SortedResults.Count } else { 0 }
                UniqueApplications      = $UniqueApplications.Count
                AdminConsentGrants      = $GrantStats.AdminConsentGrants
                UserConsentGrants       = $GrantStats.UserConsentGrants
                CriticalRiskPermissions = $GrantStats.CriticalRiskPermissions
                HighRiskPermissions     = $GrantStats.HighRiskPermissions
                MediumRiskPermissions   = $GrantStats.MediumRiskPermissions
                LowRiskPermissions      = $GrantStats.LowRiskPermissions
                ExpiredGrants           = $GrantStats.ExpiredGrants
                ExpiringIn30Days        = $GrantStats.ExpiringIn30Days
                ReportGeneratedDate     = Get-Date
                TenantId                = $TenantId
            }

            Write-Information "Service Principal permissions report completed - $($Summary.TotalPermissionGrants) permission grants analyzed" -InformationAction Continue

            [PSCustomObject]@{
                Summary                 = $Summary
                CriticalRiskPermissions = $SortedResults | Where-Object { $_.RiskLevel -eq 'Critical' } | Sort-Object ClientApplicationName, Permission
                HighRiskPermissions     = $SortedResults | Where-Object { $_.RiskLevel -eq 'High' } | Sort-Object ClientApplicationName, Permission
                MediumRiskPermissions   = $SortedResults | Where-Object { $_.RiskLevel -eq 'Medium' } | Sort-Object ClientApplicationName, Permission
                LowRiskPermissions      = $SortedResults | Where-Object { $_.RiskLevel -eq 'Low' } | Sort-Object ClientApplicationName, Permission
                AllPermissions          = $SortedResults
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntServicePrincipalPermissionReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntServicePrincipalPermissionReportError',
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
