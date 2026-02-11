function Get-TntConditionalAccessReport {
    <#
    .SYNOPSIS
        Analyzes and reports on Azure AD Conditional Access policies, their coverage, effectiveness, and security gaps.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and generates comprehensive reports
        about Conditional Access policies. It identifies policy coverage gaps and analyzes effectiveness.

        in PowerShell scripts.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Accepts SecureString or plain String.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER ExcludeDisabledPolicies
        Switch to exclude disabled policies from the analysis. By default, disabled policies are included.

    .PARAMETER FilterByState
        Filter policies by state: Enabled, Disabled, or All. Default is Enabled.

    .EXAMPLE
        Get-TntConditionalAccessReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a comprehensive Conditional Access policy report.

    .EXAMPLE
        Get-TntConditionalAccessReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret |
            ConvertTo-Json -Depth 10 | Out-File -Path 'CA_Report.json'

        Exports the report to JSON format.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured report object containing:
        - Summary: Policy counts, scenario coverage
        - PolicyAnalysis: Detailed per-policy analysis
        - NamedLocations: Location definitions
        - PolicyByScenario: Policies grouped by security scenario

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Azure AD Application Permissions:
        - Policy.Read.All (Application)
        - Directory.Read.All (Application)
        - Application.Read.All (Application)
        - User.Read.All (Application)
        - Group.Read.All (Application)
        - RoleManagement.Read.Directory (Application)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        # Tenant ID of the Microsoft 365 tenant.
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        # Application (client) ID of the registered app.
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [Alias('ApplicationId')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [string]$ClientId,

        # Client secret credential when using secret-based authentication.
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Alias('ApplicationSecret')]
        [ValidateNotNullOrEmpty()]
        [SecureString]$ClientSecret,

        # Certificate thumbprint for certificate-based authentication.
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        # Use interactive authentication (no app registration required).
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        # Switch to exclude disabled policies from the report.
        [Parameter()]
        [switch]$ExcludeDisabledPolicies,

        # Optional state filter for policies.
        [Parameter()]
        [ValidateSet('Enabled', 'Disabled', 'All')]
        [string]$FilterByState = 'All'
    )

    begin {
        Write-Information 'Starting Conditional Access policy analysis...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            # Retrieve all Conditional Access policies
            Write-Verbose 'Retrieving Conditional Access policies...'
            $AllPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            
            # Filter based on state if requested
            $PoliciesToAnalyze = switch ($FilterByState) {
                'Enabled' { $AllPolicies | Where-Object { $_.State -eq 'enabled' } }
                'Disabled' { $AllPolicies | Where-Object { $_.State -eq 'disabled' } }
                'All' { $AllPolicies }
            }

            if ($ExcludeDisabledPolicies -and $FilterByState -eq 'All') {
                $PoliciesToAnalyze = $PoliciesToAnalyze | Where-Object { $_.State -eq 'enabled' }
            }

            Write-Verbose "Found $($PoliciesToAnalyze.Count) policies to analyze"

            # Get additional data for analysis
            Write-Verbose 'Retrieving named locations...'
            $NamedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue

            # Build named location lookup for O(1) access
            $LocationLookup = @{}
            foreach ($Location in $NamedLocations) {
                if ($Location.Id) { $LocationLookup[$Location.Id] = $Location.DisplayName }
            }

            # Collect all unique GUIDs from policies for batch resolution
            Write-Verbose 'Collecting GUIDs for name resolution...'
            $AllUserIds  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $AllGroupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $AllAppIds   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $AllRoleIds  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

            # Special values that should not be resolved
            $SpecialUserValues     = @('All', 'None', 'GuestsOrExternalUsers')
            $SpecialAppValues      = @('All', 'None', 'Office365', 'MicrosoftAdminPortals')
            $SpecialLocationValues = @('All', 'AllTrusted', 'None', '00000000-0000-0000-0000-000000000000')

            # GUID pattern for validation
            $GuidPattern = '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'

            foreach ($Policy in $PoliciesToAnalyze) {
                $Conditions = $Policy.Conditions
                if ($Conditions.Users) {
                    foreach ($Id in $Conditions.Users.IncludeUsers) {
                        if ($Id -and $Id -notin $SpecialUserValues -and $Id -match $GuidPattern) {
                            [void]$AllUserIds.Add($Id)
                        }
                    }
                    foreach ($Id in $Conditions.Users.ExcludeUsers) {
                        if ($Id -and $Id -notin $SpecialUserValues -and $Id -match $GuidPattern) {
                            [void]$AllUserIds.Add($Id)
                        }
                    }
                    foreach ($Id in $Conditions.Users.IncludeGroups) {
                        if ($Id -and $Id -match $GuidPattern) { [void]$AllGroupIds.Add($Id) }
                    }
                    foreach ($Id in $Conditions.Users.ExcludeGroups) {
                        if ($Id -and $Id -match $GuidPattern) { [void]$AllGroupIds.Add($Id) }
                    }
                    foreach ($Id in $Conditions.Users.IncludeRoles) {
                        if ($Id -and $Id -match $GuidPattern) { [void]$AllRoleIds.Add($Id) }
                    }
                    foreach ($Id in $Conditions.Users.ExcludeRoles) {
                        if ($Id -and $Id -match $GuidPattern) { [void]$AllRoleIds.Add($Id) }
                    }
                }
                if ($Conditions.Applications) {
                    foreach ($Id in $Conditions.Applications.IncludeApplications) {
                        if ($Id -and $Id -notin $SpecialAppValues -and $Id -match $GuidPattern) {
                            [void]$AllAppIds.Add($Id)
                        }
                    }
                    foreach ($Id in $Conditions.Applications.ExcludeApplications) {
                        if ($Id -and $Id -notin $SpecialAppValues -and $Id -match $GuidPattern) {
                            [void]$AllAppIds.Add($Id)
                        }
                    }
                }
            }

            # Batch resolve users using cached user lookup
            $UserLookup = @{}
            if ($AllUserIds.Count -gt 0) {
                Write-Verbose "Resolving $($AllUserIds.Count) user GUIDs..."
                $UserCache = Get-CachedUsers -TenantId $TenantId -ClientId $ClientId -UserIds @($AllUserIds)
                # Extract display names from user objects
                foreach ($UserId in $UserCache.LookupById.Keys) {
                    $User = $UserCache.LookupById[$UserId]
                    if ($User.DisplayName) {
                        $UserLookup[$UserId] = $User.DisplayName
                    }
                }
            }

            # Batch resolve groups and applications using shared helper
            $Resolved    = Resolve-GraphObjectNames -GroupIds @($AllGroupIds) -ApplicationIds @($AllAppIds)
            $GroupLookup = $Resolved.GroupLookup
            $AppLookup   = $Resolved.AppLookup

            # Batch resolve directory roles
            $RoleLookup = @{}
            if ($AllRoleIds.Count -gt 0) {
                Write-Verbose "Resolving $($AllRoleIds.Count) role GUIDs..."
                $RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction SilentlyContinue
                foreach ($Role in $RoleDefinitions) {
                    if ($Role.Id) { $RoleLookup[$Role.Id] = $Role.DisplayName }
                }
            }

            # Helper function to resolve a GUID to display name
            function Resolve-DisplayName {
                param(
                    [string]$Id,
                    [hashtable]$Lookup,
                    [string[]]$SpecialValues = @()
                )
                if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
                if ($Id -in $SpecialValues) { return $Id }
                if ($Lookup.ContainsKey($Id)) {
                    return $Lookup[$Id]
                }
                return $Id
            }

            # Analyze each policy
            $PolicyAnalysis = [System.Collections.Generic.List[PSObject]]::new()

            foreach ($Policy in $PoliciesToAnalyze) {
                # Analyze conditions
                $Conditions           = $Policy.Conditions
                $IncludedUsersRaw     = @()
                $ExcludedUsersRaw     = @()
                $IncludedGroupsRaw    = @()
                $ExcludedGroupsRaw    = @()
                $IncludedAppsRaw      = @()
                $ExcludedAppsRaw      = @()
                $IncludedLocationsRaw = @()
                $ExcludedLocationsRaw = @()
                $IncludedRolesRaw     = @()
                $ExcludedRolesRaw     = @()
                $Platforms            = @()
                $ClientAppTypes       = @()

                # Process user conditions
                if ($Conditions.Users) {
                    $IncludedUsersRaw  = $Conditions.Users.IncludeUsers ?? @()
                    $ExcludedUsersRaw  = $Conditions.Users.ExcludeUsers ?? @()
                    $IncludedGroupsRaw = $Conditions.Users.IncludeGroups ?? @()
                    $ExcludedGroupsRaw = $Conditions.Users.ExcludeGroups ?? @()
                    $IncludedRolesRaw  = $Conditions.Users.IncludeRoles ?? @()
                    $ExcludedRolesRaw  = $Conditions.Users.ExcludeRoles ?? @()
                }

                # Process application conditions
                if ($Conditions.Applications) {
                    $IncludedAppsRaw = $Conditions.Applications.IncludeApplications ?? @()
                    $ExcludedAppsRaw = $Conditions.Applications.ExcludeApplications ?? @()
                }

                # Process location conditions
                if ($Conditions.Locations) {
                    $IncludedLocationsRaw = $Conditions.Locations.IncludeLocations ?? @()
                    $ExcludedLocationsRaw = $Conditions.Locations.ExcludeLocations ?? @()
                }

                # Process platform conditions
                if ($Conditions.Platforms) {
                    $Platforms = $Conditions.Platforms.IncludePlatforms ?? @()
                }

                # Process client app types
                if ($Conditions.ClientAppTypes) {
                    $ClientAppTypes = $Conditions.ClientAppTypes
                }

                # Resolve GUIDs to display names
                $IncludedUsers     = @($IncludedUsersRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $UserLookup -SpecialValues $SpecialUserValues } | Where-Object { $_ })
                $ExcludedUsers     = @($ExcludedUsersRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $UserLookup -SpecialValues $SpecialUserValues } | Where-Object { $_ })
                $IncludedGroups    = @($IncludedGroupsRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $GroupLookup } | Where-Object { $_ })
                $ExcludedGroups    = @($ExcludedGroupsRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $GroupLookup } | Where-Object { $_ })
                $IncludedApps      = @($IncludedAppsRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $AppLookup -SpecialValues $SpecialAppValues } | Where-Object { $_ })
                $ExcludedApps      = @($ExcludedAppsRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $AppLookup -SpecialValues $SpecialAppValues } | Where-Object { $_ })
                $IncludedLocations = @($IncludedLocationsRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $LocationLookup -SpecialValues $SpecialLocationValues } | Where-Object { $_ })
                $ExcludedLocations = @($ExcludedLocationsRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $LocationLookup -SpecialValues $SpecialLocationValues } | Where-Object { $_ })
                $IncludedRoles     = @($IncludedRolesRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $RoleLookup } | Where-Object { $_ })
                $ExcludedRoles     = @($ExcludedRolesRaw | ForEach-Object { Resolve-DisplayName -Id $_ -Lookup $RoleLookup } | Where-Object { $_ })

                # Analyze grant controls
                $GrantControls           = $Policy.GrantControls
                $RequiresMfa             = $false
                $RequiresCompliantDevice = $false
                $RequiresHybridJoin      = $false
                $RequiresApprovedApp     = $false
                $BlockAccess             = $false
                $RequiresPasswordChange  = $false

                if ($GrantControls) {
                    $RequiresMfa             = ('mfa' -in $GrantControls.BuiltInControls) -or ('Multifactor authentication' -in $GrantControls.AuthenticationStrength.DisplayName)
                    $RequiresCompliantDevice = 'compliantDevice' -in $GrantControls.BuiltInControls
                    $RequiresHybridJoin      = 'domainJoinedDevice' -in $GrantControls.BuiltInControls
                    $RequiresApprovedApp     = 'approvedApplication' -in $GrantControls.BuiltInControls
                    $BlockAccess             = 'block' -in $GrantControls.BuiltInControls
                    $RequiresPasswordChange  = 'passwordChange' -in $GrantControls.BuiltInControls
                }

                # Determine policy type/scenario (use raw values for logic)
                $PolicyScenario = 'General Access Control'
                if ($IncludedRolesRaw.Count -gt 0) {
                    $PolicyScenario = 'Admin Protection'
                } elseif ('GuestsOrExternalUsers' -in $IncludedUsersRaw) {
                    $PolicyScenario = 'Guest Access Control'
                } elseif ($ClientAppTypes.Count -gt 0 -and $BlockAccess) {
                    $PolicyScenario = 'Legacy Authentication Block'
                } elseif ($RequiresCompliantDevice -or $RequiresHybridJoin) {
                    $PolicyScenario = 'Device-based Access Control'
                }

                # Create policy analysis entry
                $PolicyEntry = [PSCustomObject]@{
                    PolicyId                 = $Policy.Id
                    PolicyName               = $Policy.DisplayName
                    State                    = $Policy.State
                    CreatedDateTime          = $Policy.CreatedDateTime
                    ModifiedDateTime         = $Policy.ModifiedDateTime
                    PolicyScenario           = $PolicyScenario

                    # Conditions (with resolved display names)
                    IncludedUsers            = $IncludedUsers -join '; '
                    ExcludedUsers            = $ExcludedUsers -join '; '
                    IncludedGroups           = $IncludedGroups -join '; '
                    ExcludedGroups           = $ExcludedGroups -join '; '
                    IncludedRoles            = $IncludedRoles -join '; '
                    ExcludedRoles            = $ExcludedRoles -join '; '
                    IncludedApplications     = $IncludedApps -join '; '
                    ExcludedApplications     = $ExcludedApps -join '; '
                    IncludedLocations        = $IncludedLocations -join '; '
                    ExcludedLocations        = $ExcludedLocations -join '; '
                    Platforms                = $Platforms -join '; '
                    ClientAppTypes           = $ClientAppTypes -join '; '

                    # Controls
                    RequiresMFA              = $RequiresMfa
                    RequiresCompliantDevice  = $RequiresCompliantDevice
                    RequiresHybridJoin       = $RequiresHybridJoin
                    RequiresApprovedApp      = $RequiresApprovedApp
                    BlocksAccess             = $BlockAccess
                    RequiresPasswordChange   = $RequiresPasswordChange
                    GrantOperator            = $GrantControls.Operator ?? 'AND'

                    # Analysis (use raw values for logic)
                    HasExclusions            = ($ExcludedUsersRaw.Count + $ExcludedGroupsRaw.Count + $ExcludedAppsRaw.Count + $ExcludedLocationsRaw.Count) -gt 0
                    IsHighValueAppProtection = $IncludedAppsRaw.Count -gt 0 -and $IncludedAppsRaw[0] -ne 'All'
                    CoversGuestUsers         = 'GuestsOrExternalUsers' -in $IncludedUsersRaw
                    CoversAllUsers           = 'All' -in $IncludedUsersRaw
                    CoversAllApps            = 'All' -in $IncludedAppsRaw
                }

                $PolicyAnalysis.Add($PolicyEntry)
            }

            # Create comprehensive report using single-pass accumulation
            $PolicyStats = @{
                EnabledPolicies    = 0
                DisabledPolicies   = 0
                ReportOnlyPolicies = 0
            }
            foreach ($Policy in $AllPolicies) {
                switch ($Policy.State) {
                    'enabled' { $PolicyStats.EnabledPolicies++ }
                    'disabled' { $PolicyStats.DisabledPolicies++ }
                    'enabledForReportingButNotEnforced' { $PolicyStats.ReportOnlyPolicies++ }
                }
            }

            $AnalysisStats = @{
                PoliciesRequiringMFA        = 0
                PoliciesRequiringCompliance = 0
                PoliciesBlockingAccess      = 0
                AdminProtectionPolicies     = 0
                GuestControlPolicies        = 0
                LegacyAuthBlockPolicies     = 0
            }
            foreach ($PA in $PolicyAnalysis) {
                if ($PA.RequiresMFA) { $AnalysisStats.PoliciesRequiringMFA++ }
                if ($PA.RequiresCompliantDevice -or $PA.RequiresHybridJoin) { $AnalysisStats.PoliciesRequiringCompliance++ }
                if ($PA.BlocksAccess) { $AnalysisStats.PoliciesBlockingAccess++ }
                switch ($PA.PolicyScenario) {
                    'Admin Protection' { $AnalysisStats.AdminProtectionPolicies++ }
                    'Guest Access Control' { $AnalysisStats.GuestControlPolicies++ }
                    'Legacy Authentication Block' { $AnalysisStats.LegacyAuthBlockPolicies++ }
                }
            }

            $Summary = [PSCustomObject]@{
                ReportGeneratedDate         = Get-Date
                TenantId                    = $TenantId
                TotalPolicies               = $AllPolicies.Count
                EnabledPolicies             = $PolicyStats.EnabledPolicies
                DisabledPolicies            = $PolicyStats.DisabledPolicies
                ReportOnlyPolicies          = $PolicyStats.ReportOnlyPolicies
                PoliciesRequiringMFA        = $AnalysisStats.PoliciesRequiringMFA
                PoliciesRequiringCompliance = $AnalysisStats.PoliciesRequiringCompliance
                PoliciesBlockingAccess      = $AnalysisStats.PoliciesBlockingAccess
                AdminProtectionPolicies     = $AnalysisStats.AdminProtectionPolicies
                GuestControlPolicies        = $AnalysisStats.GuestControlPolicies
                LegacyAuthBlockPolicies     = $AnalysisStats.LegacyAuthBlockPolicies
            }

            Write-Information "Conditional Access policy analysis completed - $($PoliciesToAnalyze.Count) policies analyzed" -InformationAction Continue

            [PSCustomObject]@{
                Summary          = $Summary
                PolicyAnalysis   = $PolicyAnalysis | Sort-Object State, PolicyName
                NamedLocations   = $NamedLocations ?? @()
                PolicyByScenario = $PolicyAnalysis | Group-Object PolicyScenario | ForEach-Object {
                    [PSCustomObject]@{
                        Scenario    = $_.Name
                        PolicyCount = $_.Count
                        Policies    = $_.Group | Select-Object PolicyName, State
                    }
                }
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntConditionalAccessReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntConditionalAccessReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            # Cleanup connections
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}

