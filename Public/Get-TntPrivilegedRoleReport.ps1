function Get-TntPrivilegedRoleReport {
    <#
    .SYNOPSIS
        Generates a report of permanent privileged role assignments and emergency access accounts.

    .DESCRIPTION
        This function analyzes permanent privileged role assignments in Azure AD, identifies emergency
        access accounts, and retrieves role activation audit logs. This function does NOT require an
        Azure AD Premium P2 license, as it focuses on permanent role assignments rather than PIM.

        For PIM-specific analysis (eligible and active assignments), use Get-TntPIMReport.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER LookbackDays
        Number of days to look back for activation pattern analysis. Defaults to 30 days.

    .PARAMETER EmergencyAccountPattern
        Regex pattern to identify emergency access accounts. Defaults to common patterns.

    .EXAMPLE
        Get-TntPrivilegedRoleReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a privileged role report for permanent assignments and emergency accounts.

    .EXAMPLE
        Get-TntPrivilegedRoleReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -LookbackDays 90

        Generates a report analyzing the last 90 days of role activation logs.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a privileged role report object with:
        - Summary: Statistics on assignments and activations
        - PermanentAssignments: Detailed list of permanent role assignments
        - RoleActivations: Audit logs of role activations
        - EmergencyAccessAccounts: Identified break-glass accounts
        - AssignmentsByRole: Grouped count of assignments per role

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - RoleManagement.Read.Directory (Application)
        - Directory.Read.All (Application)
        - AuditLog.Read.All (Application)

        Prerequisites:
        - No Azure AD Premium P2 license required (unlike PIM-based analysis)
        - Security Reader, Global Reader, or equivalent role to query privileged assignments.

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

        # Use interactive authentication .
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$LookbackDays = 30,

        [Parameter()]
        [string]$EmergencyAccountPattern = '(emergency|break-?glass|admin-?break|bg-|ea-)'
    )

    begin {
        # Calculate date range for analysis
        $StartDate       = [datetime]::Now.AddDays(-$LookbackDays)
        $StartDateString = $StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

        Write-Information 'Starting privileged role report generation...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            # Initialize collections
            $PermanentAssignments = [System.Collections.Generic.List[PSObject]]::new()
            $RoleActivations      = [System.Collections.Generic.List[PSObject]]::new()
            $EmergencyAccounts    = [System.Collections.Generic.List[PSObject]]::new()

            # Get all role definitions to identify privileged roles
            Write-Verbose 'Retrieving role definitions...'
            $RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop

            # Client-side filtering required: Graph API does not support filtering by DisplayName array or IsBuiltIn property
            $PrivilegedRoles = @($RoleDefinitions.Where({
                    $_.DisplayName -in $script:PrivilegedRoleNames -or $_.IsBuiltIn -eq $false
                }))

            $PrivilegedRoleLookup = @{}
            foreach ($PrivilegedRole in $PrivilegedRoles) {
                $PrivilegedRoleLookup[$PrivilegedRole.Id] = $PrivilegedRole
            }

            Write-Verbose "Identified $($PrivilegedRoles.Count) privileged roles"

            # Get permanent role assignments
            Write-Verbose 'Retrieving permanent role assignments...'
            $AllPermanentAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop

            # Pre-scan: collect group/SP IDs that need name resolution
            $GroupIdsToResolve = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $SPIdsToResolve    = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $PrivilegedRoleIds = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]$PrivilegedRoles.ForEach({ $_.Id }),
                [StringComparer]::OrdinalIgnoreCase
            )

            foreach ($Assignment in $AllPermanentAssignments) {
                if (-not $PrivilegedRoleIds.Contains($Assignment.RoleDefinitionId)) { continue }

                $HasName = $Assignment.Principal.DisplayName -or $Assignment.Principal.AdditionalProperties.displayName
                if (-not $HasName -and $Assignment.PrincipalId) {
                    $Type = ($Assignment.Principal.AdditionalProperties.'@odata.type' ?? '') -replace '#microsoft.graph.', ''
                    switch ($Type) {
                        'group'            { [void]$GroupIdsToResolve.Add($Assignment.PrincipalId) }
                        'servicePrincipal' { [void]$SPIdsToResolve.Add($Assignment.PrincipalId) }
                    }
                }
            }

            # Batch resolve collected IDs
            $PrincipalLookup = Resolve-GraphObjectNames -GroupIds @($GroupIdsToResolve) -ServicePrincipalIds @($SPIdsToResolve)

            foreach ($Assignment in $AllPermanentAssignments) {
                $Role = $PrivilegedRoleLookup[$Assignment.RoleDefinitionId]
                if ($Role) {
                    $PrincipalType = if ($Assignment.Principal.AdditionalProperties.'@odata.type') {
                        $Assignment.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                    } else {
                        'Unknown'
                    }

                    # Get PrincipalName - check direct property first, then AdditionalProperties
                    $PrincipalName = $Assignment.Principal.DisplayName
                    if (-not $PrincipalName) {
                        $PrincipalName = $Assignment.Principal.AdditionalProperties.displayName
                    }

                    # If still empty, use pre-fetched lookup
                    if (-not $PrincipalName -and $Assignment.PrincipalId) {
                        $PrincipalName = switch ($PrincipalType) {
                            'group'            { $PrincipalLookup.GroupLookup[$Assignment.PrincipalId] }
                            'servicePrincipal' { $PrincipalLookup.SPLookup[$Assignment.PrincipalId] }
                        }
                    }

                    $PrincipalUPN = $Assignment.Principal.AdditionalProperties.userPrincipalName

                    $PermanentAssignments.Add([PSCustomObject]@{
                            AssignmentId       = $Assignment.Id
                            RoleId             = $Role.Id
                            RoleName           = $Role.DisplayName
                            RoleType           = if ($Role.IsBuiltIn) { 'Built-in' } else { 'Custom' }
                            PrincipalId        = $Assignment.PrincipalId
                            PrincipalName      = $PrincipalName
                            PrincipalUPN       = $PrincipalUPN
                            PrincipalType      = $PrincipalType
                            AssignmentType     = 'Permanent'
                            CreatedDateTime    = $Assignment.CreatedDateTime
                            ExpirationDateTime = $null
                            IsEmergencyAccount = if ($PrincipalUPN) {
                                $PrincipalUPN -match $EmergencyAccountPattern -or $PrincipalName -match $EmergencyAccountPattern
                            } else { $false }
                        })
                }
            }

            # Get role activations from audit logs
            Write-Verbose 'Retrieving role activation audit logs...'
            try {
                $AuditFilter = "activityDateTime ge $($StartDateString) and category eq 'RoleManagement'"
                $AuditLogs   = Get-MgAuditLogDirectoryAudit -Filter $AuditFilter -All -ErrorAction Stop

                $RoleActivationLogs = @($AuditLogs.Where({
                            $_.ActivityDisplayName -match 'Add member to role|Role activation|Activate role'
                        }))

                foreach ($Log in $RoleActivationLogs) {
                    $RoleActivations.Add([PSCustomObject]@{
                            Id                      = $Log.Id
                            ActivityDateTime        = $Log.ActivityDateTime
                            ActivityDisplayName     = $Log.ActivityDisplayName
                            InitiatedBy             = $Log.InitiatedBy.User.UserPrincipalName
                            TargetRole              = @($Log.TargetResources).Where({ $_.Type -eq 'Role' }).DisplayName
                            TargetUserPrincipalName = @($Log.TargetResources).Where({ $_.Type -eq 'User' }).UserPrincipalName
                            Result                  = $Log.Result
                            ResultReason            = $Log.ResultReason
                        })
                }
            } catch {
                Write-Warning "Unable to retrieve audit logs: $($_.Exception.Message)"
            }

            # Identify emergency access accounts
            Write-Verbose 'Analyzing emergency access accounts...'
            $PotentialEmergencyAccounts = $PermanentAssignments.Where({
                    $_.IsEmergencyAccount -or
                    ($_.RoleName -eq 'Global Administrator' -and $_.AssignmentType -eq 'Permanent')
                }) | Select-Object PrincipalId, PrincipalName, PrincipalUPN -Unique

            # Pre-fetch emergency account users (incremental mode - only specific users needed)
            $EmergencyPrincipalIds = @($PotentialEmergencyAccounts | Select-Object -ExpandProperty PrincipalId -Unique)
            $UserCache             = $null
            $Now                   = [datetime]::Now
            if ($EmergencyPrincipalIds.Count -gt 0) {
                Write-Verbose "Pre-fetching $($EmergencyPrincipalIds.Count) emergency account users (incremental mode)..."
                $CacheParams = @{
                    TenantId           = $TenantId
                    ClientId           = $ClientId
                    UserIds            = $EmergencyPrincipalIds
                    RequiredProperties = @('CreatedDateTime', 'SignInActivity')
                    ForceBetaAPI       = $true
                }
                $UserCache = Get-CachedUsers @CacheParams
                Write-Verbose "User cache ready: $($UserCache.UserCount) users (CacheHit: $($UserCache.CacheHit))"
            }

            foreach ($Account in $PotentialEmergencyAccounts) {
                try {
                    # O(1) lookup from pre-fetched cache
                    $User = $null
                    if ($UserCache) {
                        $User = $UserCache.LookupById[$Account.PrincipalId]
                    }

                    # Fallback to individual API call if not in cache
                    if (-not $User) {
                        $User = Get-MgUser -UserId $Account.PrincipalId -Property Id, DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime, SignInActivity -ErrorAction SilentlyContinue
                    }

                    if ($User) {
                        $AccountRoles = @($PermanentAssignments.Where({ $_.PrincipalId -eq $Account.PrincipalId }))
                        $LastSignIn   = $User.SignInActivity.LastSignInDateTime

                        # Validate LastSignIn - handle "-" or empty string values
                        if ($LastSignIn -is [string] -and ($LastSignIn -eq '-' -or [string]::IsNullOrWhiteSpace($LastSignIn))) {
                            $LastSignIn = $null
                        }

                        $EmergencyAccounts.Add([PSCustomObject]@{
                                UserId                  = $User.Id
                                DisplayName             = $User.DisplayName
                                UserPrincipalName       = $User.UserPrincipalName
                                AccountEnabled          = $User.AccountEnabled
                                CreatedDateTime         = $User.CreatedDateTime
                                LastSignInDateTime      = $LastSignIn
                                AssignedRoles           = ($AccountRoles.RoleName | Sort-Object -Unique) -join '; '
                                PermanentRoles          = ($AccountRoles.RoleName) -join '; '
                                HasPermanentGlobalAdmin = @($AccountRoles.Where({ $_.RoleName -eq 'Global Administrator' })).Count -gt 0
                                MatchesNamingPattern    = $User.UserPrincipalName -match $EmergencyAccountPattern -or $User.DisplayName -match $EmergencyAccountPattern
                                DaysSinceLastSignIn     = if ($LastSignIn -and $LastSignIn -is [datetime]) {
                                    [math]::Round(($Now - $LastSignIn).TotalDays, 0)
                                } else { $null }
                            })
                    }
                } catch {
                    Write-Verbose "Unable to retrieve details for user $($Account.PrincipalId): $($_.Exception.Message)"
                }
            }

            $UniquePrivilegedUsers = ($PermanentAssignments.Where({ $_.PrincipalType -eq 'user' }) | Select-Object PrincipalId -Unique).Count

            $Summary = [PSCustomObject]@{
                TenantId                  = $TenantId
                ReportGeneratedDate       = Get-Date
                AnalysisPeriodDays        = $LookbackDays
                TotalPermanentAssignments = $PermanentAssignments.Count
                UniquePrivilegedUsers     = $UniquePrivilegedUsers
                EmergencyAccessAccounts   = $EmergencyAccounts.Count
                RoleActivationsInPeriod   = $RoleActivations.Count
                GlobalAdministrators      = $PermanentAssignments.Where({ $_.RoleName -eq 'Global Administrator' }).Count
                CustomRoles               = ($PermanentAssignments.Where({ $_.RoleType -eq 'Custom' }) | Select-Object RoleId -Unique).Count
            }

            Write-Information "Privileged role report completed - $($PermanentAssignments.Count) permanent assignments found" -InformationAction Continue

            [PSCustomObject]@{
                Summary                 = $Summary
                PermanentAssignments    = $PermanentAssignments | Sort-Object RoleName, PrincipalName
                RoleActivations         = $RoleActivations | Sort-Object ActivityDateTime -Descending
                EmergencyAccessAccounts = $EmergencyAccounts | Sort-Object DisplayName
                AssignmentsByRole       = ($PermanentAssignments | Group-Object RoleName).ForEach({
                        [PSCustomObject]@{
                            RoleName         = $_.Name
                            TotalAssignments = $_.Count
                        }
                    }) | Sort-Object TotalAssignments -Descending
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntPrivilegedRoleReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntPrivilegedRoleReportError',
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
