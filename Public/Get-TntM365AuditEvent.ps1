function Get-TntM365AuditEvent {
    <#
    .SYNOPSIS
        Audits and reports on specific events in Microsoft 365 and Azure AD.

    .DESCRIPTION
        This function retrieves and processes audit logs for user lifecycle (creation, deletion) and group membership activities.
        Use the -AuditMode parameter to switch between the event streams while keeping authentication options consistent.

    .PARAMETER TenantId
        The Azure AD Tenant ID to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration with necessary permissions.

    .PARAMETER ClientSecret
        The client secret for the app registration.

    .PARAMETER CertificateThumbprint
        The thumbprint of a certificate for authentication.

    .PARAMETER DaysBack
        Number of days to look back for audit logs. Defaults to 30 days. Maximum is 30.

    .PARAMETER ExportToFile
        If specified, exports the report to a file in the specified format.

    .PARAMETER OutputPath
        The directory path where the report file will be saved. Defaults to the current directory.

    .PARAMETER OutputFormat
        The output format for the exported file. Valid values are 'CSV' or 'JSON'. Required if -ExportToFile is used.

    .PARAMETER UserFilter
        Filter results by the user principal name of the affected user. Supports wildcards.

    .PARAMETER InitiatedByFilter
        Filter results by the user principal name of the person who initiated the action. Supports wildcards.

    .PARAMETER GroupFilter
        (Group mode only) Filter results by the display name of the affected group. Supports wildcards.

    .PARAMETER AuditMode
        Selects the audit stream to query. Use 'User' for account lifecycle events (creation, deletion) or 'Group' for membership changes.
        Legacy modes 'UserCreation' and 'GroupMembership' are also supported.

    .EXAMPLE
        Get-TntM365AuditEvent -AuditMode User -TenantId "..." -ClientId "..." -ClientSecret $secret -DaysBack 14

        Retrieves all user creation and deletion events from the last 14 days.

    .EXAMPLE
        Get-TntM365AuditEvent -AuditMode Group -TenantId "..." -ClientId "..." -ClientSecret $secret -GroupFilter "*Admins*" |
        Export-Csv -Path ".\AdminGroupChanges.csv" -NoTypeInformation

        Retrieves group membership changes for any group with "Admins" in the name and exports the results to a CSV file.

    .EXAMPLE
        Get-TntM365AuditEvent -AuditMode User -TenantId "..." -ClientId "..." -ClientSecret $secret -ExportToFile -OutputFormat JSON -OutputPath "C:\AuditReports"

        Retrieves user lifecycle events and saves them to a JSON file in the C:\AuditReports directory.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a report object containing:
        - Summary: Statistics including TenantId, AuditMode, DaysBack, TotalEvents, SuccessfulEvents, FailedEvents
        - Details: Array of audit event objects with Timestamp, Activity, Result, InitiatedBy, and target information

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports
        Required Permissions:
        - AuditLog.Read.All (Application)
        - Directory.Read.All (Application)

    .LINK
        https://systom.dev
    #>
    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [Alias('ApplicationId')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Alias('ApplicationSecret')]
        [ValidateNotNullOrEmpty()]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$DaysBack = 30,

        [Parameter()]
        [string]$UserFilter,

        [Parameter()]
        [string]$InitiatedByFilter,

        [string]$GroupFilter,

        [Parameter()]
        [Alias('Mode')]
        [ValidateSet('User', 'Group', 'UserCreation', 'GroupMembership')]
        [string]$AuditMode = 'User'
    )

    begin {
        Write-Information "STARTED  : $AuditMode Audit event retrieval..." -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Define audit activities and properties based on the requested audit mode
            $AuditActivities = @()
            $IsGroupMode = $false

            switch ($AuditMode) {
                { $_ -in 'User', 'UserCreation' } {
                    $AuditActivities = @(
                        'Add user',
                        'Create user',
                        'Invite external user',
                        'Delete user'
                    )
                }
                { $_ -in 'Group', 'GroupMembership' } {
                    $AuditActivities = @(
                        'Add member to group',
                        'Remove member from group'
                    )
                    $IsGroupMode = $true
                }
                default {
                    $AuditActivities = @(
                        'Add user',
                        'Create user',
                        'Invite external user',
                        'Delete user'
                    )
                }
            }

            # Build a single, efficient filter for the API call
            $ActivityFilters = $AuditActivities.ForEach({ "activityDisplayName eq '$($_)'" })
            $FilterString    = $ActivityFilters -join ' or '
            $startDate       = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $FullFilter      = "activityDateTime ge $startDate and ($FilterString)"

            Write-Verbose "Retrieving audit logs with filter: $FullFilter"
            $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $FullFilter -All

            Write-Verbose "Retrieved $($auditLogs.Count) total log entries."

            $GroupCache = @{}
            if ($IsGroupMode) {
                Write-Verbose 'Pre-caching group names for audit events...'

                # Extract unique group IDs from all audit logs
                $UniqueGroupIdsSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($AuditLog in $auditLogs) {
                    foreach ($TargetResource in @($AuditLog.TargetResources)) {
                        if ($TargetResource.Type -eq 'Group' -and $TargetResource.Id) {
                            [void]$UniqueGroupIdsSet.Add($TargetResource.Id)
                        }
                    }
                }
                $UniqueGroupIds = @($UniqueGroupIdsSet)

                # Build cache with single API call per unique group
                foreach ($GroupId in $UniqueGroupIds) {
                    if (-not $GroupCache.ContainsKey($GroupId)) {
                        try {
                            $group = Get-MgGroup -GroupId $GroupId -Property DisplayName -ErrorAction Stop
                            $GroupCache[$GroupId] = $group.DisplayName
                        } catch {
                            Write-Warning "Could not retrieve group name for ID '$GroupId' - using ID as fallback"
                            $GroupCache[$GroupId] = $GroupId
                        }
                    }
                }

                Write-Verbose "Group name cache built with $($GroupCache.Count) entries"
            }

            # Process logs with cached lookups (no API calls in loop)
            Write-Verbose 'Processing audit events...'
            $Results = foreach ($log in $auditLogs) {
                # Determine initiator - can be either a User or an App (service principal)
                $InitiatedBy = if ($log.InitiatedBy.User.UserPrincipalName) {
                    $log.InitiatedBy.User.UserPrincipalName
                } elseif ($log.InitiatedBy.App.DisplayName) {
                    $log.InitiatedBy.App.DisplayName
                } else {
                    'Unknown'
                }

                # Common properties for all events
                $Output = [PSCustomObject]@{
                    Timestamp        = $log.ActivityDateTime
                    Activity         = $log.ActivityDisplayName
                    Result           = $log.Result
                    InitiatedBy      = $InitiatedBy
                    InitiatedByIP    = $log.InitiatedBy.User.IPAddress
                    TargetUserUPN    = ''
                    TargetDeviceName = ''
                    TargetGroupName  = ''
                    TargetObjectID   = ''
                }

                # Extract target resources. An event can have multiple targets.
                $targetUser = $null
                $targetDevice = $null
                $targetGroup = $null
                foreach ($TargetResource in @($log.TargetResources)) {
                    switch ($TargetResource.Type) {
                        'User' {
                            if (-not $targetUser) { $targetUser = $TargetResource }
                        }
                        'Device' {
                            if (-not $targetDevice) { $targetDevice = $TargetResource }
                        }
                        'Group' {
                            if (-not $targetGroup) { $targetGroup = $TargetResource }
                        }
                    }

                    if ($targetUser -and $targetDevice -and $targetGroup) {
                        break
                    }
                }

                if ($targetUser) {
                    $Output.TargetUserUPN = $targetUser.UserPrincipalName
                    $Output.TargetObjectID = $targetUser.Id
                }
                if ($targetDevice) {
                    $Output.TargetDeviceName = $targetDevice.DisplayName
                    $Output.TargetObjectID = $targetDevice.Id
                }
                if ($targetGroup) {
                    $GroupId = $targetGroup.Id
                    # Overwrite TargetObjectID if group is the primary target
                    $Output.TargetObjectID = $targetGroup.Id

                    if ($GroupCache.ContainsKey($GroupId)) {
                        $Output.TargetGroupName = $GroupCache[$GroupId]
                    } else {
                        # Fallback if group not in cache (shouldn't happen)
                        Write-Verbose "Cache miss for group ID: $GroupId (using DisplayName from audit log)"
                        $Output.TargetGroupName = $targetGroup.DisplayName ?? $GroupId
                    }
                }

                # Apply client-side filters
                $isMatch = $true
                if ($InitiatedByFilter -and $Output.InitiatedBy -notlike $InitiatedByFilter) { $isMatch = $false }
                if ($UserFilter -and $Output.TargetUserUPN -notlike $UserFilter) { $isMatch = $false }
                if ($IsGroupMode -and $GroupFilter -and $Output.TargetGroupName -notlike $GroupFilter) { $isMatch = $false }

                if ($isMatch) {
                    # Output the object to the pipeline
                    $Output
                }
            }

            Write-Information "FINISHED : $AuditMode Audit event retrieval - $($Results.Count) matching events found" -InformationAction Continue

            [PSCustomObject]@{
                Summary = [PSCustomObject]@{
                    TenantId            = $TenantId
                    ReportGeneratedDate = Get-Date
                    AuditMode           = $AuditMode
                    DaysBack            = $DaysBack
                    TotalEvents         = $Results.Count
                    SuccessfulEvents    = $Results.Where({ $_.Result -eq 'success' }).Count
                    FailedEvents        = $Results.Where({ $_.Result -eq 'failure' }).Count
                }
                Details = $Results
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntM365AuditEvent failed: $($_.Exception.Message)", $_.Exception),
                'GetTntM365AuditEventError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo | Out-Null
            }
        }
    }
}
