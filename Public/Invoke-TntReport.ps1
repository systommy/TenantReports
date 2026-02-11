function Invoke-TntReport {
    <#
    .SYNOPSIS
        Generates a security report using all TenantReports functions.

    .DESCRIPTION
        This function executes all available security report functions from the TenantReports module
        and consolidates the results into a structured PSCustomObject. It provides a complete
        security posture assessment for Microsoft 365 environments.

    .PARAMETER TenantId
        The Azure AD tenant ID (GUID) to generate reports for.

    .PARAMETER ClientId
        The Azure AD application (client) ID used for authentication.

    .PARAMETER ClientSecret
        The client secret for the Azure AD application. Accepts SecureString or plain String.

    .PARAMETER CertificateThumbprint
        The certificate thumbprint for certificate-based authentication (alternative to ClientSecret).

    .PARAMETER OutputPath
        The directory path where the JSON report will be saved. If not specified, no file is written.

    .PARAMETER OutputFileName
        The filename for the JSON report. Defaults to 'SecurityReport_YYYYMMDD_HHMMSS.json'

    .PARAMETER IncludeAuditReports
        Switch to include audit analysis (group membership, user creation).

    .PARAMETER IncludeMailboxPermissions
        Switch to include Exchange Online mailbox delegation permissions analysis (FullAccess, SendAs, SendOnBehalf).

    .PARAMETER IncludeCalendarPermissions
        Switch to include Exchange Online calendar folder permissions analysis. Note: This can be time-consuming for large tenants.

    .PARAMETER AuditDaysBack
        Number of days to look back for audit analysis. Defaults to 30 days.

    .PARAMETER IncludeSections
        Array of section names to include in the report. If specified, only these sections will be generated.
        Use tab completion to see available sections. Cannot be used with -ExcludeSections.

    .PARAMETER ExcludeSections
        Array of section names to exclude from the report. If specified, all sections except these will be generated.
        Use tab completion to see available sections. Cannot be used with -IncludeSections.

    .PARAMETER TenantName
        Optional friendly name for the tenant (used in report metadata).

    .EXAMPLE
        Invoke-TntReport -TenantId "guid" -ClientId "guid" -ClientSecret $secret

        Generates a complete security report and returns a PSCustomObject.

    .EXAMPLE
        Invoke-TntReport -TenantId "guid" -ClientId "guid" -ClientSecret $secret |
            ConvertTo-Json -Depth 100 | Out-File "SecurityReport.json"

        Generates report and exports to JSON file.

    .EXAMPLE
        $Report = Invoke-TntReport -TenantId "guid" -ClientId "guid" -CertificateThumbprint "thumbprint" `
            -IncludeAuditReports -IncludeMailboxPermissions -IncludeCalendarPermissions

        Generates full report including audit analysis, mailbox permissions, and calendar permissions.

    .EXAMPLE
        Invoke-TntReport -TenantId "guid" -ClientId "guid" -ClientSecret $secret `
            -IncludeSections 'TenantInfo','SecureScore','ConditionalAccess'

        Generates a report with only the specified sections.

    .EXAMPLE
        $Report = Invoke-TntReport @params -ExcludeSections 'ServicePrincipals','Intune'
        $Report.ConditionalAccess.Recommendations | Where-Object Priority -eq 'High'

        Generates report excluding specific sections and filters high-priority recommendations.

    .EXAMPLE
        Invoke-TntReport -Interactive

        Generates a security report using interactive authentication (no app registration required).
        Note: RiskyUsers and Defender sections are automatically skipped as they require application permissions.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

        Returns a structured report object containing:
        - ReportMetadata: Generation info, timing, section status, errors
        - TenantInfo: Organization details and directory statistics
        - LicenseAllocation: License assignments and usage
        - ConditionalAccess: Policy analysis and recommendations
        - SecureScore: Microsoft 365 Secure Score with history
        - AzureSecureScore: Azure Security Center score
        - Users: User accounts and activity analysis
        - RiskyUsers: Identity Protection risky users
        - PrivilegedAccess: Privileged roles and PIM configuration
        - Intune: Device compliance status
        - ServicePrincipals: Application permissions audit
        - DefenderIncidents: Security incidents (if available)
        - Defender: Email threat analysis
        - Additional sections based on parameters

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports
        Version: 5.0.0

        Required Azure AD Application Permissions vary by section.
        See individual Get-*Report function documentation for specific requirements.

    .LINK
        https://github.com/systommy/TenantReports
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

        # Note: RiskyUsers and Defender sections will be skipped as they require application permissions.
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateScript({
                if ($_ -and -not (Test-Path $_ -PathType Container)) {
                    throw "Output path does not exist or is not a directory: $_"
                }
                $true
            })]
        [string]$OutputPath,

        [Parameter()]
        [string]$OutputFileName,

        [Parameter()]
        [switch]$IncludeAuditReports,

        [Parameter()]
        [switch]$IncludeMailboxPermissions,

        [Parameter()]
        [switch]$IncludeCalendarPermissions,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$AuditDaysBack = 30,

        [Parameter()]
        [ArgumentCompleter({
                param($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
                (Get-ValidSecurityReportSection).Where({ $_ -like "$WordToComplete*" })
            })]
        [string[]]$IncludeSections,

        [Parameter()]
        [ArgumentCompleter({
                param($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
                (Get-ValidSecurityReportSection).Where({ $_ -like "$WordToComplete*" })
            })]
        [string[]]$ExcludeSections,

        [Parameter()]
        [string]$TenantName,

        [Parameter()]
        [string]$WsClientId,

        [Parameter()]
        $WsClientSecret,

        [Parameter()]
        [string]$WsOrganizationName
    )

    begin {
        # Validate parameter combinations
        if ($IncludeSections -and $ExcludeSections) {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('Invoke-TntReport failed: Cannot use both -IncludeSections and -ExcludeSections parameters together. Please use one or the other.'),
                'InvokeTntSecurityReportParameterError',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $null
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        # Prepare common parameters for all report functions
        # Note: WithSecure and TenantName parameters are excluded as they're not accepted by all report functions
        $script:ReportParams = @{}
        foreach ($Param in $PSBoundParameters.GetEnumerator()) {
            if ($Param.Key -in @('TenantId', 'ClientId', 'ClientSecret', 'CertificateThumbprint', 'Interactive')) {
                $script:ReportParams[$Param.Key] = $Param.Value
            }
        }

        # Track if using interactive authentication
        $script:IsInteractiveAuth = $Interactive.IsPresent

        # Generate output filename if not provided
        if (-not $OutputFileName) {
            $DateSuffix = Get-Date -Format 'yyyyMMdd_HHmmss'
            $OutputFileName = "SecurityReport_$DateSuffix.json"
        }

        # Establish orchestrator-level connection
        $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
        $script:OrchestratorConnection = Connect-TntGraphSession @ConnectionParams
        $script:ConnectionEstablishedByOrchestrator = $true

        # For interactive auth, get TenantId from the established connection and add to ReportParams
        if ($Interactive -and $script:OrchestratorConnection.TenantId) {
            $TenantId = $script:OrchestratorConnection.TenantId
            $ClientId = $script:OrchestratorConnection.ClientId
            $script:ReportParams['TenantId'] = $TenantId
            if ($ClientId) {
                $script:ReportParams['ClientId'] = $ClientId
            }
            Write-Verbose "Using connection context for interactive report: Tenant=$TenantId, Client=$ClientId"
        }
    }

    process {
        Write-Information 'Starting security report generation...' -InformationAction Continue
        $ReportStartTime = Get-Date

        # Initialize section status tracking and error collection
        $SectionStatus = @{}
        $Errors = [System.Collections.Generic.List[PSObject]]::new()

        # Build hashtable first (no object copying
        $ReportData = [ordered]@{
            ReportMetadata = [PSCustomObject]@{
                TenantId             = $TenantId
                TenantName           = $TenantName
                GeneratedDate        = $ReportStartTime
                ReportVersion        = '5.0.0'
                IncludedSections     = $null  # Will be populated after filtering
                ExcludedSections     = $ExcludeSections
                IsInteractiveAuth    = $script:IsInteractiveAuth
                IncludesAuditReports = $IncludeAuditReports.IsPresent
                AuditLookbackDays    = if ($IncludeAuditReports) { $AuditDaysBack } else { 30 }
                GenerationDuration   = $null  # Will be populated at the end
                SectionStatus        = $null  # Will be populated at the end
                Errors               = $null  # Will be populated at the end
            }
        }

        # Define all available sections with scriptblocks
        $AvailableSections = [ordered]@{
            'TenantInfo'            = {
                Get-TntOrganizationReport @script:ReportParams
            }
            'TenantConfiguration'   = {
                Get-TntConfigurationReport @script:ReportParams
            }
            'LicenseAllocation'     = {
                Get-TntLicenseReport @script:ReportParams
            }
            'ConditionalAccess'  = {
                Get-TntConditionalAccessReport @script:ReportParams
            }
            'SecureScore'        = {
                Get-TntM365SecureScoreReport @script:ReportParams -IncludeHistoricalData
            }
            'AzureSecureScore'   = {
                Get-TntAzureSecureScoreReport @script:ReportParams -IncludeRecommendations -IncludeHistoricalData
            }
            'Users'              = {
                Get-TntM365UserReport @script:ReportParams
            }
            'RiskyUsers'         = {
                Get-TntM365RiskyUserReport @script:ReportParams -RiskLevel @('Low', 'Medium', 'High')
            }
            'PrivilegedRoles'   = {
                Get-TntPrivilegedRoleReport @script:ReportParams
            }
            'PIM'             = {
                Get-TntPIMReport @script:ReportParams
            }
            'Intune'             = {
                Get-TntIntuneDeviceComplianceReport @script:ReportParams
            }
            'ServicePrincipals'  = {
                Get-TntServicePrincipalPermissionReport @script:ReportParams
            }
            'DefenderIncidents'  = {
                Get-TntDefenderIncidentReport @script:ReportParams -DaysBack 90
            }
            'DefenderEmail'           = {
                Get-TntDefenderEmailThreatReport @script:ReportParams -DaysBack 90
            }
            'Apple'              = {
                Get-TntIntuneAppleCertificateReport @script:ReportParams
            }
            'LicenseChangeAudit' = {
                Get-TntLicenseChangeAuditReport @script:ReportParams
            }
            'AppRegistrationExpiry' = {
                Get-TntAppRegistrationExpiryReport @script:ReportParams
            }
        }

        # Add conditional sections based on parameters
        if ($IncludeAuditReports) {
            $AvailableSections['GroupMembershipAudit'] = {
                $GroupAuditParams = $ReportParams.Clone()
                $GroupAuditParams.DaysBack = $AuditDaysBack
                $GroupAuditParams.AuditMode = 'Group'
                Get-TntM365AuditEvent @GroupAuditParams
            }
            $AvailableSections['UserCreationAudit'] = {
                $UserAuditParams = $ReportParams.Clone()
                $UserAuditParams.DaysBack = $AuditDaysBack
                $UserAuditParams.AuditMode = 'User'
                Get-TntM365AuditEvent @UserAuditParams
            }
        }

        if ($IncludeMailboxPermissions) {
            $AvailableSections['MailboxPermissions'] = {
                Get-TntExchangeMailboxPermissionReport @script:ReportParams
            }
            $AvailableSections['SharedMailboxCompliance'] = {
                Get-TntSharedMailboxComplianceReport @script:ReportParams
            }
            $AvailableSections['InboxForwardingRules'] = {
                Get-TntInboxForwardingRuleReport @script:ReportParams
            }
        }

        if ($IncludeCalendarPermissions) {
            $AvailableSections['CalendarPermissions'] = {
                Get-TntExchangeCalendarPermissionReport @script:ReportParams
            }
        }

        if ($WsClientId -and $WsClientSecret -and $WsOrganizationName) {
            $AvailableSections['WithSecure'] = {
                Get-TntWithSecureReport -WsClientId $WsClientId -WsClientSecret $WsClientSecret -WsOrganizationName $WsOrganizationName
            }
        }

        # Apply section filtering
        $SectionsToRun = [System.Collections.Generic.List[string]]::new()
        foreach ($SectionName in $AvailableSections.Keys) {
            [void]$SectionsToRun.Add($SectionName)
        }

        if ($IncludeSections) {
            $SectionsToRun = $SectionsToRun.Where({ $_ -in $IncludeSections })
            Write-Verbose "Including only sections: $($SectionsToRun -join ', ')"
        }

        if ($ExcludeSections) {
            $SectionsToRun = $SectionsToRun.Where({ $_ -notin $ExcludeSections })
            Write-Verbose "Excluded sections: $($ExcludeSections -join ', ')"
        }

        # Skip sections that require application permissions when using interactive auth
        $InteractiveIncompatibleSections = @('RiskyUsers', 'Defender')
        if ($script:IsInteractiveAuth) {
            $SkippedSections = [System.Collections.Generic.List[string]]::new()
            foreach ($Section in $InteractiveIncompatibleSections) {
                if ($Section -in $SectionsToRun) {
                    [void]$SkippedSections.Add($Section)
                    $SectionStatus[$Section] = 'Skipped (requires application permissions)'
                    Write-Warning "Section '$Section' requires application permissions and will be skipped with interactive authentication."
                }
            }
            if ($SkippedSections.Count -gt 0) {
                $SectionsToRun = $SectionsToRun.Where({ $_ -notin $InteractiveIncompatibleSections })
                Write-Information "Skipped $($SkippedSections.Count) section(s) that require application permissions: $($SkippedSections -join ', ')" -InformationAction Continue
            }
        }

        # Update metadata with included sections
        $ReportData.ReportMetadata.IncludedSections = $SectionsToRun
        $ReportData.ReportMetadata.IsInteractiveAuth = $script:IsInteractiveAuth

        # Helper to check if token needs refresh
        function Test-TokenRefreshNeeded {
            param([PSCustomObject]$TokenInfo)
            if ($null -eq $TokenInfo -or $null -eq $TokenInfo.ExpiresAt) { return $true }
            return ($TokenInfo.ExpiresAt - [datetime]::Now).TotalMinutes -lt 10
        }

        # Execute selected sections with progress tracking
        $SectionCount = 0
        $TotalSections = $SectionsToRun.Count

        foreach ($SectionName in $SectionsToRun) {
            $SectionCount++
            $PercentComplete = [Math]::Min(95, ($SectionCount / $TotalSections) * 90)

            Write-Progress -Activity 'Generating Report' -Status "Processing: $SectionName" -PercentComplete $PercentComplete

            # Refresh token if needed
            if (Test-TokenRefreshNeeded $script:TokenInfo) {
                Write-Verbose "Refreshing token (expires in < 10 min)..."
                $script:TokenInfo = Get-GraphToken @script:ReportParams
            }

            try {
                $SectionData = & $AvailableSections[$SectionName]
                $ReportData[$SectionName] = $SectionData
                $SectionStatus[$SectionName] = 'Success'
            } catch {
                Write-Warning $_.Exception.Message
                $ReportData[$SectionName] = $null
                $SectionStatus[$SectionName] = 'Failed'
                $Errors.Add([PSCustomObject]@{
                    Section      = $SectionName
                    ErrorMessage = $_.Exception.Message
                    Timestamp    = Get-Date
                })
            }
        }

        Write-Progress -Activity 'Generating Report' -Status 'Finalizing Report' -PercentComplete 95

        $ReportEndTime = Get-Date
        $Duration = $ReportEndTime - $ReportStartTime

        # Add section status and errors to metadata
        $ReportData.ReportMetadata.GenerationDuration = $Duration
        $ReportData.ReportMetadata.SectionStatus = $SectionStatus
        $ReportData.ReportMetadata.Errors = $Errors

        # Surface section failures
        $Failed = @($SectionStatus.GetEnumerator().Where({ $_.Value -eq 'Failed' }))
        if ($Failed) {
            Write-Warning "Failed sections: $(($Failed.Key) -join ', ')"
            Write-Warning "See `$report.ReportMetadata.Errors for details"
        }

        # Build final report object
        $FullReport = [PSCustomObject]$ReportData
        Write-Verbose "Report assembly complete with $($SectionStatus.Count) sections"

        Write-Progress -Activity 'Generating Report' -Completed

        # Write to local file if output path specified
        if ($OutputPath) {
            try {
                $JsonPath = Join-Path -Path $OutputPath -ChildPath $OutputFileName
                $FullReport | ConvertTo-Json -Depth 40 -Compress | Out-File -FilePath $JsonPath -Encoding UTF8
                Write-Information "JSON report saved to: $JsonPath" -InformationAction Continue

                # Update metadata with file path
                $FullReport.ReportMetadata | Add-Member -NotePropertyName 'OutputPath' -NotePropertyValue $JsonPath -Force
            }
            catch {
                Write-Error "Failed to save JSON report: $($_.Exception.Message)"
            }
        }

        Write-Information "Security report generation completed in $($Duration.Minutes)m $($Duration.Seconds)s" -InformationAction Continue

        $FullReport
    }

    end {
        # Reset orchestrator flag and disconnect
        $script:ConnectionEstablishedByOrchestrator = $false
        $script:OrchestratorConnection.ShouldDisconnect = $true
        if ($script:OrchestratorConnection.ShouldDisconnect) {
            Disconnect-TntGraphSession -ConnectionState $script:OrchestratorConnection
        }
    }
}
