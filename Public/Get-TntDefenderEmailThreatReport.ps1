function Get-TntDefenderEmailThreatReport {
    <#
    .SYNOPSIS
        Retrieves email threat alerts from Microsoft Defender for Office 365.

    .DESCRIPTION
        Connects to Microsoft Graph and retrieves email-related security alerts from
        Microsoft Defender, including phishing, malware, spam, and other email threat categories.
        Also retrieves threat submission data for the specified period.

        This function retrieves individual alert-level detections (via /security/alerts_v2). These
        are discrete detection signals for specific email threat events, not Defender incidents.
        A Defender incident is a separate, higher-level concept: a correlated attack investigation
        that groups multiple related alerts across email, endpoint, and identity. Use
        Get-TntDefenderIncidentReport to retrieve incident-level data.

        Returns a structured object containing:
        - Summary: Aggregate counts by severity, status, and threat category.
        - Alerts: Projected details of each alert including affected users and alert URL.

        Write-Information output is emitted on stream 6. Add -InformationAction Continue or set
        $InformationPreference = 'Continue' to see progress messages.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER DaysBack
        Number of days to look back from today for the reporting period. Defaults to 90 days.

    .EXAMPLE
        $Params = @{
            TenantId     = $TenantId
            ClientId     = $ClientId
            ClientSecret = $Secret
        }
        Get-TntDefenderEmailThreatReport @Params

        Retrieves email threat alerts for the last 90 days.

    .EXAMPLE
        $Params = @{
            TenantId     = $TenantId
            ClientId     = $ClientId
            ClientSecret = $Secret
            DaysBack     = 30
        }
        Get-TntDefenderEmailThreatReport @Params

        Retrieves email threat alerts for the last 30 days.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object with:
        - Summary: Aggregate counts by severity, status, and threat type.
        - Alerts: Projected alert details for each email-related security alert.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - SecurityEvents.Read.All (Application)
        - SecurityAlert.Read.All (Application)
        - ThreatSubmission.Read.All (Application)

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

        # Interactive authentication is not supported — this function requires application permissions.
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 180)]
        [int]$DaysBack = 90
    )

    begin {
        $EndDate   = [DateTime]::Now
        $StartDate = $EndDate.AddDays(-$DaysBack)

        Write-Information "STARTED  : Defender email threat report generation for past $DaysBack days..." -InformationAction Continue
    }

    process {
        if ($Interactive) {
            Write-Warning 'Get-TntDefenderEmailThreatReport requires application permissions and cannot run with interactive authentication.'
            Write-Warning 'Required permissions: SecurityEvents.Read.All, SecurityAlert.Read.All, ThreatSubmission.Read.All'
            Write-Warning 'Use -ClientSecret or -CertificateThumbprint authentication instead.'
            return $null
        }

        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            # --- Security alerts ---
            $SecurityAlerts = @()
            Write-Verbose 'Retrieving email security alerts...'
            try {
                $AlertFilter = "createdDateTime ge $($StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $($EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
                $AllAlerts   = Get-MgBetaSecurityAlert -Filter $AlertFilter -All -ErrorAction Stop

                $SecurityAlerts = @($AllAlerts.Where({
                    $_.Category -in @('phishing', 'malware', 'spam', 'email') -or
                    $_.Title -match 'phish|malware|spam|email|threat'
                }))

                Write-Verbose "Retrieved $($AllAlerts.Count) total alerts, $($SecurityAlerts.Count) email-related"
            } catch {
                Write-Warning "Failed to retrieve security alerts: $($_.Exception.Message)"
            }

            # --- Threat submissions ---
            $RecentSubmissions = @()
            Write-Verbose 'Retrieving threat submission data...'
            try {
                $AllSubmissions    = Get-MgBetaSecurityThreatSubmissionEmailThreat -All -ErrorAction Stop
                $RecentSubmissions = @($AllSubmissions.Where({ $_.CreatedDateTime -ge $StartDate }))
                Write-Verbose "Retrieved $($RecentSubmissions.Count) recent threat submissions"
            } catch {
                Write-Warning "Failed to retrieve threat submission data: $($_.Exception.Message)"
            }

            # --- Build Summary ---
            $Summary = [PSCustomObject]@{
                ReportDate             = $EndDate
                StartDate              = $StartDate
                EndDate                = $EndDate
                TotalSecurityAlerts    = $SecurityAlerts.Count
                InformationalAlerts    = $SecurityAlerts.Where({ $_.Severity -eq 'informational' }).Count
                LowSeverityAlerts      = $SecurityAlerts.Where({ $_.Severity -eq 'low' }).Count
                MediumSeverityAlerts   = $SecurityAlerts.Where({ $_.Severity -eq 'medium' }).Count
                HighSeverityAlerts     = $SecurityAlerts.Where({ $_.Severity -eq 'high' }).Count
                ActiveAlerts           = $SecurityAlerts.Where({ $_.Status -ne 'resolved' }).Count
                ResolvedAlerts         = $SecurityAlerts.Where({ $_.Status -eq 'resolved' }).Count
                PhishingAlerts         = $SecurityAlerts.Where({ $_.Category -eq 'phishing' }).Count
                MalwareAlerts          = $SecurityAlerts.Where({ $_.Category -eq 'malware' }).Count
                TotalThreatSubmissions = $RecentSubmissions.Count
                PhishingSubmissions    = $RecentSubmissions.Where({ $_.Category -eq 'phishing' }).Count
                MalwareSubmissions     = $RecentSubmissions.Where({ $_.Category -eq 'malware' }).Count
            }

            # --- Build Alerts ---
            $Alerts = foreach ($Alert in $SecurityAlerts) {
                [PSCustomObject]@{
                    AlertId              = $Alert.Id
                    Title                = $Alert.Title
                    Category             = $Alert.Category
                    Severity             = $Alert.Severity
                    Status               = $Alert.Status
                    Description          = $Alert.Description
                    AssignedTo           = $Alert.AssignedTo
                    CreatedDateTime      = $Alert.CreatedDateTime
                    EventDateTime        = $Alert.EventDateTime
                    LastModifiedDateTime = $Alert.LastModifiedDateTime
                    ClosedDateTime       = $Alert.ClosedDateTime
                    AffectedUsers        = $Alert.UserStates.UserPrincipalName
                    AlertUrl             = $Alert.SourceMaterials | Select-Object -First 1
                    Comments             = $Alert.Comments
                    AzureTenantId        = $Alert.AzureTenantId
                }
            }

            Write-Information "FINISHED : Defender email threat report - $($Summary.TotalSecurityAlerts) security alerts found" -InformationAction Continue

            [PSCustomObject]@{
                Summary = $Summary
                Alerts  = @($Alerts)
            }
        } catch {
            $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntDefenderEmailThreatReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntDefenderEmailThreatReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        } finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
