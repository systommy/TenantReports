function Get-TntDefenderEmailThreatReport {
    <#
    .SYNOPSIS
        Retrieves email threat summary from Microsoft Defender for Office 365.

    .DESCRIPTION
        This function generates a detailed report of email security threats including phishing attempts,
        malware detections, spam statistics, and threat submission data.

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
        Get-TntDefenderEmailThreatReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves email threat summary for the last 90 days.

    .EXAMPLE
        Get-TntDefenderEmailThreatReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -DaysBack 30

        Retrieves report for the last 30 days.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing summary statistics of email threats.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - SecurityEvents.Read.All (Application)
        - Reports.Read.All (Application)
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

        # Use interactive authentication (not supported for this function - requires application permissions).
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 180)]
        [int]$DaysBack = 90
    )

    begin {
        # Calculate date range from DaysBack
        $EndDate   = Get-Date
        $StartDate = $EndDate.AddDays(-$DaysBack)

        # Map DaysBack to nearest valid API period (D7, D30, D90, D180)
        $ValidPeriods = @(7, 30, 90, 180)
        $ApiPeriod    = $ValidPeriods | Sort-Object { [Math]::Abs($_ - $DaysBack) } | Select-Object -First 1
        Write-Verbose "DaysBack $DaysBack mapped to API period D$ApiPeriod"

        Write-Information "Starting Defender email threat report generation for past $($DaysBack) days..." -InformationAction Continue
    }

    process {
        # Interactive authentication is not supported for this function
        # Defender/Security APIs require application permissions
        if ($Interactive) {
            Write-Warning 'Get-TntDefenderEmailThreatReport requires application permissions and cannot run with interactive authentication.'
            Write-Warning 'The following application permissions are required: SecurityEvents.Read.All, SecurityAlert.Read.All, ThreatSubmission.Read.All'
            Write-Warning 'Use -ClientSecret or -CertificateThumbprint authentication instead.'
            return $null
        }

        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            $Report = [PSCustomObject]@{
                ReportDate             = Get-Date
                StartDate              = $StartDate
                EndDate                = $EndDate
                TotalSecurityAlerts    = 0
                HighSeverityAlerts     = 0
                MediumSeverityAlerts   = 0
                LowSeverityAlerts      = 0
                ActiveAlerts           = 0
                ResolvedAlerts         = 0
                PhishingAlerts         = 0
                MalwareAlerts          = 0
                TotalEmailsReceived    = 0
                TotalEmailsSent        = 0
                TotalThreatSubmissions = 0
                PhishingSubmissions    = 0
                MalwareSubmissions     = 0
            }

            # Email-related security alerts
            Write-Verbose 'Retrieving email security alerts...'
            try {
                # Fetch all alerts within date range, then filter post-retrieval for email-related content
                $AlertFilter = "createdDateTime ge $($StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $($EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
                $AllAlerts   = Get-MgBetaSecurityAlert -Filter $AlertFilter -All -ErrorAction Stop

                # Filter for email-related alerts by category or title - ensure array output
                $SecurityAlerts = @($AllAlerts | Where-Object {
                        $_.Category -in @('phishing', 'malware', 'spam', 'email') -or
                        $_.Title -match 'phish|malware|spam|email|threat'
                    })

                Write-Verbose "Retrieved $($AllAlerts.Count) total alerts, $($SecurityAlerts.Count) email-related"

                if ($SecurityAlerts.Count -gt 0) {
                    $Report.TotalSecurityAlerts  = $SecurityAlerts.Count
                    $Report.HighSeverityAlerts   = ($SecurityAlerts | Where-Object { $_.Severity -eq 'high' }).Count
                    $Report.MediumSeverityAlerts = ($SecurityAlerts | Where-Object { $_.Severity -eq 'medium' }).Count
                    $Report.LowSeverityAlerts    = ($SecurityAlerts | Where-Object { $_.Severity -eq 'low' }).Count
                    $Report.ActiveAlerts         = ($SecurityAlerts | Where-Object { $_.Status -ne 'resolved' }).Count
                    $Report.ResolvedAlerts       = ($SecurityAlerts | Where-Object { $_.Status -eq 'resolved' }).Count
                    $Report.PhishingAlerts       = ($SecurityAlerts | Where-Object { $_.Category -eq 'phishing' }).Count
                    $Report.MalwareAlerts        = ($SecurityAlerts | Where-Object { $_.Category -eq 'malware' }).Count
                }
            } catch {
                Write-Warning "Failed to retrieve security alerts: $($_.Exception.Message)"
            }

            # 2. Get email threat detection data
            Write-Verbose 'Retrieving email activity data...'
            $TempFile = [System.IO.Path]::GetTempFileName()
            Remove-Item $TempFile -ErrorAction SilentlyContinue  # Remove empty file created by GetTempFileName to suppress warning
            try {
                # This report shows delivered emails but may not contain threat specifics depending on tenant license
                # Suppress progress bar due to Microsoft Graph SDK bug with PercentComplete overflow (Int32.MaxValue)
                # Use script block with isolated scope and ignore the progress-related error
                $null = & {
                    $ProgressPreference = 'SilentlyContinue'
                    $ErrorActionPreference = 'SilentlyContinue'
                    Get-MgReportEmailActivityUserDetail -Period "D$ApiPeriod" -OutFile $TempFile 2>$null
                }

                if (-not (Test-Path $TempFile) -or (Get-Item $TempFile).Length -eq 0) {
                    throw 'Email activity report file was not created or is empty'
                }
                $ThreatData = Import-Csv -Path $TempFile

                if ($ThreatData) {
                    Write-Verbose "Email activity data retrieved for $($ThreatData.Count) users"
                    # Cast to int to avoid decimal output (Measure-Object returns double)
                    $receiveSum                 = ($ThreatData | Measure-Object -Property 'Receive Count' -Sum -ErrorAction SilentlyContinue).Sum
                    $Report.TotalEmailsReceived = if ($null -ne $receiveSum) { [int]$receiveSum } else { 0 }

                    $sendSum                = ($ThreatData | Measure-Object -Property 'Send Count' -Sum -ErrorAction SilentlyContinue).Sum
                    $Report.TotalEmailsSent = if ($null -ne $sendSum) { [int]$sendSum } else { 0 }
                } else {
                    Write-Verbose 'No email activity data returned from API'
                }
            } catch {
                Write-Warning "Failed to retrieve email activity data: $($_.Exception.Message)"
            } finally {
                if (Test-Path $TempFile) {
                    Remove-Item $TempFile -ErrorAction SilentlyContinue
                }
            }

            # 3. Get threat submission data
            Write-Verbose 'Retrieving threat submission data...'
            try {
                $allSubmissions    = Get-MgBetaSecurityThreatSubmissionEmailThreat -All -ErrorAction Stop
                $recentSubmissions = $allSubmissions | Where-Object { $_.CreatedDateTime -ge $StartDate }

                if ($null -ne $recentSubmissions) {
                    $Report.TotalThreatSubmissions = $recentSubmissions.Count
                    $Report.PhishingSubmissions    = ($recentSubmissions | Where-Object { $_.Category -eq 'phishing' }).Count
                    $Report.MalwareSubmissions     = ($recentSubmissions | Where-Object { $_.Category -eq 'malware' }).Count
                }
                Write-Verbose "Retrieved $($Report.TotalThreatSubmissions) recent threat submissions."
            } catch {
                Write-Warning "Failed to retrieve threat submission data: $($_.Exception.Message)"
            }

            Write-Information "Defender email threat report completed - $($Report.TotalSecurityAlerts) security alerts found" -InformationAction Continue

            $Report
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntDefenderEmailThreatReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntDefenderEmailThreatReportError',
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
