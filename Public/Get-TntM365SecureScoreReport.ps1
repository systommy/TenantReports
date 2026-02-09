function Get-TntM365SecureScoreReport {
    <#
    .SYNOPSIS
        Generates a Microsoft 365 Tenant Secure Score report with security recommendations and trends.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and generates detailed reports about
        the tenant's secure score, security controls implementation status, and provides actionable security
        recommendations. It includes historical trending data and risk-based prioritization.

        in PowerShell scripts.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Accepts SecureString or plain String.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER IncludeHistoricalData
        Switch to include historical secure score data for trend analysis (last 90 days).

    .PARAMETER FilterByCategory
        Filter results by security control category. Valid values are Identity, Data, Device, Apps, Infrastructure.

    .PARAMETER ShowOnlyRecommendations
        Switch to show only actionable recommendations rather than all controls.

    .PARAMETER MaxHistoryDays
        Maximum number of days of historical data to retrieve. Defaults to 90 days.

    .EXAMPLE
        Get-TntM365SecureScoreReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a comprehensive secure score report.

    .EXAMPLE
        Get-TntM365SecureScoreReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret |
            ConvertTo-Json -Depth 10 | Out-File -Path 'SecureScore.json'

        Exports the report to JSON format.

    .EXAMPLE
        $Report = Get-TntM365SecureScoreReport @params -IncludeHistoricalData
        $Report.RecommendationsByImpact.High | Format-Table Title, MaxScore, ScoreGap

        Retrieves report with historical data and displays high-impact recommendations.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured report object containing:
        - Summary: Current score, percentage, control counts by category
        - TrendAnalysis: Historical score changes (if -IncludeHistoricalData specified)
        - RecommendationsByImpact: High/Medium/Low impact recommendations
        - ImplementedControls: Controls already implemented
        - AllControls: Complete list of security controls
        - ControlsByCategory: Controls grouped by category
        - HistoricalScores: Raw historical data (if -IncludeHistoricalData specified)

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Azure AD Application Permissions:
        - SecurityEvents.Read.All (Application)
        - SecurityActions.Read.All (Application)

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

        # Switch to include historical trend data.
        [Parameter()]
        [switch]$IncludeHistoricalData,

        # Optional secure score category filter.
        [Parameter()]
        [ValidateSet('Identity', 'Data', 'Device', 'Apps', 'Infrastructure')]
        [string]$FilterByCategory,

        # Switch to return only actionable recommendations.
        [Parameter()]
        [switch]$ShowOnlyRecommendations,

        # Maximum number of days of historical data to retrieve.
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$MaxHistoryDays = 90
    )

    begin {
        Write-Information 'Starting Secure Score report generation...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            Write-Verbose 'Retrieving current secure scores...'
            try {
                # Three fallback methods: SDK with params, REST API, SDK with local sort
                $CurrentSecureScores = [System.Collections.Generic.List[PSObject]]::new()
                try {
                    $CurrentSecureScores = Get-MgSecuritySecureScore -Top 1 -OrderBy 'createdDateTime desc' -ErrorAction Stop
                } catch {
                    Write-Verbose "Direct method failed, trying alternative approach: $($_.Exception.Message)"

                    # Method 2: Alternative approach using Invoke-MgGraphRequest
                    try {
                        $GraphUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top = 1&`$orderby = createdDateTime desc"
                        $Response = Invoke-MgGraphRequest -Uri $GraphUri -Method GET
                        if ($Response.value -and $Response.value.Count -gt 0) {
                            $CurrentSecureScores.Clear()
                            foreach ($item in $Response.value) {
                                $CurrentSecureScores.Add($item)
                            }
                        }
                    } catch {
                        Write-Verbose "Alternative method also failed: $($_.Exception.Message)"
                    }
                }

                # Method 3: If both fail, try getting all and sorting locally
                if ($CurrentSecureScores.Count -eq 0) {
                    Write-Verbose 'Trying to get all secure scores and sort locally...'
                    try {
                        $AllScores = Get-MgSecuritySecureScore -All -ErrorAction Stop
                        if ($AllScores -and $AllScores.Count -gt 0) {
                            $LatestScoreFromAll = $AllScores | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
                            $CurrentSecureScores.Add($LatestScoreFromAll)
                        }
                    } catch {
                        Write-Warning "Failed to retrieve secure scores with all methods: $($_.Exception.Message)"
                    }
                }
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new("Get-TntM365SecureScoreReport failed retrieving secure score data: $($_.Exception.Message)", $_.Exception),
                    'GetM365SecureScoreReportDataError',
                    [System.Management.Automation.ErrorCategory]::OperationStopped,
                    $TenantId
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            if ($CurrentSecureScores.Count -eq 0) {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('Get-TntM365SecureScoreReport failed: No secure score data available. Verify that the app registration has SecurityEvents.Read.All permissions.'),
                    'GetM365SecureScoreReportNoDataError',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $TenantId
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            # Handle both array and single object cases
            $LatestScore = if ($CurrentSecureScores -is [array]) {
                $CurrentSecureScores[0]
            } else {
                $CurrentSecureScores
            }

            # Safely extract score values with null checks
            $CurrentScoreValue = if ($null -ne $LatestScore.CurrentScore) {
                [int]$LatestScore.CurrentScore
            } else {
                0
            }
            $MaxScoreValue = if ($null -ne $LatestScore.MaxScore) {
                [int]$LatestScore.MaxScore
            } else {
                0
            }

            $CurrentScorePercentage = if ($MaxScoreValue -gt 0) {
                [math]::Round(($CurrentScoreValue / $MaxScoreValue) * 100, 1)
            } else {
                0
            }

            Write-Verbose "Current secure score: $CurrentScoreValue / $MaxScoreValue ($CurrentScorePercentage%)"

            # Get historical data if requested
            $HistoricalScores = [System.Collections.Generic.List[PSObject]]::new()
            if ($IncludeHistoricalData) {
                Write-Verbose "Retrieving historical secure score data (last $MaxHistoryDays days)..."
                try {
                    $HistoryStartDate = (Get-Date).AddDays(-$MaxHistoryDays).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

                    # Try multiple methods for historical data
                    try {
                        $HistoricalScores = Get-MgSecuritySecureScore -Filter "createdDateTime ge $HistoryStartDate" -OrderBy 'createdDateTime desc' -All -ErrorAction Stop
                    } catch {
                        Write-Verbose 'Primary historical method failed, trying alternative...'
                        $GraphUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$filter=createdDateTime ge $HistoryStartDate&`$orderby=createdDateTime desc"
                        $Response = Invoke-MgGraphRequest -Uri $GraphUri -Method GET
                        if ($Response.value) {
                            foreach ($item in $Response.value) {
                                $HistoricalScores.Add($item)
                            }
                        }
                    }
                    Write-Verbose "Retrieved $($HistoricalScores.Count) historical score entries"
                } catch {
                    Write-Warning "Failed to retrieve historical data: $($_.Exception.Message)"
                }
            }

            Write-Verbose 'Retrieving secure score control profiles...'
            try {
                $ControlProfiles = [System.Collections.Generic.List[PSObject]]::new()

                # Method 1: REST API (primary)
                try {
                    $GraphUri = 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles'
                    $Response = Invoke-MgGraphRequest -Uri $GraphUri -Method GET
                    if ($Response.value) {
                        foreach ($controlProfile in $Response.value) {
                            $ControlProfiles.Add($controlProfile)
                        }

                        # Handle pagination if needed
                        while ($Response.'@odata.nextLink') {
                            $Response = Invoke-MgGraphRequest -Uri $Response.'@odata.nextLink' -Method GET
                            if ($Response.value) {
                                foreach ($controlProfile in $Response.value) {
                                    $ControlProfiles.Add($controlProfile)
                                }
                            }
                        }
                    }
                } catch {
                    # Method 2: SDK fallback
                    Write-Verbose 'REST API method failed, trying SDK fallback...'
                    try {
                        $DirectProfiles = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop
                        foreach ($controlProfile in $DirectProfiles) {
                            $ControlProfiles.Add($controlProfile)
                        }
                    } catch {
                        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                            [System.Exception]::new("Get-TntM365SecureScoreReport failed retrieving control profiles (SDK fallback): $($_.Exception.Message)", $_.Exception),
                            'GetM365SecureScoreReportControlProfilesError',
                            [System.Management.Automation.ErrorCategory]::OperationStopped,
                            $TenantId
                        )
                        $PSCmdlet.ThrowTerminatingError($errorRecord)
                    }
                }

                Write-Verbose "Retrieved $($ControlProfiles.Count) security control profiles"
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new("Get-TntM365SecureScoreReport failed retrieving control profiles. Verify SecurityEvents.Read.All permissions: $($_.Exception.Message)", $_.Exception),
                    'GetM365SecureScoreReportControlProfilesError',
                    [System.Management.Automation.ErrorCategory]::OperationStopped,
                    $TenantId
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            $SecurityControls = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($Control in $ControlProfiles) {
                # Get tenant-specific score and calculate implementation status from score comparison
                # Note: The Microsoft Graph API does NOT return 'implementationStatus' in controlScores
                $CurrentControlScore = 0
                $ControlImplementationStatus = 'Unknown'

                # Get MaxScore from control profile
                $MaxControlScore = if ($null -ne $Control.MaxScore) { [double]$Control.MaxScore } else { 0 }

                # Get control scores array
                $controlScoresArray = $LatestScore.ControlScores

                if ($controlScoresArray -and $controlScoresArray.Count -gt 0) {
                    # Find matching control by ID or Title
                    $ControlId = $Control.Id
                    $ControlTitle = $Control.Title

                    $MatchingControl = $controlScoresArray | Where-Object {
                        $_.ControlName -and ($_.ControlName -eq $ControlId -or $_.ControlName -eq $ControlTitle)
                    }

                    if ($MatchingControl) {
                        $CurrentControlScore = if ($null -ne $MatchingControl.Score) { [double]$MatchingControl.Score } else { 0 }

                        # Calculate implementation status from score comparison
                        if ($MaxControlScore -gt 0) {
                            if ($CurrentControlScore -ge $MaxControlScore) {
                                $ControlImplementationStatus = 'Implemented'
                            } elseif ($CurrentControlScore -gt 0) {
                                $ControlImplementationStatus = 'InProgress'
                            } else {
                                $ControlImplementationStatus = 'NotImplemented'
                            }
                        }
                    }
                }

                $ControlCategory = $Control.ControlCategory ?? $Control.Category ?? 'Unknown'

                # Skip if filtering by category
                if ($FilterByCategory -and $ControlCategory -ne $FilterByCategory) {
                    Write-Verbose 'Skipping control because of category filter.'
                    continue
                }

                # Skip implemented controls if only showing recommendations
                if ($ShowOnlyRecommendations -and $ControlImplementationStatus -eq 'Implemented') {
                    Write-Verbose 'Skipping control because of recommendation filter.'
                    continue
                }

                $ControlEntry = [PSCustomObject]@{
                    ControlId            = $Control.Id ?? 'Unknown'
                    Rank                 = $Control.Rank
                    Title                = $Control.Title ?? 'Unknown Control'
                    Category             = $ControlCategory
                    Description          = $Control.Description ?? 'No description available'
                    ImplementationStatus = $ControlImplementationStatus
                    ImplementationCost   = $Control.ImplementationCost ?? 'Unknown'
                    UserImpact           = $Control.UserImpact ?? 'Unknown'
                    MaxScore             = $MaxControlScore
                    CurrentScore         = $CurrentControlScore
                    ScoreGap             = $MaxControlScore - $CurrentControlScore
                    Tier                 = $Control.Tier ?? 'Unknown'
                    Threats              = if ($Control.Threats -and $Control.Threats.Count -gt 0) {
                        ($Control.Threats -join '; ')
                    } else {
                        'Not specified'
                    }
                    ActionType           = $Control.ActionType ?? 'Unknown'
                    ActionUrl            = $Control.ActionUrl ?? ''
                    LastModifiedDateTime = $Control.LastModifiedDateTime
                    IsRecommendation     = ($ControlImplementationStatus -eq 'NotImplemented' -or $ControlImplementationStatus -eq 'InProgress')
                    RiskReduction        = switch ($MaxControlScore) {
                        { $_ -ge 10 } { 'High' }
                        { $_ -ge 5 } { 'Medium' }
                        default { 'Low' }
                    }
                }
                $SecurityControls.Add($ControlEntry)
            }

            # Sort controls by priority (category priority, then by score gap)
            $SortedControls = $SecurityControls | Sort-Object ScoreGap -Descending

            # Calculate trend analysis if historical data is available
            $TrendAnalysis = $null
            if ($HistoricalScores.Count -gt 1) {
                $OldestScore = $HistoricalScores[-1]
                $OldestScoreValue = if ($null -ne $OldestScore.CurrentScore) {
                    [int]$OldestScore.CurrentScore
                } else {
                    0
                }
                $ScoreChange = $CurrentScoreValue - $OldestScoreValue
                $PercentageChange = if ($OldestScoreValue -gt 0) {
                    [math]::Round((($CurrentScoreValue - $OldestScoreValue) / $OldestScoreValue) * 100, 2)
                } else {
                    0
                }

                $TrendAnalysis = [PSCustomObject]@{
                    PeriodDays           = $MaxHistoryDays
                    ScoreChange          = $ScoreChange
                    PercentageChange     = $PercentageChange
                    Trend                = if ($ScoreChange -gt 0) {
                        'Improving'
                    } elseif ($ScoreChange -lt 0) {
                        'Declining'
                    } else {
                        'Stable'
                    }
                    OldestScoreDate      = $OldestScore.CreatedDateTime
                    OldestScore          = $OldestScoreValue
                    LatestScoreDate      = $LatestScore.CreatedDateTime
                    LatestScore          = $CurrentScoreValue
                    AverageScore         = [math]::Round(($HistoricalScores | ForEach-Object {
                                if ($null -ne $_.CurrentScore) {
                                    [int]$_.CurrentScore
                                } else {
                                    0
                                }
                            } | Measure-Object -Average).Average, 1)
                    HistoricalDataPoints = $HistoricalScores.Count
                }
            }

            # Generate comprehensive summary using single-pass accumulation
            $ControlStats = @{
                ImplementedControls         = 0
                NotImplementedControls      = 0
                InProgressControls          = 0
                PlannedControls             = 0
                TotalScoreGap               = 0
                HighImpactRecommendations   = 0
                MediumImpactRecommendations = 0
                LowImpactRecommendations    = 0
                IdentityControls            = 0
                DataControls                = 0
                DeviceControls              = 0
                AppControls                 = 0
                InfrastructureControls      = 0
            }

            foreach ($Ctrl in $SecurityControls) {
                # Implementation status counts
                switch ($Ctrl.ImplementationStatus) {
                    'Implemented' { $ControlStats.ImplementedControls++ }
                    'NotImplemented' { $ControlStats.NotImplementedControls++ }
                    'InProgress' { $ControlStats.InProgressControls++ }
                    'Planned' { $ControlStats.PlannedControls++ }
                }
                # Recommendation impact counts
                if ($Ctrl.IsRecommendation) {
                    $ControlStats.TotalScoreGap += $Ctrl.ScoreGap
                    if ($Ctrl.MaxScore -ge 10) {
                        $ControlStats.HighImpactRecommendations++
                    } elseif ($Ctrl.MaxScore -ge 5) {
                        $ControlStats.MediumImpactRecommendations++
                    } else {
                        $ControlStats.LowImpactRecommendations++
                    }
                }
                # Category counts
                switch ($Ctrl.Category) {
                    'Identity' { $ControlStats.IdentityControls++ }
                    'Data' { $ControlStats.DataControls++ }
                    'Device' { $ControlStats.DeviceControls++ }
                    'Apps' { $ControlStats.AppControls++ }
                    'Infrastructure' { $ControlStats.InfrastructureControls++ }
                }
            }

            $Summary = [PSCustomObject]@{
                TenantId                    = $TenantId
                ReportGeneratedDate         = Get-Date
                CurrentScore                = $CurrentScoreValue
                MaxPossibleScore            = $MaxScoreValue
                ScorePercentage             = $CurrentScorePercentage
                TotalControls               = $SecurityControls.Count
                ImplementedControls         = $ControlStats.ImplementedControls
                NotImplementedControls      = $ControlStats.NotImplementedControls
                InProgressControls          = $ControlStats.InProgressControls
                PlannedControls             = $ControlStats.PlannedControls
                TotalScoreGap               = $ControlStats.TotalScoreGap
                HighImpactRecommendations   = $ControlStats.HighImpactRecommendations
                MediumImpactRecommendations = $ControlStats.MediumImpactRecommendations
                LowImpactRecommendations    = $ControlStats.LowImpactRecommendations
                IdentityControls            = $ControlStats.IdentityControls
                DataControls                = $ControlStats.DataControls
                DeviceControls              = $ControlStats.DeviceControls
                AppControls                 = $ControlStats.AppControls
                InfrastructureControls      = $ControlStats.InfrastructureControls
                LastUpdated                 = $LatestScore.CreatedDateTime
            }

            Write-Information "Secure Score report completed - Score: $($CurrentScoreValue)/$($MaxScoreValue) ($($CurrentScorePercentage)%)" -InformationAction Continue

            [PSCustomObject]@{
                Summary                 = $Summary
                TrendAnalysis           = $TrendAnalysis
                RecommendationsByImpact = @{
                    High   = $SortedControls | Where-Object { $_.IsRecommendation -and $_.MaxScore -ge 10 }
                    Medium = $SortedControls | Where-Object { $_.IsRecommendation -and $_.MaxScore -ge 5 -and $_.MaxScore -lt 10 }
                    Low    = $SortedControls | Where-Object { $_.IsRecommendation -and $_.MaxScore -lt 5 }
                }
                ImplementedControls     = $SortedControls | Where-Object { $_.ImplementationStatus -eq 'Implemented' }
                AllControls             = $SortedControls
                ControlsByCategory      = @{
                    Identity       = $SortedControls | Where-Object { $_.Category -eq 'Identity' }
                    Data           = $SortedControls | Where-Object { $_.Category -eq 'Data' }
                    Device         = $SortedControls | Where-Object { $_.Category -eq 'Device' }
                    Apps           = $SortedControls | Where-Object { $_.Category -eq 'Apps' }
                    Infrastructure = $SortedControls | Where-Object { $_.Category -eq 'Infrastructure' }
                }
                HistoricalScores        = if ($IncludeHistoricalData) { $HistoricalScores } else { @() }
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntM365SecureScoreReport failed: $($_.Exception.Message)", $_.Exception),
                'GetM365SecureScoreReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            # Only disconnect if we established the connection
            Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
        }
    }
}

