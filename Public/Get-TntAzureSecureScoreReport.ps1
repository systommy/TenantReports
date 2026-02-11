function Get-TntAzureSecureScoreReport {
    <#
    .SYNOPSIS
        Retrieves Azure Secure Score data from all subscriptions within the tenant.

    .DESCRIPTION
        This function connects to Azure Resource Manager using an app registration and retrieves
        Azure Security Center secure scores from all accessible subscriptions. It provides comprehensive
        reporting on security posture, recommendations, and compliance across the Azure environment.

        in PowerShell scripts.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Accepts SecureString or plain String.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER IncludeRecommendations
        Switch to include detailed security recommendations for each subscription.

    .PARAMETER FilterBySubscription
        Filter results to specific subscription IDs. Accepts array of subscription IDs.

    .PARAMETER MaxConcurrentRequests
        Maximum number of concurrent API requests. Defaults to 5 for rate limiting.

    .PARAMETER IncludeComplianceScore
        Switch to include regulatory compliance scores where available.

    .PARAMETER IncludeHistoricalData
        Switch to include historical secure score data for trend analysis (last 90 days).

    .PARAMETER MaxHistoryDays
        Maximum number of days of historical data to retrieve. Defaults to 90 days.

    .EXAMPLE
        Get-TntAzureSecureScoreReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves Azure Secure Score data from all accessible subscriptions.

    .EXAMPLE
        Get-TntAzureSecureScoreReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret |
            ConvertTo-Json -Depth 10 | Out-File -Path 'AzureSecureScore.json'

        Exports the report to JSON format.

    .EXAMPLE
        $Report = Get-TntAzureSecureScoreReport @params -IncludeRecommendations -IncludeHistoricalData
        $Report.SubscriptionScores | Sort-Object ScorePercentage | Format-Table

        Retrieves comprehensive data and displays subscription scores.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured report object containing:
        - Summary: Aggregated statistics across all subscriptions
        - SubscriptionScores: Per-subscription secure score data
        - ComplianceData: Regulatory compliance scores (if -IncludeComplianceScore specified)
        - TrendAnalysis: Historical trend analysis (if -IncludeHistoricalData specified)
        - HistoricalScores: Raw historical data (if -IncludeHistoricalData specified)
        - Recommendations: Security recommendations (if -IncludeRecommendations specified)
        - ProcessingErrors: Any errors encountered during processing

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Microsoft Graph: Directory.Read.All (Application)
        - Azure Service Management: user_impersonation (Delegated)

        Additional Requirements:
        - Security Reader role on each subscription (or Contributor/Reader role)

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

        # Switch to include detailed security recommendations.
        [Parameter()]
        [switch]$IncludeRecommendations,

        # Optional list of subscription IDs to scope results.
        [Parameter()]
        [string[]]$FilterBySubscription,

        # Maximum number of concurrent API calls.
        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxConcurrentRequests = 5,

        # Switch to include regulatory compliance scores.
        [Parameter()]
        [switch]$IncludeComplianceScore,

        # Switch to include historical trend data.
        [Parameter()]
        [switch]$IncludeHistoricalData,

        # Maximum number of days of historical data to retrieve.
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$MaxHistoryDays = 90
    )

    begin {
        # Azure Resource Manager endpoint
        $Script:ArmBaseUri = 'https://management.azure.com'

        Write-Information 'Starting Azure Secure Score collection across subscriptions...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionParams['Scope'] = 'Azure'
            $ConnectionParams['ConnectionType'] = 'RestApi'
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams
            $Script:ArmHeaders = $ConnectionInfo.Headers

            $SubscriptionsUri      = "$($Script:ArmBaseUri)/subscriptions?api-version=2020-01-01"
            $SubscriptionsResponse = Invoke-RestMethod -Uri $SubscriptionsUri -Headers $Script:ArmHeaders -Method GET -ErrorAction Stop
            $AllSubscriptions      = $SubscriptionsResponse.value | Where-Object { $_.state -eq 'Enabled' }

            # Filter subscriptions if specified
            if ($FilterBySubscription) {
                $AllSubscriptions = $AllSubscriptions | Where-Object { $_.subscriptionId -in $FilterBySubscription }
            }

            Write-Verbose "Found $($AllSubscriptions.Count) enabled subscriptions to process"

            if ($AllSubscriptions.Count -eq 0) {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('Get-TntAzureSecureScoreReport failed: No enabled subscriptions found or insufficient permissions.'),
                    'GetAzureSecureScoreReportNoSubscriptionsError',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $TenantId
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            # Process subscriptions for secure score data (parallel across subscriptions)
            $SubscriptionSecureScores = [System.Collections.Generic.List[PSObject]]::new()
            $OverallRecommendations   = [System.Collections.Generic.List[PSObject]]::new()
            $ComplianceData           = [System.Collections.Generic.List[PSObject]]::new()
            $ProcessingErrors         = [System.Collections.Generic.List[PSObject]]::new()

            Write-Verbose "Processing $($AllSubscriptions.Count) subscriptions with throttle limit: $MaxConcurrentRequests"

            # Capture variables for parallel runspaces
            $ArmBaseUri              = $Script:ArmBaseUri
            $ArmHeaders              = $Script:ArmHeaders
            $WantRecommendations     = $IncludeRecommendations.IsPresent
            $WantCompliance          = $IncludeComplianceScore.IsPresent

            $ParallelResults = $AllSubscriptions | ForEach-Object -ThrottleLimit $MaxConcurrentRequests -Parallel {
                $Subscription        = $_
                $BaseUri             = $using:ArmBaseUri
                $Headers             = $using:ArmHeaders
                $GetRecommendations  = $using:WantRecommendations
                $GetCompliance       = $using:WantCompliance

                try {
                    $SecureScoreUri      = "$BaseUri/subscriptions/$($Subscription.subscriptionId)/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"

                    try {
                        $SecureScoreResponse = Invoke-RestMethod -Uri $SecureScoreUri -Headers $Headers -Method GET -ErrorAction Stop

                        # Get secure score controls for detailed breakdown
                        $ControlsUri      = "$BaseUri/subscriptions/$($Subscription.subscriptionId)/providers/Microsoft.Security/secureScoreControls?api-version=2020-01-01"
                        $ControlsResponse = Invoke-RestMethod -Uri $ControlsUri -Headers $Headers -Method GET -ErrorAction SilentlyContinue

                        # Calculate control statistics using single-pass
                        $Controls              = $ControlsResponse.value ?? @()
                        $HealthyControls       = 0
                        $UnhealthyControls     = 0
                        $NotApplicableControls = 0
                        foreach ($CtrlItem in $Controls) {
                            if ($CtrlItem.properties.score.max -eq 0) {
                                $NotApplicableControls++
                            } elseif ($CtrlItem.properties.score.current -eq $CtrlItem.properties.score.max) {
                                $HealthyControls++
                            } else {
                                $UnhealthyControls++
                            }
                        }

                        # Collect recommendations for this subscription if requested
                        $SubscriptionRecommendations = [System.Collections.Generic.List[PSObject]]::new()
                        if ($GetRecommendations) {
                            $RecommendationsUri      = "$BaseUri/subscriptions/$($Subscription.subscriptionId)/providers/Microsoft.Security/assessments?api-version=2020-01-01"
                            $RecommendationsResponse = Invoke-RestMethod -Uri $RecommendationsUri -Headers $Headers -Method GET -ErrorAction SilentlyContinue

                            foreach ($Assessment in ($RecommendationsResponse.value ?? @())) {
                                if ($Assessment.properties.status.code -eq 'Unhealthy') {
                                    $Recommendation = [PSCustomObject]@{
                                        SubscriptionId         = $Subscription.subscriptionId
                                        SubscriptionName       = $Subscription.displayName
                                        AssessmentId           = $Assessment.id
                                        DisplayName            = $Assessment.properties.displayName
                                        Description            = $Assessment.properties.description
                                        RemediationDescription = $Assessment.properties.remediationDescription
                                        Severity               = $Assessment.properties.status.severity
                                        Category               = $Assessment.properties.categories -join '; '
                                        ResourceType           = $Assessment.properties.resourceDetails.source
                                        LastStatusChangeDate   = $Assessment.properties.timeGenerated
                                    }
                                    $SubscriptionRecommendations.Add($Recommendation)

                                    # Output recommendation for aggregation
                                    [PSCustomObject]@{
                                        ResultType = 'Recommendation'
                                        Data       = $Recommendation
                                    }
                                }
                            }
                        }

                        # Output subscription score
                        [PSCustomObject]@{
                            ResultType = 'Score'
                            Data       = [PSCustomObject]@{
                                SubscriptionId          = $Subscription.subscriptionId
                                SubscriptionName        = $Subscription.displayName
                                TenantId                = $Subscription.tenantId
                                State                   = $Subscription.state
                                CurrentScore            = [math]::Round($SecureScoreResponse.properties.score.current, 2)
                                MaxScore                = [math]::Round($SecureScoreResponse.properties.score.max, 2)
                                ScorePercentage         = if ($SecureScoreResponse.properties.score.max -gt 0) {
                                    [math]::Round(($SecureScoreResponse.properties.score.current / $SecureScoreResponse.properties.score.max) * 100, 1)
                                } else { 0 }
                                Weight                  = $SecureScoreResponse.properties.weight ?? 0
                                LastCalculatedDate      = $SecureScoreResponse.properties.lastAssessedDate ?? $SecureScoreResponse.properties.createdDate
                                Controls                = $Controls.properties
                                TotalControls           = $Controls.Count
                                HealthyControls         = $HealthyControls
                                UnhealthyControls       = $UnhealthyControls
                                NotApplicableControls   = $NotApplicableControls
                                SecurityCenterEnabled   = $true
                                SecurityRecommendations = $SubscriptionRecommendations
                            }
                        }

                        # Get regulatory compliance if requested
                        if ($GetCompliance) {
                            $ComplianceUri      = "$BaseUri/subscriptions/$($Subscription.subscriptionId)/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview"
                            $ComplianceResponse = Invoke-RestMethod -Uri $ComplianceUri -Headers $Headers -Method GET -ErrorAction SilentlyContinue

                            foreach ($Standard in ($ComplianceResponse.value ?? @())) {
                                [PSCustomObject]@{
                                    ResultType = 'Compliance'
                                    Data       = [PSCustomObject]@{
                                        SubscriptionId      = $Subscription.subscriptionId
                                        SubscriptionName    = $Subscription.displayName
                                        StandardName        = $Standard.properties.displayName
                                        StandardId          = $Standard.name
                                        State               = $Standard.properties.state
                                        PassedControls      = $Standard.properties.passedControls
                                        FailedControls      = $Standard.properties.failedControls
                                        SkippedControls     = $Standard.properties.skippedControls
                                        UnsupportedControls = $Standard.properties.unsupportedControls
                                    }
                                }
                            }
                        }

                    } catch {
                        # Handle subscriptions without Security Center or insufficient permissions
                        [PSCustomObject]@{
                            ResultType = 'Error'
                            Data       = [PSCustomObject]@{
                                SubscriptionId   = $Subscription.subscriptionId
                                SubscriptionName = $Subscription.displayName
                                Error            = $_.Exception.Message
                                ErrorType        = if ($_.Exception.Message -match '403|Forbidden') { 'Insufficient Permissions' }
                                                   elseif ($_.Exception.Message -match '404|Not Found') { 'Security Center Not Enabled' }
                                                   else { 'API Error' }
                            }
                        }

                        # Add placeholder entry for failed subscriptions
                        [PSCustomObject]@{
                            ResultType = 'Score'
                            Data       = [PSCustomObject]@{
                                SubscriptionId        = $Subscription.subscriptionId
                                SubscriptionName      = $Subscription.displayName
                                TenantId              = $Subscription.tenantId
                                State                 = $Subscription.state
                                CurrentScore          = 0
                                MaxScore              = 0
                                ScorePercentage       = 0
                                Weight                = 0
                                LastCalculatedDate    = $null
                                TotalControls         = 0
                                HealthyControls       = 0
                                UnhealthyControls     = 0
                                NotApplicableControls = 0
                                SecurityCenterEnabled = $false
                                Error                 = $_.Exception.Message
                            }
                        }
                    }
                } catch {
                    [PSCustomObject]@{
                        ResultType = 'Warning'
                        Data       = "Failed to process subscription $($Subscription.displayName): $($_.Exception.Message)"
                    }
                }
            }

            # Aggregate parallel results by type
            foreach ($Result in $ParallelResults) {
                switch ($Result.ResultType) {
                    'Score'          { $SubscriptionSecureScores.Add($Result.Data) }
                    'Recommendation' { $OverallRecommendations.Add($Result.Data) }
                    'Compliance'     { $ComplianceData.Add($Result.Data) }
                    'Error'          { $ProcessingErrors.Add($Result.Data) }
                    'Warning'        { Write-Warning $Result.Data }
                }
            }

            # Calculate aggregated statistics
            $ValidScores = $SubscriptionSecureScores | Where-Object { $_.SecurityCenterEnabled -eq $true }

            if ($ValidScores.Count -eq 0) {
                Write-Warning 'No subscriptions with valid secure score data found. Check Security Center enablement and RBAC permissions.'
                return
            }

            # Calculate aggregated stats using single-pass accumulation
            $ScoreStats = @{
                TotalCurrentScore = 0
                TotalMaxScore     = 0
                HighestScore      = 0
                LowestScore       = [double]::MaxValue
                ScoreSum          = 0
                PercentageSum     = 0
            }
            foreach ($VS in $ValidScores) {
                $ScoreStats.TotalCurrentScore += $VS.CurrentScore
                $ScoreStats.TotalMaxScore     += $VS.MaxScore
                $ScoreStats.ScoreSum          += $VS.CurrentScore
                $ScoreStats.PercentageSum     += $VS.ScorePercentage
                if ($VS.CurrentScore -gt $ScoreStats.HighestScore) { $ScoreStats.HighestScore = $VS.CurrentScore }
                if ($VS.CurrentScore -lt $ScoreStats.LowestScore) { $ScoreStats.LowestScore = $VS.CurrentScore }
            }
            if ($ScoreStats.LowestScore -eq [double]::MaxValue) { $ScoreStats.LowestScore = 0 }

            $RecommendationStats = @{ Critical = 0; High = 0; Medium = 0 }
            foreach ($Rec in $OverallRecommendations) {
                switch ($Rec.Severity) {
                    'High' { $RecommendationStats.Critical++ }
                    'Medium' { $RecommendationStats.High++ }
                    'Low' { $RecommendationStats.Medium++ }
                }
            }

            $ValidScoreCount = $ValidScores.Count
            $AggregatedStats = [PSCustomObject]@{
                TotalSubscriptions              = $AllSubscriptions.Count
                SubscriptionsWithSecurityCenter = $ValidScoreCount
                SubscriptionsWithErrors         = $ProcessingErrors.Count
                AverageScore                    = if ($ValidScoreCount -gt 0) { [math]::Round($ScoreStats.ScoreSum / $ValidScoreCount, 2) } else { 0 }
                AveragePercentage               = if ($ValidScoreCount -gt 0) { [math]::Round($ScoreStats.PercentageSum / $ValidScoreCount, 1) } else { 0 }
                HighestScore                    = $ScoreStats.HighestScore
                LowestScore                     = $ScoreStats.LowestScore
                TotalCurrentScore               = $ScoreStats.TotalCurrentScore
                TotalMaxScore                   = $ScoreStats.TotalMaxScore
                OverallPercentage               = if ($ScoreStats.TotalMaxScore -gt 0) {
                    [math]::Round(($ScoreStats.TotalCurrentScore / $ScoreStats.TotalMaxScore) * 100, 1)
                } else { 0 }
                TotalRecommendations            = $OverallRecommendations.Count
                CriticalRecommendations         = $RecommendationStats.Critical
                HighRecommendations             = $RecommendationStats.High
                MediumRecommendations           = $RecommendationStats.Medium
            }

            # Get historical data if requested
            $HistoricalScores = [System.Collections.Generic.List[PSObject]]::new()
            $TrendAnalysis = $null
            if ($IncludeHistoricalData -and $ValidScores.Count -gt 0) {
                Write-Verbose "Retrieving historical secure score data (last $MaxHistoryDays days) for subscriptions..."

                foreach ($Subscription in ($AllSubscriptions | Where-Object { $_.subscriptionId -in ($ValidScores.SubscriptionId) })) {
                    try {
                        Write-Verbose "Retrieving historical data for subscription: $($Subscription.displayName)"

                        # Calculate date range for historical data
                        $StartDate = (Get-Date).AddDays(-$MaxHistoryDays).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

                        # Try to get historical secure score data
                        try {
                            $HistoryScoreUri = "$($Script:ArmBaseUri)/subscriptions/$($Subscription.subscriptionId)/providers/Microsoft.Security/secureScores?api-version=2020-01-01&`$filter=createdDateTime ge $StartDate&`$orderby=createdDateTime desc"
                            $HistoryResponse = Invoke-RestMethod -Uri $HistoryScoreUri -Headers $Script:ArmHeaders -Method GET -ErrorAction SilentlyContinue

                            if ($HistoryResponse.value) {
                                foreach ($HistoryEntry in $HistoryResponse.value) {
                                    $HistoricalScores.Add([PSCustomObject]@{
                                            SubscriptionId   = $Subscription.subscriptionId
                                            SubscriptionName = $Subscription.displayName
                                            Date             = $HistoryEntry.properties.createdDateTime
                                            CurrentScore     = [math]::Round($HistoryEntry.properties.score.current, 2)
                                            MaxScore         = [math]::Round($HistoryEntry.properties.score.max, 2)
                                            ScorePercentage  = if ($HistoryEntry.properties.score.max -gt 0) {
                                                [math]::Round(($HistoryEntry.properties.score.current / $HistoryEntry.properties.score.max) * 100, 1)
                                            } else { 0 }
                                        })
                                }
                            }
                        } catch {
                            Write-Verbose "Could not retrieve historical data for subscription $($Subscription.displayName): $($_.Exception.Message)"
                        }
                    } catch {
                        Write-Verbose "Failed to process historical data for subscription $($Subscription.displayName): $($_.Exception.Message)"
                        continue
                    }
                }

                # Calculate trend analysis if we have historical data
                if ($HistoricalScores.Count -gt 1) {
                    Write-Verbose "Calculating trend analysis from $($HistoricalScores.Count) historical data points"

                    # Group by subscription and calculate trends
                    $SubscriptionTrends = [System.Collections.Generic.List[PSObject]]::new()
                    $HistoricalScores | Group-Object SubscriptionId | ForEach-Object {
                        $SubHistory = $_.Group | Sort-Object Date
                        if ($SubHistory.Count -gt 1) {
                            $OldestScore = $SubHistory[0]
                            $LatestScore = $SubHistory[-1]
                            $ScoreChange = $LatestScore.CurrentScore - $OldestScore.CurrentScore
                            $PercentageChange = if ($OldestScore.CurrentScore -gt 0) {
                                [math]::Round((($LatestScore.CurrentScore - $OldestScore.CurrentScore) / $OldestScore.CurrentScore) * 100, 2)
                            } else { 0 }

                            $SubscriptionTrends.Add([PSCustomObject]@{
                                    SubscriptionId   = $_.Name
                                    SubscriptionName = $OldestScore.SubscriptionName
                                    PeriodDays       = $MaxHistoryDays
                                    ScoreChange      = [math]::Round($ScoreChange, 2)
                                    PercentageChange = $PercentageChange
                                    Trend            = if ($ScoreChange -gt 0) { 'Improving' } elseif ($ScoreChange -lt 0) { 'Declining' } else { 'Stable' }
                                    OldestScore      = $OldestScore.CurrentScore
                                    LatestScore      = $LatestScore.CurrentScore
                                    OldestDate       = $OldestScore.Date
                                    LatestDate       = $LatestScore.Date
                                    DataPoints       = $SubHistory.Count
                                })
                        }
                    }

                    # Calculate overall trend analysis using single-pass accumulation
                    if ($SubscriptionTrends.Count -gt 0) {
                        $TrendStats = @{
                            ScoreChangeSum       = 0
                            PercentageChangeSum  = 0
                            ImprovingCount       = 0
                            DecliningCount       = 0
                            StableCount          = 0
                        }
                        foreach ($SubTrend in $SubscriptionTrends) {
                            $TrendStats.ScoreChangeSum += $SubTrend.ScoreChange
                            $TrendStats.PercentageChangeSum += $SubTrend.PercentageChange
                            switch ($SubTrend.Trend) {
                                'Improving' { $TrendStats.ImprovingCount++ }
                                'Declining' { $TrendStats.DecliningCount++ }
                                'Stable' { $TrendStats.StableCount++ }
                            }
                        }
                        $TrendCount              = $SubscriptionTrends.Count
                        $OverallScoreChange      = $TrendStats.ScoreChangeSum
                        $AveragePercentageChange = if ($TrendCount -gt 0) { $TrendStats.PercentageChangeSum / $TrendCount } else { 0 }

                        $TrendAnalysis = [PSCustomObject]@{
                            PeriodDays                  = $MaxHistoryDays
                            TotalSubscriptionsWithTrend = $TrendCount
                            OverallScoreChange          = [math]::Round($OverallScoreChange, 2)
                            AveragePercentageChange     = [math]::Round($AveragePercentageChange, 2)
                            OverallTrend                = if ($OverallScoreChange -gt 0) { 'Improving' } elseif ($OverallScoreChange -lt 0) { 'Declining' } else { 'Stable' }
                            ImprovingSubscriptions      = $TrendStats.ImprovingCount
                            DecliningSubscriptions      = $TrendStats.DecliningCount
                            StableSubscriptions         = $TrendStats.StableCount
                            SubscriptionTrends          = $SubscriptionTrends
                            TotalHistoricalDataPoints   = $HistoricalScores.Count
                        }
                    }
                }

                Write-Verbose "Historical data processing completed. Found $($HistoricalScores.Count) historical entries"
            }

            Write-Information "Azure Secure Score collection completed - $($ValidScores.Count) subscriptions processed" -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary            = $AggregatedStats
                SubscriptionScores = $SubscriptionSecureScores | Sort-Object ScorePercentage -Descending
                ComplianceData     = if ($IncludeComplianceScore) {
                    $ComplianceData | Sort-Object SubscriptionName, StandardName
                } else {
                    @()
                }
                TrendAnalysis      = $TrendAnalysis
                HistoricalScores   = if ($IncludeHistoricalData) {
                    $HistoricalScores | Sort-Object Date -Descending
                } else {
                    @()
                }
                Recommendations    = $OverallRecommendations | Sort-Object Severity -Descending
                ProcessingErrors   = $ProcessingErrors
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntAzureSecureScoreReport failed: $($_.Exception.Message)", $_.Exception),
                'GetAzureSecureScoreReportError',
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

