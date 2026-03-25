function Get-TntAzureSecureScoreReport {
    <#
    .SYNOPSIS
        Retrieves Azure Secure Score data from all subscriptions within the tenant.

    .DESCRIPTION
        This function connects to Azure Resource Manager using an app registration and retrieves
        Azure Security Center secure scores from all accessible subscriptions. It provides comprehensive
        reporting on security posture, recommendations, and compliance across the Azure environment.

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

    .EXAMPLE
        $Report = Get-TntAzureSecureScoreReport @params -IncludeRecommendations -IncludeHistoricalData
        $Report.SubscriptionScores | Sort-Object ScorePercentage | Format-Table

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
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
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
        [switch]$IncludeRecommendations,

        [Parameter()]
        [string[]]$FilterBySubscription,

        [Parameter()]
        [switch]$IncludeComplianceScore,

        [Parameter()]
        [switch]$IncludeHistoricalData,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$MaxHistoryDays = 90
    )

    begin {
        $ArmBaseUri           = 'https://management.azure.com'
        $SecurityApiVersion   = '2020-01-01'
        $ComplianceApiVersion = '2019-01-01-preview'

        Write-Information 'STARTED  : Azure Secure Score collection...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionParams['Scope'] = 'Azure'
            $ConnectionParams['ConnectionType'] = 'RestApi'
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams
            $Headers = $ConnectionInfo.Headers

            # Get all enabled subscriptions
            $SubscriptionsResponse = Invoke-RestMethod -Uri "$ArmBaseUri/subscriptions?api-version=$SecurityApiVersion" -Headers $Headers -Method GET -ErrorAction Stop
            $AllSubscriptions = $SubscriptionsResponse.value.Where({ $_.state -eq 'Enabled' })

            if ($FilterBySubscription) {
                $AllSubscriptions = $AllSubscriptions.Where({ $_.subscriptionId -in $FilterBySubscription })
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

            # Initialize collections
            $SubscriptionScores = [System.Collections.Generic.List[PSObject]]::new()
            $AllRecommendations = [System.Collections.Generic.List[PSObject]]::new()
            $ComplianceData     = [System.Collections.Generic.List[PSObject]]::new()
            $ProcessingErrors   = [System.Collections.Generic.List[PSObject]]::new()

            # Process each subscription
            foreach ($Sub in $AllSubscriptions) {
                $SubId   = $Sub.subscriptionId
                $SubName = $Sub.displayName

                try {
                    # Get secure score
                    $ScoreUri      = "$ArmBaseUri/subscriptions/$SubId/providers/Microsoft.Security/secureScores/ascScore?api-version=$SecurityApiVersion"
                    $ScoreResponse = Invoke-RestMethod -Uri $ScoreUri -Headers $Headers -Method GET -ErrorAction Stop

                    # Get secure score controls
                    $Controls = @()
                    try {
                        $ControlsUri = "$ArmBaseUri/subscriptions/$SubId/providers/Microsoft.Security/secureScoreControls?api-version=$SecurityApiVersion"
                        $Controls = (Invoke-RestMethod -Uri $ControlsUri -Headers $Headers -Method GET -ErrorAction Stop).value ?? @()
                    } catch {
                        Write-Warning "Could not retrieve security controls for '$SubName': $($_.Exception.Message)"
                    }

                    # Calculate control statistics
                    $HealthyControls = 0; $UnhealthyControls = 0; $NotApplicableControls = 0
                    foreach ($Ctrl in $Controls) {
                        if ($Ctrl.properties.score.max -eq 0) { $NotApplicableControls++ }
                        elseif ($Ctrl.properties.score.current -eq $Ctrl.properties.score.max) { $HealthyControls++ }
                        else { $UnhealthyControls++ }
                    }

                    # Get recommendations if requested
                    $SubRecommendations = [System.Collections.Generic.List[PSObject]]::new()
                    if ($IncludeRecommendations) {
                        try {
                            $AssessmentsUri      = "$ArmBaseUri/subscriptions/$SubId/providers/Microsoft.Security/assessments?api-version=$SecurityApiVersion"
                            $AssessmentsResponse = Invoke-RestMethod -Uri $AssessmentsUri -Headers $Headers -Method GET -ErrorAction Stop

                            foreach ($Assessment in ($AssessmentsResponse.value ?? @())) {
                                if ($Assessment.properties.status.code -eq 'Unhealthy') {
                                    $Rec = [PSCustomObject]@{
                                        SubscriptionId         = $SubId
                                        SubscriptionName       = $SubName
                                        AssessmentId           = $Assessment.id
                                        DisplayName            = $Assessment.properties.displayName
                                        Description            = $Assessment.properties.description
                                        RemediationDescription = $Assessment.properties.remediationDescription
                                        Severity               = $Assessment.properties.status.severity
                                        Category               = $Assessment.properties.categories -join '; '
                                        ResourceType           = $Assessment.properties.resourceDetails.source
                                        LastStatusChangeDate   = $Assessment.properties.timeGenerated
                                    }
                                    $SubRecommendations.Add($Rec)
                                    $AllRecommendations.Add($Rec)
                                }
                            }
                        } catch {
                            Write-Warning "Could not retrieve recommendations for '$SubName': $($_.Exception.Message)"
                        }
                    }

                    # Build score entry
                    $CurrentScore = $ScoreResponse.properties.score.current
                    $MaxScore     = $ScoreResponse.properties.score.max
                    $SubscriptionScores.Add([PSCustomObject]@{
                        SubscriptionId          = $SubId
                        SubscriptionName        = $SubName
                        TenantId                = $Sub.tenantId
                        State                   = $Sub.state
                        CurrentScore            = [math]::Round($CurrentScore, 2)
                        MaxScore                = [math]::Round($MaxScore, 2)
                        ScorePercentage         = if ($MaxScore -gt 0) { [math]::Round(($CurrentScore / $MaxScore) * 100, 1) } else { 0 }
                        Weight                  = $ScoreResponse.properties.weight ?? 0
                        LastCalculatedDate      = $ScoreResponse.properties.lastAssessedDate ?? $ScoreResponse.properties.createdDate
                        Controls                = $Controls.properties
                        TotalControls           = $Controls.Count
                        HealthyControls         = $HealthyControls
                        UnhealthyControls       = $UnhealthyControls
                        NotApplicableControls   = $NotApplicableControls
                        SecurityCenterEnabled   = $true
                        SecurityRecommendations = $SubRecommendations
                    })

                    # Get regulatory compliance if requested
                    if ($IncludeComplianceScore) {
                        try {
                            $ComplianceUri      = "$ArmBaseUri/subscriptions/$SubId/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=$ComplianceApiVersion"
                            $ComplianceResponse = Invoke-RestMethod -Uri $ComplianceUri -Headers $Headers -Method GET -ErrorAction Stop

                            foreach ($Standard in ($ComplianceResponse.value ?? @())) {
                                $ComplianceData.Add([PSCustomObject]@{
                                    SubscriptionId      = $SubId
                                    SubscriptionName    = $SubName
                                    StandardName        = $Standard.properties.displayName
                                    StandardId          = $Standard.name
                                    State               = $Standard.properties.state
                                    PassedControls      = $Standard.properties.passedControls
                                    FailedControls      = $Standard.properties.failedControls
                                    SkippedControls     = $Standard.properties.skippedControls
                                    UnsupportedControls = $Standard.properties.unsupportedControls
                                })
                            }
                        } catch {
                            Write-Warning "Could not retrieve compliance data for '$SubName': $($_.Exception.Message)"
                        }
                    }

                } catch {
                    $ErrorType = if ($_.Exception.Message -match '403|Forbidden') { 'Insufficient Permissions' }
                                 elseif ($_.Exception.Message -match '404|Not Found') { 'Security Center Not Enabled' }
                                 else { 'API Error' }

                    $ProcessingErrors.Add([PSCustomObject]@{
                        SubscriptionId   = $SubId
                        SubscriptionName = $SubName
                        Error            = $_.Exception.Message
                        ErrorType        = $ErrorType
                    })

                    $SubscriptionScores.Add([PSCustomObject]@{
                        SubscriptionId        = $SubId
                        SubscriptionName      = $SubName
                        TenantId              = $Sub.tenantId
                        State                 = $Sub.state
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
                    })
                }
            }

            # Calculate aggregated statistics
            $ValidScores = $SubscriptionScores.Where({ $_.SecurityCenterEnabled -eq $true })

            if ($ValidScores.Count -eq 0) {
                Write-Warning 'No subscriptions with valid secure score data found. Check Security Center enablement and RBAC permissions.'
                if ($ProcessingErrors.Count -gt 0) {
                    Write-Warning "  $($ProcessingErrors.Count) subscription(s) returned errors. Check the ProcessingErrors property for details."
                }
            }

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
                if ($VS.CurrentScore -lt $ScoreStats.LowestScore)  { $ScoreStats.LowestScore = $VS.CurrentScore }
            }
            if ($ScoreStats.LowestScore -eq [double]::MaxValue) { $ScoreStats.LowestScore = 0 }

            $RecommendationStats = @{ Critical = 0; High = 0; Medium = 0 }
            foreach ($Rec in $AllRecommendations) {
                switch ($Rec.Severity) {
                    'High'   { $RecommendationStats.Critical++ }
                    'Medium' { $RecommendationStats.High++ }
                    'Low'    { $RecommendationStats.Medium++ }
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
                TotalRecommendations            = $AllRecommendations.Count
                CriticalRecommendations         = $RecommendationStats.Critical
                HighRecommendations             = $RecommendationStats.High
                MediumRecommendations           = $RecommendationStats.Medium
            }

            # Get historical data if requested
            $HistoricalScores = [System.Collections.Generic.List[PSObject]]::new()
            $TrendAnalysis = $null
            if ($IncludeHistoricalData -and $ValidScores.Count -gt 0) {
                Write-Verbose "Retrieving historical secure score data (last $MaxHistoryDays days)..."

                $StartDate = [DateTime]::UtcNow.AddDays(-$MaxHistoryDays).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

                foreach ($Sub in $AllSubscriptions.Where({ $_.subscriptionId -in $ValidScores.SubscriptionId })) {
                    try {
                        $HistoryUri      = "$ArmBaseUri/subscriptions/$($Sub.subscriptionId)/providers/Microsoft.Security/secureScores?api-version=$SecurityApiVersion"
                        $HistoryResponse = Invoke-RestMethod -Uri $HistoryUri -Headers $Headers -Method GET -ErrorAction Stop

                        foreach ($Entry in ($HistoryResponse.value ?? @())) {
                            $HistoricalScores.Add([PSCustomObject]@{
                                SubscriptionId   = $Sub.subscriptionId
                                SubscriptionName = $Sub.displayName
                                Date             = $Entry.properties.createdDateTime
                                CurrentScore     = [math]::Round($Entry.properties.score.current, 2)
                                MaxScore         = [math]::Round($Entry.properties.score.max, 2)
                                ScorePercentage  = if ($Entry.properties.score.max -gt 0) {
                                    [math]::Round(($Entry.properties.score.current / $Entry.properties.score.max) * 100, 1)
                                } else { 0 }
                            })
                        }
                    } catch {
                        Write-Verbose "Could not retrieve historical data for '$($Sub.displayName)': $($_.Exception.Message)"
                    }
                }

                # Calculate trend analysis
                if ($HistoricalScores.Count -gt 1) {
                    $SubscriptionTrends = [System.Collections.Generic.List[PSObject]]::new()
                    foreach ($Group in ($HistoricalScores | Group-Object SubscriptionId)) {
                        $SubHistory = $Group.Group | Sort-Object Date
                        if ($SubHistory.Count -gt 1) {
                            $Oldest = $SubHistory[0]
                            $Latest = $SubHistory[-1]
                            $ScoreChange = $Latest.CurrentScore - $Oldest.CurrentScore
                            $PctChange = if ($Oldest.CurrentScore -gt 0) {
                                [math]::Round((($Latest.CurrentScore - $Oldest.CurrentScore) / $Oldest.CurrentScore) * 100, 2)
                            } else { 0 }

                            $SubscriptionTrends.Add([PSCustomObject]@{
                                SubscriptionId   = $Group.Name
                                SubscriptionName = $Oldest.SubscriptionName
                                PeriodDays       = $MaxHistoryDays
                                ScoreChange      = [math]::Round($ScoreChange, 2)
                                PercentageChange = $PctChange
                                Trend            = if ($ScoreChange -gt 0) { 'Improving' } elseif ($ScoreChange -lt 0) { 'Declining' } else { 'Stable' }
                                OldestScore      = $Oldest.CurrentScore
                                LatestScore      = $Latest.CurrentScore
                                OldestDate       = $Oldest.Date
                                LatestDate       = $Latest.Date
                                DataPoints       = $SubHistory.Count
                            })
                        }
                    }

                    if ($SubscriptionTrends.Count -gt 0) {
                        $TrendStats = @{ ScoreChangeSum = 0; PctChangeSum = 0; Improving = 0; Declining = 0; Stable = 0 }
                        foreach ($T in $SubscriptionTrends) {
                            $TrendStats.ScoreChangeSum += $T.ScoreChange
                            $TrendStats.PctChangeSum   += $T.PercentageChange
                            switch ($T.Trend) {
                                'Improving' { $TrendStats.Improving++ }
                                'Declining' { $TrendStats.Declining++ }
                                'Stable'    { $TrendStats.Stable++ }
                            }
                        }
                        $TrendCount = $SubscriptionTrends.Count

                        $TrendAnalysis = [PSCustomObject]@{
                            PeriodDays                  = $MaxHistoryDays
                            TotalSubscriptionsWithTrend = $TrendCount
                            OverallScoreChange          = [math]::Round($TrendStats.ScoreChangeSum, 2)
                            AveragePercentageChange     = if ($TrendCount -gt 0) { [math]::Round($TrendStats.PctChangeSum / $TrendCount, 2) } else { 0 }
                            OverallTrend                = if ($TrendStats.ScoreChangeSum -gt 0) { 'Improving' } elseif ($TrendStats.ScoreChangeSum -lt 0) { 'Declining' } else { 'Stable' }
                            ImprovingSubscriptions      = $TrendStats.Improving
                            DecliningSubscriptions      = $TrendStats.Declining
                            StableSubscriptions         = $TrendStats.Stable
                            SubscriptionTrends          = $SubscriptionTrends
                            TotalHistoricalDataPoints   = $HistoricalScores.Count
                        }
                    }
                }

                Write-Verbose "Historical data processing completed. Found $($HistoricalScores.Count) historical entries"
            }

            Write-Information "FINISHED : Azure Secure Score collection - $($ValidScores.Count) subscriptions processed" -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary            = $AggregatedStats
                SubscriptionScores = $SubscriptionScores | Sort-Object ScorePercentage -Descending
                ComplianceData     = if ($IncludeComplianceScore) { $ComplianceData | Sort-Object SubscriptionName, StandardName } else { @() }
                TrendAnalysis      = $TrendAnalysis
                HistoricalScores   = if ($IncludeHistoricalData) { $HistoricalScores | Sort-Object Date -Descending } else { @() }
                Recommendations    = $AllRecommendations | Sort-Object Severity -Descending
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
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
