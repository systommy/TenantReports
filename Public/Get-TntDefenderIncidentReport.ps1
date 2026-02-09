function Get-TntDefenderIncidentReport {
    <#
    .SYNOPSIS
        Retrieves Microsoft Defender incident summary information.

    .DESCRIPTION
        Connects to Microsoft Graph to retrieve basic incident information from Microsoft Defender,
        including incident ID, title, severity, status, and creation/modification dates.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER DaysBack
        Number of days back to retrieve incidents. Default is 90 days.

    .PARAMETER Severity
        Filter by incident severity. Valid values: Informational, Low, Medium, High.

    .PARAMETER Status
        Filter by incident status. Valid values: New, Active, Closed.

    .EXAMPLE
        Get-TntDefenderIncidentReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves all incidents from the last 90 days.

    .EXAMPLE
        Get-TntDefenderIncidentReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -Severity High -DaysBack 30

        Retrieves High severity incidents from the last 30 days.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Counts of incidents by severity and status
        - Incidents: Detailed list of incidents

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - SecurityIncident.Read.All (Application)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tenant')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
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
        [ValidateRange(1, 365)]
        [int]$DaysBack = 90,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string[]]$Severity,

        [Parameter()]
        [ValidateSet('New', 'Active', 'Closed')]
        [string[]]$Status
    )

    begin {
        Write-Information 'Starting Microsoft Defender Incidents report generation...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Calculate start date
            $StartDate = (Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
            Write-Verbose "Retrieving incidents from $($StartDate) to present"

            # Build filter parameters
            $FilterParams = @{
                Filter = "createdDateTime ge $($StartDate)"
            }

            if ($Severity -and $Severity.Count -gt 0) {
                $SeverityFilter = $Severity | ForEach-Object { "'$($_.ToLower())'" }
                $SeverityFilterString = $SeverityFilter -join ', '
                $FilterParams.Filter += " and severity in ($($SeverityFilterString))"
                Write-Verbose "Filtering by severity: $($Severity -join ', ')"
            }

            if ($Status -and $Status.Count -gt 0) {
                $StatusFilter = $Status | ForEach-Object { "'$($_.ToLower())'" }
                $StatusFilterString = $StatusFilter -join ', '
                $FilterParams.Filter += " and status in ($($StatusFilterString))"
                Write-Verbose "Filtering by status: $($Status -join ', ')"
            }

            Write-Verbose "Using filter: $($FilterParams.Filter)"

            # Retrieve incidents
            Write-Verbose 'Retrieving Microsoft Defender incidents...'
            $Incidents = Get-MgSecurityIncident @FilterParams -All -ErrorAction SilentlyContinue

            if (-not $Incidents) {
                Write-Verbose "No incidents found or Defender not enabled."
                $Incidents = @()
            }

            Write-Verbose "Retrieved $($Incidents.Count) incident(s)"

            # Process incident data
            $IncidentSummary = foreach ($Incident in $Incidents) {
                [PSCustomObject]@{
                    IncidentId      = $Incident.Id
                    DisplayName     = $Incident.DisplayName
                    Severity        = $Incident.Severity
                    Status          = $Incident.Status
                    Classification  = $Incident.Classification
                    CreatedDateTime = $Incident.CreatedDateTime
                    Comments        = $Incident.Comments.Comment
                }
            }

            # Generate summary statistics
            $Summary = [PSCustomObject]@{
                TotalIncidents = if ($IncidentSummary) { $IncidentSummary.Count } else { 0 }
                BySeverity     = if ($IncidentSummary) {
                    $IncidentSummary | Group-Object Severity | ForEach-Object { @{ $_.Name = $_.Count } }
                } else { @{} }
                ByStatus       = if ($IncidentSummary) {
                    $IncidentSummary | Group-Object Status | ForEach-Object { @{ $_.Name = $_.Count } }
                } else { @{} }
            }

            Write-Information "Defender incidents report completed - $($Summary.TotalIncidents) incidents found" -InformationAction Continue

            [PSCustomObject]@{
                Summary   = $Summary
                Incidents = $IncidentSummary
            }
        }
        catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntDefenderIncidentReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntDefenderIncidentReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
