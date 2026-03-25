function Get-TntM365EmailActivityReport {
    <#
    .SYNOPSIS
        Retrieves Microsoft 365 email activity per user from the Graph Reports API.

    .DESCRIPTION
        Downloads the email activity user detail report via Get-MgReportEmailActivityUserDetail
        and returns a structured object with per-user send, receive, and read counts for the
        reporting period.

        Returns a structured object containing:
        - Summary: Aggregate totals across all users for the period.
        - ActivityData: Per-user email activity rows.

        The DaysBack parameter is mapped to the nearest valid API period (7, 30, 90, or 180 days).

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
        Number of days to look back. Mapped to the nearest valid API period: 7, 30, 90, or 180.
        Defaults to 90 days.

    .EXAMPLE
        $Params = @{
            TenantId     = $TenantId
            ClientId     = $ClientId
            ClientSecret = $Secret
        }
        Get-TntM365EmailActivityReport @Params

        Retrieves email activity for all users for the period closest to 90 days.

    .EXAMPLE
        $Params = @{
            TenantId     = $TenantId
            ClientId     = $ClientId
            ClientSecret = $Secret
            DaysBack     = 30
        }
        Get-TntM365EmailActivityReport @Params

        Retrieves email activity for the period closest to 30 days.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object with:
        - Summary: Period, total user count, and aggregate send/receive/read totals.
        - ActivityData: Per-user email activity as PSCustomObjects.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Reports.Read.All (Application or Delegated)

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

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 180)]
        [int]$DaysBack = 90
    )

    begin {
        # Map DaysBack to nearest valid API period (D7, D30, D90, D180)
        $ValidPeriods = @(7, 30, 90, 180)
        $ApiPeriod    = $ValidPeriods | Sort-Object { [Math]::Abs($_ - $DaysBack) } | Select-Object -First 1
        Write-Verbose "DaysBack $DaysBack mapped to API period D$ApiPeriod"

        Write-Information "STARTED  : M365 email activity report generation (period: D$ApiPeriod)..." -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            $TempFile = [System.IO.Path]::GetTempFileName()
            Remove-Item $TempFile -ErrorAction SilentlyContinue

            $Summary      = $null
            $ActivityData = @()

            try {
                # Microsoft Graph SDK has a bug where it sets PercentComplete to Int32.MaxValue,
                # which throws a terminating ArgumentOutOfRangeException. The file download
                # typically completes before the progress error fires, so catch it and continue.
                & {
                    $ProgressPreference = 'SilentlyContinue'
                    try {
                        Get-MgReportEmailActivityUserDetail -Period "D$ApiPeriod" -OutFile $TempFile -ProgressAction SilentlyContinue 2>$null
                    }
                    catch {
                        if ($_.Exception.Message -notmatch 'PercentComplete') {
                            throw
                        }
                    }
                }

                if (-not (Test-Path $TempFile) -or (Get-Item $TempFile).Length -eq 0) {
                    throw 'Email activity report file was not created or is empty'
                }

                $RawData = Import-Csv -Path $TempFile

                if (-not $RawData) {
                    Write-Verbose 'No email activity data returned from API'
                    $RawData = @()
                }

                Write-Verbose "Email activity data retrieved for $($RawData.Count) users"

                $ActivityData = foreach ($Row in $RawData) {
                    [PSCustomObject]@{
                        UserPrincipalName      = $Row.'User Principal Name'
                        DisplayName            = $Row.'Display Name'
                        IsDeleted              = $Row.'Is Deleted' -eq 'True'
                        LastActivityDate       = $Row.'Last Activity Date'
                        SendCount              = [int]($Row.'Send Count' -as [int])
                        ReceiveCount           = [int]($Row.'Receive Count' -as [int])
                        ReadCount              = [int]($Row.'Read Count' -as [int])
                        MeetingCreatedCount    = [int]($Row.'Meeting Created Count' -as [int])
                        MeetingInteractedCount = [int]($Row.'Meeting Interacted Count' -as [int])
                        ReportPeriod           = $Row.'Report Period'
                    }
                }

                $SendSum    = ($RawData | Measure-Object -Property 'Send Count'    -Sum -ErrorAction SilentlyContinue).Sum
                $ReceiveSum = ($RawData | Measure-Object -Property 'Receive Count' -Sum -ErrorAction SilentlyContinue).Sum
                $ReadSum    = ($RawData | Measure-Object -Property 'Read Count'    -Sum -ErrorAction SilentlyContinue).Sum

                $Summary = [PSCustomObject]@{
                    Period              = "D$ApiPeriod"
                    TotalUsers          = $RawData.Count
                    TotalEmailsSent     = if ($null -ne $SendSum)    { [int]$SendSum }    else { 0 }
                    TotalEmailsReceived = if ($null -ne $ReceiveSum) { [int]$ReceiveSum } else { 0 }
                    TotalEmailsRead     = if ($null -ne $ReadSum)    { [int]$ReadSum }    else { 0 }
                }
            } catch {
                Write-Warning "Failed to retrieve email activity data: $($_.Exception.Message)"
                $Summary = [PSCustomObject]@{
                    Period              = "D$ApiPeriod"
                    TotalUsers          = 0
                    TotalEmailsSent     = 0
                    TotalEmailsReceived = 0
                    TotalEmailsRead     = 0
                }
            } finally {
                if (Test-Path $TempFile) {
                    Remove-Item $TempFile -ErrorAction SilentlyContinue
                }
            }

            Write-Information "FINISHED : M365 email activity report - $($Summary.TotalUsers) users" -InformationAction Continue

            [PSCustomObject]@{
                Summary      = $Summary
                ActivityData = @($ActivityData)
            }
        } catch {
            $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntM365EmailActivityReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntM365EmailActivityReportError',
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
