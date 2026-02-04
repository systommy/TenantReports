function Get-TntAppRegistrationExpiryReport {
    <#
    .SYNOPSIS
        Reports on app registration credential expiry status.

    .DESCRIPTION
        Queries Microsoft Graph for all application registrations and checks their password
        and key (certificate) credentials for expiry. Categorizes each credential as Expired,
        Expiring Soon (within threshold), or Valid.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER DaysUntilExpiry
        Number of days threshold for 'Expiring Soon' classification. Defaults to 30.

    .EXAMPLE
        Get-TntAppRegistrationExpiryReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Checks all app registrations for credentials expiring within 30 days.

    .EXAMPLE
        Get-TntAppRegistrationExpiryReport -TenantId $tid -ClientId $cid -ClientSecret $secret -DaysUntilExpiry 90

        Checks for credentials expiring within 90 days.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Total apps, expired/expiring credential counts
        - Credentials: Detailed per-credential records with expiry info

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Application.Read.All (Application)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tenant')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [Alias('ApplicationId')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Secret', 'ApplicationSecret')]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Thumbprint')]
        [string]$CertificateThumbprint,

        # Use interactive authentication (no app registration required).
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysUntilExpiry = 30
    )

    begin {
        Write-Information 'Starting app registration credential expiry analysis...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            $Credentials = [System.Collections.Generic.List[PSCustomObject]]::new()
            $Now = Get-Date
            $ExpiryThreshold = $Now.AddDays($DaysUntilExpiry)

            # Page through all applications
            $Uri = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999'

            Write-Verbose 'Retrieving application registrations...'

            do {
                $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop

                foreach ($App in $Response.value) {
                    # Process password credentials (client secrets)
                    foreach ($Cred in $App.passwordCredentials) {
                        $EndDate = [DateTime]$Cred.endDateTime
                        $DaysRemaining = [Math]::Round(($EndDate - $Now).TotalDays, 0)

                        $Status = if ($EndDate -lt $Now) { 'Expired' }
                        elseif ($EndDate -le $ExpiryThreshold) { 'ExpiringSoon' }
                        else { 'Valid' }

                        $Credentials.Add([PSCustomObject]@{
                                AppDisplayName  = $App.displayName
                                AppId           = $App.appId
                                ObjectId        = $App.id
                                CredentialType  = 'ClientSecret'
                                CredentialName  = $Cred.displayName
                                KeyId           = $Cred.keyId
                                StartDate       = $Cred.startDateTime
                                EndDate         = $EndDate
                                DaysRemaining   = $DaysRemaining
                                Status          = $Status
                            })
                    }

                    # Process key credentials (certificates)
                    foreach ($Cred in $App.keyCredentials) {
                        $EndDate = [DateTime]$Cred.endDateTime
                        $DaysRemaining = [Math]::Round(($EndDate - $Now).TotalDays, 0)

                        $Status = if ($EndDate -lt $Now) { 'Expired' }
                        elseif ($EndDate -le $ExpiryThreshold) { 'ExpiringSoon' }
                        else { 'Valid' }

                        $Credentials.Add([PSCustomObject]@{
                                AppDisplayName  = $App.displayName
                                AppId           = $App.appId
                                ObjectId        = $App.id
                                CredentialType  = 'Certificate'
                                CredentialName  = $Cred.displayName
                                KeyId           = $Cred.keyId
                                StartDate       = $Cred.startDateTime
                                EndDate         = $EndDate
                                DaysRemaining   = $DaysRemaining
                                Status          = $Status
                            })
                    }
                }

                $Uri = $Response.'@odata.nextLink'
            } while ($Uri)

            # Build summary
            $Expired = @($Credentials | Where-Object Status -EQ 'Expired')
            $ExpiringSoon = @($Credentials | Where-Object Status -EQ 'ExpiringSoon')
            $Valid = @($Credentials | Where-Object Status -EQ 'Valid')

            $AppsWithIssues = ($Credentials | Where-Object { $_.Status -in 'Expired', 'ExpiringSoon' } |
                Select-Object -ExpandProperty AppId -Unique).Count

            $Summary = [PSCustomObject]@{
                TenantId                    = $TenantId
                ReportGeneratedDate         = $Now
                DaysUntilExpiryThreshold    = $DaysUntilExpiry
                TotalCredentials            = $Credentials.Count
                ExpiredCount                = $Expired.Count
                ExpiringSoonCount           = $ExpiringSoon.Count
                ValidCount                  = $Valid.Count
                AppsWithExpiredOrExpiring    = $AppsWithIssues
            }

            Write-Information "App registration expiry analysis completed - $($Expired.Count) expired, $($ExpiringSoon.Count) expiring soon." -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary     = $Summary
                Credentials = $Credentials.ToArray()
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntAppRegistrationExpiryReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntAppRegistrationExpiryReportError',
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
