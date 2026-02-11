function Get-TntOrganizationReport {
    <#
    .SYNOPSIS
        Retrieves and displays information about the Microsoft 365 tenant organization.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and retrieves essential
        information about the tenant organization. It provides a clear overview of the organization's
        configuration, including company details, domains and directory statistics.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER IncludeDirectoryStats
        Switch to include detailed directory object statistics in the report.

    .EXAMPLE
        Get-TntOrganizationReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves and displays basic tenant information.

    .EXAMPLE
        Get-TntOrganizationReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -IncludeDirectoryStats

        Retrieves comprehensive tenant information including directory statistics.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Core tenant details (Name, ID, Location, Sync Status)
        - DirectoryStatistics: Counts of users, groups, devices (if requested)
        - AllDomains: List of verified and federated domains

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Organization.Read.All (Application)
        - Directory.Read.All (Application)
        - Domain.Read.All (Application)
        - SubscribedSku.Read.All (Application)
        - User.Read.All (Application)

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

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Secret', 'ApplicationSecret')]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    begin {
        Write-Information 'Starting tenant information retrieval...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            Write-Verbose 'Retrieving organization details...'
            $Organization = Get-MgOrganization -ErrorAction Stop

            # Handle multiple organizations (rare but possible)
            if ($Organization -is [array]) {
                $Organization = $Organization[0]
                Write-Warning "Multiple organizations found, using primary: $($Organization.DisplayName)"
            }

            # Retrieve verified domains
            Write-Verbose 'Retrieving domain information...'
            $Domains = Get-MgDomain -All -ErrorAction Stop
            $PrimaryDomain = @($Domains.Where({ $_.IsDefault -eq $true }))
            $InitialDomain = @($Domains.Where({ $_.IsInitial -eq $true }))
            $VerifiedDomains = @($Domains.Where({ $_.IsVerified -eq $true }))
            $FederatedDomains = @($Domains.Where({ $_.AuthenticationType -eq 'Federated' }))

            Write-Verbose 'Retrieving directory statistics...'
            try {
                # Get user count
                $UserCount = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$count=true&`$top=1" -Headers @{'ConsistencyLevel' = 'eventual' } -Method GET).'@odata.count'

                # Get group count
                $GroupCount = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$count=true&`$top=1" -Headers @{'ConsistencyLevel' = 'eventual' } -Method GET).'@odata.count'

                # Get device count
                $DeviceCount = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/devices?`$count=true&`$top=1" -Headers @{'ConsistencyLevel' = 'eventual' } -Method GET).'@odata.count'

                # Get application count
                $AppCount = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications?`$count=true&`$top=1" -Headers @{'ConsistencyLevel' = 'eventual' } -Method GET).'@odata.count'

                $DirectoryStats = [PSCustomObject]@{
                    TotalUsers        = $UserCount
                    TotalGroups       = $GroupCount
                    TotalDevices      = $DeviceCount
                    TotalApplications = $AppCount
                    LastUpdated       = Get-Date
                }
            } catch {
                Write-Warning "Unable to retrieve complete directory statistics: $($_.Exception.Message)"
            }

            # Parse technical contact information
            $TechnicalContact = if ($Organization.TechnicalNotificationMails) {
                $Organization.TechnicalNotificationMails -join '; '
            } else {
                'Not specified'
            }

            # Parse privacy profile
            $PrivacyProfile = if ($Organization.PrivacyProfile) {
                [PSCustomObject]@{
                    ContactEmail = $Organization.PrivacyProfile.ContactEmail ?? 'Not specified'
                    StatementUrl = $Organization.PrivacyProfile.StatementUrl ?? 'Not specified'
                }
            } else {
                [PSCustomObject]@{
                    ContactEmail = 'Not specified'
                    StatementUrl = 'Not specified'
                }
            }

            # Build tenant information
            $TenantInfo = [PSCustomObject]@{
                OrganizationName           = $Organization.DisplayName
                TenantId                   = $Organization.Id
                CreatedDateTime            = $Organization.CreatedDateTime
                OrganizationType           = $Organization.OrganizationType -join ', '

                # Contact Information
                TechnicalNotificationEmail = $TechnicalContact
                MarketingNotificationEmail = if ($Organization.MarketingNotificationEmails) {
                    $Organization.MarketingNotificationEmails -join '; '
                } else { 'Not specified' }

                # Location Information
                Country                    = $Organization.Country ?? 'Not specified'
                CountryLetterCode          = $Organization.CountryLetterCode ?? 'Not specified'
                State                      = $Organization.State ?? 'Not specified'
                City                       = $Organization.City ?? 'Not specified'
                PostalCode                 = $Organization.PostalCode ?? 'Not specified'
                PreferredLanguage          = $Organization.PreferredLanguage ?? 'Not specified'

                # Domain Information
                PrimaryDomain              = $PrimaryDomain.Id
                InitialDomain              = $InitialDomain.Id
                TotalDomains               = $Domains.Count
                VerifiedDomains            = $VerifiedDomains.Count
                FederatedDomains           = $FederatedDomains.Count

                # Feature Settings
                OnPremisesSyncEnabled      = $Organization.OnPremisesSyncEnabled ?? $false
                OnPremisesLastSyncDateTime = $Organization.OnPremisesLastSyncDateTime
                DirSyncServiceAccount      = $Organization.DirSyncServiceAccount ?? 'Not configured'
                PasswordSyncEnabled        = $Organization.OnPremisesPasswordSyncEnabled ?? $false
                AssignedPlans              = $Organization.AssignedPlans.Count

                # Privacy Information
                PrivacyProfile             = $PrivacyProfile

                # Metadata
                ReportGeneratedDate        = Get-Date
                ReportGeneratedBy          = $ClientId
            }

            Write-Information "Tenant information retrieval completed - $($Organization.DisplayName)" -InformationAction Continue

            [PSCustomObject][Ordered] @{
                Summary             = $TenantInfo
                DirectoryStatistics = $DirectoryStats
                AllDomains          = ($Domains | Select-Object Id, IsDefault, IsInitial, IsVerified, AuthenticationType | Sort-Object Id)
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntOrganizationReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntOrganizationReportError',
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
