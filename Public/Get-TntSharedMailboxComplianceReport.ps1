function Get-TntSharedMailboxComplianceReport {
    <#
    .SYNOPSIS
        Reports on shared mailbox licensing compliance.

    .DESCRIPTION
        Retrieves all shared mailboxes and checks whether enabled accounts have an Exchange Online
        license assigned. Shared mailboxes with sign-in enabled but no Exchange Online license
        are flagged as noncompliant.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .EXAMPLE
        Get-TntSharedMailboxComplianceReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Checks all shared mailboxes for licensing compliance.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Total shared mailboxes, compliant/noncompliant counts
        - Mailboxes: Detailed per-mailbox compliance status

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - User.Read.All (Application)
        - Exchange Online app access

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

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    begin {
        Write-Information 'Starting shared mailbox compliance analysis...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Connect to Exchange Online (required - throw on failure)
            try {
                if ($PSCmdlet.ParameterSetName -eq 'ClientSecret') {
                    $TokenParams = @{
                        TenantId     = $TenantId
                        ClientId     = $ClientId
                        ClientSecret = $ClientSecret
                        Scope        = 'Exchange'
                    }
                    $ExchangeToken = Get-GraphToken @TokenParams
                    Connect-ExchangeOnline -Organization $TenantId -AccessToken $ExchangeToken.AccessToken -ShowBanner:$false -ErrorAction Stop
                } else {
                    # Certificate auth requires domain name, not GUID
                    $TenantDomain = $null
                    try {
                        $Org = Get-MgOrganization -Property VerifiedDomains | Select-Object -First 1
                        if ($Org.VerifiedDomains) {
                            $TenantDomain = ($Org.VerifiedDomains.Where({ $_.IsInitial }) | Select-Object -First 1 -ExpandProperty Name)
                            if (-not $TenantDomain) {
                                $TenantDomain = ($Org.VerifiedDomains.Where({ $_.IsDefault }) | Select-Object -First 1 -ExpandProperty Name)
                            }
                        }
                    } catch {
                        Write-Verbose "Could not resolve tenant domain: $($_.Exception.Message)"
                    }

                    if (-not $TenantDomain) {
                        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                                [System.Exception]::new('Could not resolve tenant domain name. Certificate authentication requires a domain name for Exchange Online, not a tenant GUID.'),
                                'ExchangeTenantDomainResolutionError',
                                [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                                $TenantId
                            ))
                    }

                    Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
                }
                Write-Verbose 'Successfully connected to Exchange Online.'
            } catch {
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Exchange Online connection required: $($_.Exception.Message)"),
                        'ExchangeConnectionError',
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $null
                    ))
            }

            $Mailboxes = [System.Collections.Generic.List[PSCustomObject]]::new()

            # Exchange Online service plan IDs
            $ExchangePlans = @(
                'EXCHANGE_S_ENTERPRISE'
                'EXCHANGE_S_STANDARD'
                'EXCHANGE_S_FOUNDATION'
                'EXCHANGE_S_DESKLESS'
                'EXCHANGE_S_ARCHIVE'
            )

            # Get all shared mailboxes
            Write-Verbose 'Retrieving shared mailboxes...'
            $SharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties UserPrincipalName, DisplayName, ExternalDirectoryObjectId

            Write-Verbose "Found $($SharedMailboxes.Count) shared mailboxes. Checking compliance..."

            foreach ($Mbx in $SharedMailboxes) {
                $UserId = $Mbx.ExternalDirectoryObjectId
                if (-not $UserId) {
                    $Mailboxes.Add([PSCustomObject]@{
                            DisplayName       = $Mbx.DisplayName
                            UserPrincipalName = $Mbx.UserPrincipalName
                            AccountEnabled    = 'Unknown'
                            HasExchangeLicense = $false
                            ComplianceStatus  = 'Unknown'
                            LicensePlans      = @()
                        })
                    continue
                }

                # Get user account status
                try {
                    $User = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$UserId`?`$select=accountEnabled" -Method GET -ErrorAction Stop
                    $AccountEnabled = $User.accountEnabled
                } catch {
                    Write-Warning "Could not retrieve user info for $($Mbx.UserPrincipalName): $($_.Exception.Message)"
                    $AccountEnabled = $null
                }

                # Get license details
                $HasExchangeLicense = $false
                [System.Collections.Generic.List[string]]$AssignedPlans = @()
                try {
                    $LicenseDetails = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$UserId/licenseDetails" -Method GET -ErrorAction Stop
                    foreach ($License in $LicenseDetails.value) {
                        $ExchangeServicePlans = @($License.servicePlans).Where({
                            $_.servicePlanName -in $ExchangePlans -and $_.provisioningStatus -eq 'Success'
                        })
                        if ($ExchangeServicePlans.Count -gt 0) {
                            $HasExchangeLicense = $true
                            foreach ($Plan in $ExchangeServicePlans) { $AssignedPlans.Add($Plan.servicePlanName) }
                        }
                    }
                } catch {
                    Write-Warning "Could not retrieve license details for $($Mbx.UserPrincipalName): $($_.Exception.Message)"
                }

                # Determine compliance
                $ComplianceStatus = if ($null -eq $AccountEnabled) {
                    'Unknown'
                } elseif (-not $AccountEnabled) {
                    'Compliant'  # Disabled account - no license needed
                } elseif ($HasExchangeLicense) {
                    'Compliant'  # Enabled with license
                } else {
                    'NonCompliant'  # Enabled without Exchange license
                }

                $Mailboxes.Add([PSCustomObject]@{
                        DisplayName        = $Mbx.DisplayName
                        UserPrincipalName  = $Mbx.UserPrincipalName
                        AccountEnabled     = $AccountEnabled
                        HasExchangeLicense = $HasExchangeLicense
                        ComplianceStatus   = $ComplianceStatus
                        LicensePlans       = $AssignedPlans
                    })
            }

            $Compliant = @($Mailboxes.Where({ $_.ComplianceStatus -eq 'Compliant' }))
            $NonCompliant = @($Mailboxes.Where({ $_.ComplianceStatus -eq 'NonCompliant' }))
            $Unknown = @($Mailboxes.Where({ $_.ComplianceStatus -eq 'Unknown' }))

            $Summary = [PSCustomObject]@{
                TenantId              = $TenantId
                ReportGeneratedDate   = Get-Date
                TotalSharedMailboxes  = $Mailboxes.Count
                CompliantCount        = $Compliant.Count
                NonCompliantCount     = $NonCompliant.Count
                UnknownCount          = $Unknown.Count
            }

            Write-Information "Shared mailbox compliance analysis completed - $($NonCompliant.Count) noncompliant of $($Mailboxes.Count) total." -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary   = $Summary
                Mailboxes = $Mailboxes.ToArray()
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntSharedMailboxComplianceReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntSharedMailboxComplianceReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            try {
                if ($ConnectionInfo.ShouldDisconnect) {
                    Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
                }
            } catch {
                Write-Verbose "Could not disconnect from services: $($_.Exception.Message)"
            }
        }
    }
}
