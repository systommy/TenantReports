function Get-TntInboxForwardingRuleReport {
    <#
    .SYNOPSIS
        Reports on inbox forwarding rules targeting external addresses.

    .DESCRIPTION
        Retrieves all user and shared mailboxes and checks inbox rules for forwarding to external recipients.
        External addresses are determined by comparing against the tenant's accepted domains.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .EXAMPLE
        Get-TntInboxForwardingRuleReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Checks all user mailboxes for external forwarding rules.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Total rules checked, external forwards found
        - ForwardingRules: Detailed per-rule information

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
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

        # Use interactive authentication (no app registration required).
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    begin {
        Write-Information 'Starting inbox forwarding rule analysis... (this may take a while)' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

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
                            $TenantDomain = ($Org.VerifiedDomains | Where-Object { $_.IsInitial }) | Select-Object -First 1 -ExpandProperty Name
                            if (-not $TenantDomain) {
                                $TenantDomain = ($Org.VerifiedDomains | Where-Object { $_.IsDefault }) | Select-Object -First 1 -ExpandProperty Name
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

            $ForwardingRules = [System.Collections.Generic.List[PSCustomObject]]::new()

            # Get accepted domains to determine internal vs external
            Write-Verbose 'Retrieving accepted domains...'
            $AcceptedDomains = (Get-AcceptedDomain).DomainName

            # Get all user and shared mailboxes
            Write-Verbose 'Retrieving mailboxes...'
            $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties UserPrincipalName, DisplayName, RecipientTypeDetails |
                Where-Object { $_.RecipientTypeDetails -in @('UserMailbox', 'SharedMailbox') }

            Write-Verbose "Checking inbox rules for $($Mailboxes.Count) mailboxes..."
            $TotalRulesChecked = 0

            foreach ($Mbx in $Mailboxes) {
                try {
                    $Rules = Get-InboxRule -Mailbox $Mbx.UserPrincipalName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    if (-not $Rules) { continue }

                    foreach ($Rule in $Rules) {
                        $TotalRulesChecked++

                        # Collect all forward targets
                        $ForwardTargets = @()
                        if ($Rule.ForwardTo) { $ForwardTargets += $Rule.ForwardTo }
                        if ($Rule.ForwardAsAttachmentTo) { $ForwardTargets += $Rule.ForwardAsAttachmentTo }
                        if ($Rule.RedirectTo) { $ForwardTargets += $Rule.RedirectTo }

                        if (-not $ForwardTargets) { continue }

                        # Check each target for external domains
                        foreach ($Target in $ForwardTargets) {
                            # Extract email address - targets can be in format "DisplayName [SMTP:user@domain.com]"
                            $EmailMatch = [regex]::Match($Target, '[Ss][Mm][Tt][Pp]:([^\]]+)')
                            $Email = if ($EmailMatch.Success) { $EmailMatch.Groups[1].Value } else { $Target }

                            $Domain = ($Email -split '@')[-1]
                            $IsExternal = $Domain -and ($Domain -notin $AcceptedDomains)

                            if ($IsExternal) {
                                $ForwardType = if ($Rule.ForwardTo -contains $Target) { 'ForwardTo' }
                                elseif ($Rule.ForwardAsAttachmentTo -contains $Target) { 'ForwardAsAttachment' }
                                else { 'RedirectTo' }

                                $ForwardingRules.Add([PSCustomObject]@{
                                        MailboxUPN      = $Mbx.UserPrincipalName
                                        MailboxDisplay  = $Mbx.DisplayName
                                        RuleName        = $Rule.Name
                                        RuleEnabled     = $Rule.Enabled
                                        ForwardType     = $ForwardType
                                        ForwardTarget   = $Email
                                        TargetDomain    = $Domain
                                        RulePriority    = $Rule.Priority
                                        RuleDescription = $Rule.Description
                                    })
                            }
                        }
                    }
                } catch {
                    Write-Warning "Failed to retrieve inbox rules for $($Mbx.UserPrincipalName): $($_.Exception.Message)"
                }
            }

            # Build summary
            $EnabledForwards       = @($ForwardingRules | Where-Object RuleEnabled -EQ $true)
            $UniqueMailboxes       = ($ForwardingRules.MailboxUPN | Select-Object -Unique).Count
            $UniqueExternalDomains = ($ForwardingRules.TargetDomain | Select-Object -Unique)

            $Summary = [PSCustomObject]@{
                TenantId                = $TenantId
                ReportGeneratedDate     = Get-Date
                TotalMailboxesChecked   = $Mailboxes.Count
                TotalRulesChecked       = $TotalRulesChecked
                ExternalForwardsFound   = $ForwardingRules.Count
                EnabledExternalForwards = $EnabledForwards.Count
                MailboxesWithForwards   = $UniqueMailboxes
                ExternalDomains         = $UniqueExternalDomains
            }

            Write-Information "Inbox forwarding analysis completed - checked $($Mailboxes.Count) mailboxes, found $($ForwardingRules.Count) external forwarding rules." -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary         = $Summary
                ForwardingRules = $ForwardingRules.ToArray()
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntInboxForwardingRuleReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntInboxForwardingRuleReportError',
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
