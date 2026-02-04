function Get-TntExchangeMailboxPermissionReport {
    <#
    .SYNOPSIS
        Retrieves mailbox delegation permissions for all users in Microsoft 365 tenant.

    .DESCRIPTION
        This function retrieves and analyzes mailbox delegation permissions for all users in a Microsoft 365 tenant including:
        - Full Access permissions to mailboxes (who can access which mailboxes)
        - Send As permissions (who can send emails as other users)
        - Send on Behalf permissions (who can send emails on behalf of other users)

        Note: This function requires Exchange Online PowerShell for complete delegation permission coverage.
        
    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for mailbox permission reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER IncludeSystemAccounts
        Switch to include system and service accounts in the results. By default, these are excluded.

    .PARAMETER IncludeInheritedPermissions
        Switch to include inherited permissions in addition to explicitly granted permissions. By default, only explicit permissions are shown.

    .EXAMPLE
        Get-TntExchangeMailboxPermissionReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves mailbox delegation permissions for all users.

    .EXAMPLE
        Get-TntExchangeMailboxPermissionReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -IncludeSystemAccounts

        Retrieves permissions including known system accounts.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Statistics on permissions found
        - MailboxPermissions: Detailed list of delegation permissions

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - User.Read.All (Application)
        - Directory.Read.All (Application)
        - Exchange Online View-Only Recipients role (or higher)

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
        [switch]$IncludeSystemAccounts,

        [Parameter()]
        [switch]$IncludeInheritedPermissions
    )

    begin {
        Write-Information 'Starting mailbox delegation permissions analysis...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            # Initialize results collection
            $MailboxPermissions = [System.Collections.Generic.List[PSObject]]::new()

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
                    Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
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

            # Retrieve all mailboxes via Exchange Online
            Write-Verbose 'Retrieving mailboxes via Exchange Online...'
            $MailboxParams = @{
                ResultSize = 'Unlimited'
                Properties = 'RecipientTypeDetails', 'PrimarySmtpAddress', 'DisplayName', 'UserPrincipalName', 'GrantSendOnBehalfTo'
            }
            $TargetMailboxes = Get-EXOMailbox @MailboxParams | Where-Object {
                $_.RecipientTypeDetails -in @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')
            }

            if (-not $IncludeSystemAccounts) {
                $TargetMailboxes = $TargetMailboxes | Where-Object {
                    $_.Name -notmatch '^(HealthMailbox|SystemMailbox|DiscoverySearchMailbox|Migration\.|FederatedEmail\.)'
                }
            }

            # Process mailbox delegation permissions using parallel processing
            Write-Verbose "Processing $($TargetMailboxes.Count) mailboxes..."
            $MailboxPermissions = $TargetMailboxes | ForEach-Object -Parallel {
                $Mailbox = $_
                $Results = [System.Collections.Generic.List[PSObject]]::new()
                
                # FullAccess
                try {
                    $FullAccess = Get-EXOMailboxPermission -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue | Where-Object {
                        $_.User -notmatch '^(NT AUTHORITY\\SELF|S-1-5-.*)' -and
                        $_.AccessRights -contains 'FullAccess'
                    }
                    
                    if (-not $using:IncludeInheritedPermissions) {
                        $FullAccess = $FullAccess | Where-Object { -not $_.IsInherited }
                    }

                    foreach ($Perm in $FullAccess) {
                        $Results.Add([PSCustomObject]@{
                                MailboxIdentity    = $Mailbox.UserPrincipalName
                                MailboxDisplayName = $Mailbox.DisplayName
                                GrantedTo          = $Perm.User
                                AccessRights       = 'FullAccess'
                                PermissionType     = 'FullAccess'
                                IsInherited        = $Perm.IsInherited
                            })
                    }
                } catch {
                    Write-Warning "Failed to retrieve FullAccess for $($Mailbox.UserPrincipalName)"
                }

                # SendAs
                try {
                    $SendAs = Get-EXORecipientPermission -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue | Where-Object {
                        $_.Trustee -notmatch '^(NT AUTHORITY\\SELF|S-1-5-.*)' -and
                        $_.AccessRights -contains 'SendAs'
                    }

                    foreach ($Perm in $SendAs) {
                        $Results.Add([PSCustomObject]@{
                                MailboxIdentity    = $Mailbox.UserPrincipalName
                                MailboxDisplayName = $Mailbox.DisplayName
                                GrantedTo          = $Perm.Trustee
                                AccessRights       = 'SendAs'
                                PermissionType     = 'SendAs'
                                IsInherited        = $false # SendAs is rarely inherited in the same way
                            })
                    }
                } catch {
                    Write-Warning "Failed to retrieve SendAs for $($Mailbox.UserPrincipalName)"
                }

                # SendOnBehalf - No new API call needed; data exists on the $Mailbox object passed in.
                if ($Mailbox.GrantSendOnBehalfTo) {
                    foreach ($Delegate in $Mailbox.GrantSendOnBehalfTo) {
                        $Results.Add([PSCustomObject]@{
                                MailboxIdentity    = $Mailbox.UserPrincipalName
                                MailboxDisplayName = $Mailbox.DisplayName
                                GrantedTo          = $Delegate # Usually returns Name/ID, may need resolution if you want UPN
                                AccessRights       = 'SendOnBehalf'
                                PermissionType     = 'SendOnBehalf'
                                IsInherited        = $false
                            })
                    }
                }

                return $Results

            } -ThrottleLimit 20 # Adjust based on tenant size/throttling tolerance

            $Summary = [PSCustomObject]@{
                TotalMailboxesAnalyzed  = $TargetMailboxes.Count
                TotalPermissionsFound   = $MailboxPermissions.Count
                FullAccessPermissions   = ($MailboxPermissions | Where-Object PermissionType -EQ 'FullAccess').Count
                SendAsPermissions       = ($MailboxPermissions | Where-Object PermissionType -EQ 'SendAs').Count
                SendOnBehalfPermissions = ($MailboxPermissions | Where-Object PermissionType -EQ 'SendOnBehalf').Count
                UniqueGrantees          = ($MailboxPermissions.GrantedTo | Select-Object -Unique).Count
            }

            # Full report object
            Write-Information "Mailbox delegation permissions analysis completed - $($Summary.TotalPermissionsFound) permissions found" -InformationAction Continue
            [PSCustomObject]@{
                Summary            = $Summary
                MailboxPermissions = $MailboxPermissions
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntExchangeMailboxPermissionReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntExchangeMailboxPermissionReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            # Cleanup connections
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
