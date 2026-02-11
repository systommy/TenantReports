function Get-TntExchangeCalendarPermissionReport {
    <#
    .SYNOPSIS
        Retrieves calendar folder permissions for all users in Microsoft 365 tenant.

    .DESCRIPTION
        This function retrieves and analyzes calendar folder permissions for all users in a Microsoft 365 tenant
        with support for multi-language calendar folder names. It identifies who has access to each user's calendar
        and what level of permissions they have been granted.

        PERFORMANCE WARNING: This function processes calendar permissions for each user individually using
        Exchange Online PowerShell. For large tenants (>500 users), expect processing times of 10-30 minutes.
        Use -Verbose to monitor progress.

        MULTI-LANGUAGE SUPPORT:
        Automatically detects calendar folders in multiple languages including:
        - English (Calendar)
        - Dutch (Agenda)
        - French (Calendrier)
        - German (Kalender)
        - Spanish/Italian (Calendario)
        - Portuguese (Calendario)

    .PARAMETER TenantId
        The Azure AD Tenant ID to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for calendar permission reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER OutputPath
        The directory path where reports will be saved. Defaults to current directory.

    .PARAMETER OutputFormat
        The output format for the report. Valid values are CSV, JSON, or All.

    .PARAMETER ExportToFile
        Switch to export the report to a file in addition to returning the object.

    .PARAMETER IncludeSystemAccounts
        Switch to include system and service accounts in the results. By default, these are excluded.

    .PARAMETER IncludeDefaultPermissions
        Switch to include Default and Anonymous calendar permissions. By default, these are excluded.

    .EXAMPLE
        Get-TntExchangeCalendarPermissionReport -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret $secret

        Retrieves calendar permissions for all users.

    .EXAMPLE
        Get-TntExchangeCalendarPermissionReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -ExportToFile -OutputFormat CSV -Verbose

        Retrieves all calendar permissions, exports to CSV, and shows verbose progress.

    .OUTPUTS
        ITC.Reports.CalendarPermissions
        Returns comprehensive calendar permissions analysis.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - User.Read.All (Application)
        - Directory.Read.All (Application)

        Additional Requirements:
        - Exchange Online View-Only Recipients role (or higher) to query folder permissions.

        Performance Considerations:
        - Large tenants may take significant time; use -Verbose to monitor progress.

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
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
        [switch]$IncludeSystemAccounts,

        [Parameter()]
        [switch]$IncludeDefaultPermissions
    )

    begin {
        # Multi-language calendar folder names
        $CalendarFolderNames = @(
            'Calendar',      # English
            'Agenda',        # Dutch
            'Calendrier',    # French
            'Kalender',      # German
            'Calendario',    # Spanish/Italian
            [string]::Concat('Calend', [char]0x00E1, 'rio')     # Portuguese
        )

        Write-Information 'Starting calendar permissions analysis... (This may take several minutes for large tenants)' -InformationAction Continue
    }

    process {
        try {
            # Establish or verify Microsoft Graph connection (needed for tenant domain resolution)
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Initialize results collection
            $CalendarPermissions = [System.Collections.Generic.List[PSObject]]::new()

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
                $ExchangeConnected = $true
                Write-Verbose 'Successfully connected to Exchange Online.'
            } catch {
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Exchange Online connection required: $($_.Exception.Message)"),
                        'ExchangeConnectionError',
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $null
                    ))
            }

            # Retrieve mailboxes via Exchange Online (better coverage than Graph users)
            Write-Verbose 'Retrieving mailboxes via Exchange Online...'

            $TargetMailboxes = (Get-EXOMailbox -ResultSize Unlimited -Properties RecipientTypeDetails, PrimarySmtpAddress, DisplayName, UserPrincipalName).Where({
                $_.RecipientTypeDetails -in @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')
            })

            if (-not $IncludeSystemAccounts) {
                $TargetMailboxes = $TargetMailboxes.Where({
                    $_.Name -notlike 'HealthMailbox*' -and
                    $_.Name -notlike 'SystemMailbox*' -and
                    $_.Name -notlike 'DiscoverySearchMailbox*' -and
                    $_.Name -notlike 'Migration.*' -and
                    $_.Name -notlike 'FederatedEmail.*'
                })
            }

            # Use parallel processing for calendar permissions
            Write-Verbose "Processing $($TargetMailboxes.Count) mailboxes in parallel for calendar folder permissions..."

            $AllCalendarPermissions = $TargetMailboxes | ForEach-Object -Parallel {
                $UserCalendarPermissions = [System.Collections.Generic.List[PSObject]]::new()

                foreach ($FolderName in $using:CalendarFolderNames) {
                    try {
                        $FolderPath = "$($_.UserPrincipalName):\$($FolderName)"
                        $FolderPerms = Get-EXOMailboxFolderPermission -Identity $FolderPath -ErrorAction Stop

                        if ($FolderPerms) {
                            # Filter out Default and Anonymous entries unless explicitly included
                            if (-not $using:IncludeDefaultPermissions) {
                                $FolderPerms = @($FolderPerms.Where({
                                    $_.User.DisplayName -notin @('Default', 'Anonymous') -and
                                    $_.User.DisplayName -ne $_.FolderName -and
                                    $_.AccessRights -ne 'None'
                                }))
                            }

                            foreach ($Perm in $FolderPerms) {
                                $UserCalendarPermissions.Add([PSCustomObject]@{
                                        UserPrincipalName          = $_.UserPrincipalName
                                        DisplayName                = $_.DisplayName
                                        FolderName                 = $FolderName
                                        FolderPath                 = $FolderPath
                                        GrantedToUser              = $Perm.User.DisplayName
                                        GrantedToUserPrincipalName = $Perm.User.UserPrincipalName
                                        AccessRights               = $Perm.AccessRights -join ', '
                                        SharingPermissionFlags     = $Perm.SharingPermissionFlags
                                    })
                            }

                            # Break after finding the first valid calendar folder
                            if ($FolderPerms.Count -gt 0) {
                                break
                            }
                        }
                    } catch {
                        # Silent handling for each folder attempt
                        continue
                    }
                }

                return $UserCalendarPermissions
            } -ThrottleLimit 20

            # Process the calendar permissions into the standard format
            foreach ($CalPerm in $AllCalendarPermissions) {
                $CalendarPermissions.Add([PSCustomObject]@{
                        Mailbox                = $CalPerm.UserPrincipalName
                        MailboxDisplayName     = $CalPerm.DisplayName
                        CalendarName           = $CalPerm.FolderName
                        FolderPath             = $CalPerm.FolderPath
                        GrantedTo              = $CalPerm.GrantedToUserPrincipalName
                        GrantedToName          = $CalPerm.GrantedToUser
                        AccessRights           = $CalPerm.AccessRights
                        SharingPermissionFlags = $CalPerm.SharingPermissionFlags
                    })
            }

            $Summary = [PSCustomObject]@{
                TotalPermissions         = $CalendarPermissions.Count
                UniqueGrantees           = ($CalendarPermissions | Select-Object -ExpandProperty GrantedTo -Unique).Count
                UsersWithSharedCalendars = ($CalendarPermissions | Select-Object -ExpandProperty Mailbox -Unique).Count
            }

            Write-Information "Calendar permissions analysis completed - $($Summary.TotalPermissions) permissions found" -InformationAction Continue
            
            [PSCustomObject][Ordered]@{
                Summary             = $Summary
                CalendarPermissions = $CalendarPermissions
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntExchangeCalendarPermissionReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntExchangeCalendarPermissionReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            try {
                # Only disconnect if we established the connection
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo | Out-Null

                if ($ExchangeConnected) {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null
                }
            } catch {
                Write-Verbose "Could not disconnect from services: $($_.Exception.Message)"
            }
        }
    }
}
