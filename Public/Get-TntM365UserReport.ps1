function Get-TntM365UserReport {
    <#
    .SYNOPSIS
        Generates a security report of all Microsoft 365 users including licenses, sign-in activity, and MFA status.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and retrieves detailed security
        information for all users in the tenant. It provides insights into user licensing, authentication
        methods, last sign-in activity, password changes, and MFA device registrations.

        in PowerShell scripts.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Accepts SecureString or plain String.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER SignInLookbackDays
        Number of days to look back for sign-in activity. Defaults to 90 days.

    .PARAMETER ExcludeDisabledUsers
        Switch to exclude disabled user accounts from the report. By default, disabled users are included.

    .PARAMETER ExcludeGuestUsers
        Switch to exclude guest user accounts from the report. By default, guest users are included.

    .PARAMETER MaxUsers
        Maximum number of users to process. Useful for testing or large tenant limits.

    .EXAMPLE
        Get-TntM365UserReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a comprehensive user security report.

    .EXAMPLE
        Get-TntM365UserReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret |
            ConvertTo-Json -Depth 10 | Out-File -Path 'UserReport.json'

        Exports the report to JSON format.

    .EXAMPLE
        $Report = Get-TntM365UserReport @params -ExcludeDisabledUsers -ExcludeGuestUsers
        $Report.UserDetails | Where-Object { $_.IsMfaRegistered -eq $false } | Format-Table

        Retrieves only enabled member users and displays those without MFA.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured report object containing:
        - Summary: User counts, MFA adoption rates, license statistics
        - UserDetails: Detailed information for each user
        - MfaMethodAnalysis: MFA method usage breakdown
        - LicenseAnalysis: License distribution analysis

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Azure AD Application Permissions:
        - User.Read.All (Application)
        - UserAuthenticationMethod.Read.All (Application)
        - AuditLog.Read.All (Application)
        - Reports.Read.All (Application)
        - Directory.Read.All (Application)
        - Organization.Read.All (Application)

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        # Tenant ID of the Microsoft 365 tenant.
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        # Application (client) ID of the registered app.
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
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

        # Number of days of sign-in history to analyze.
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$SignInLookbackDays = 90,

        # Switch to exclude disabled accounts.
        [Parameter()]
        [switch]$ExcludeDisabledUsers,

        # Switch to exclude guest accounts.
        [Parameter()]
        [switch]$ExcludeGuestUsers,

        # Maximum number of users to process (testing limit).
        [Parameter()]
        [ValidateRange(1, 100000)]
        [int]$MaxUsers
    )

    begin {
        # Load .CSV with SKU Translation table for retrieving friendly license names
        $SkuHashTable = @{}
        Get-SkuTranslationTable | Group-Object GUID | ForEach-Object {
            $SkuHashTable[$_.Name] = ($_.Group | Select-Object -First 1).Product_Display_Name
        }

        # MFA Method types array for individual property mapping
        $AllMethods = @(
            [pscustomobject]@{type = 'microsoftAuthenticatorPasswordless'; Name = 'Microsoft Authenticator Passwordless'; Strength = 'Strong' }
            [pscustomobject]@{type = 'fido2SecurityKey'; AltName = 'Fido2'; Name = 'Fido2 Security Key'; Strength = 'Strong' }
            [pscustomobject]@{type = 'passKeyDeviceBound'; AltName = 'Fido2'; Name = 'Device Bound Passkey'; Strength = 'Strong' }
            [pscustomobject]@{type = 'passKeyDeviceBoundAuthenticator'; AltName = 'Fido2'; Name = 'Microsoft Authenticator Passkey'; Strength = 'Strong' }
            [pscustomobject]@{type = 'passKeyDeviceBoundWindowsHello'; AltName = 'Fido2'; Name = 'Windows Hello Passkey'; Strength = 'Strong' }
            [pscustomobject]@{type = 'microsoftAuthenticatorPush'; AltName = 'MicrosoftAuthenticator'; Name = 'Microsoft Authenticator App'; Strength = 'Strong' }
            [pscustomobject]@{type = 'softwareOneTimePasscode'; AltName = 'SoftwareOath'; Name = 'Software OTP'; Strength = 'Strong' }
            [pscustomobject]@{type = 'hardwareOneTimePasscode'; AltName = 'HardwareOath'; Name = 'Hardware OTP'; Strength = 'Strong' }
            [pscustomobject]@{type = 'windowsHelloForBusiness'; AltName = 'windowsHelloForBusiness'; Name = 'Windows Hello for Business'; Strength = 'Strong' }
            [pscustomobject]@{type = 'temporaryAccessPass'; AltName = 'TemporaryAccessPass'; Name = 'Temporary Access Pass'; Strength = 'Strong' }
            [pscustomobject]@{type = 'macOsSecureEnclaveKey'; Name = 'MacOS Secure Enclave Key'; Strength = 'Strong' }
            [pscustomobject]@{type = 'SMS'; AltName = 'SMS'; Name = 'SMS'; Strength = 'Weak' }
            [pscustomobject]@{type = 'Voice Call'; AltName = 'voice'; Name = 'Voice Call'; Strength = 'Weak' }
            [pscustomobject]@{type = 'email'; AltName = 'Email'; Name = 'Email'; Strength = 'Weak' }
            [pscustomobject]@{type = 'alternateMobilePhone'; AltName = 'Voice'; Name = 'Alternative Mobile Phone'; Strength = 'Weak' }
            [pscustomobject]@{type = 'securityQuestion'; AltName = 'Security Questions'; Name = 'Security Questions'; Strength = 'Weak' }
        )

        Write-Information 'Starting user security report generation...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            # Retrieve users with required properties - Using Get-MgBetaUser to access lastSuccessfulSignInDateTime
            Write-Verbose 'Retrieving user accounts...'
            $UserProperties = @(
                'Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled', 'Mail',
                'UserType', 'CreatedDateTime', 'LastPasswordChangeDateTime',
                'SignInActivity', 'AssignedLicenses', 'UsageLocation'
            )
            $AllUsers = Get-MgBetaUser -All -Property $UserProperties -ErrorAction Stop

            # Apply initial filters
            $FilteredUsers = $AllUsers
            if ($ExcludeDisabledUsers) {
                $FilteredUsers = $FilteredUsers | Where-Object { $_.AccountEnabled -eq $true }
            }
            if ($ExcludeGuestUsers) {
                $FilteredUsers = $FilteredUsers | Where-Object { $_.UserType -ne 'Guest' }
            }
            if ($MaxUsers) {
                $FilteredUsers = $FilteredUsers | Select-Object -First $MaxUsers
            }

            Write-Verbose "Found $($FilteredUsers.Count) users to process after filtering"

            # Get subscription information for license translation
            Write-Verbose 'Retrieving subscription information for license mapping fallback...'
            $SubscribedSkus = @{}
            try {
                $Skus = Get-MgSubscribedSku -All -ErrorAction SilentlyContinue
                foreach ($Sku in $Skus) {
                    $SubscribedSkus[$Sku.SkuId] = $Sku.SkuPartNumber
                }
            } catch {
                Write-Warning "Unable to retrieve subscription information for license mapping: $($_.Exception.Message)"
            }

            # Retrieve MFA registration data for all users
            try {
                Write-Verbose 'Retrieving MFA registration information...'
                $MfaRegistrationData = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
            } catch {
                Write-Error "Error retrieving MFA registration information: $($_.Exception.Message)"
            }

            # Create lookup table for MFA data by UserPrincipalName
            $MfaLookup = @{}
            foreach ($MfaUser in $MfaRegistrationData) {
                if ($MfaUser.UserPrincipalName) {
                    $MfaLookup[$MfaUser.UserPrincipalName] = $MfaUser
                }
            }

            Write-Verbose "Processing $($FilteredUsers.Count) users..."

            # Process each user and combine data
            $UserSecurityReport = [System.Collections.Generic.List[PSObject]]::new()

            foreach ($User in $FilteredUsers) {
                try {
                    # Get corresponding MFA data
                    $MfaData = $MfaLookup[$User.UserPrincipalName]

                    # Translate assigned licenses to friendly name
                    try {
                        $UserLicenses = $User.AssignedLicenses | ForEach-Object {
                            Resolve-SkuName -SkuId $_.SkuId -SkuHashTable $SkuHashTable
                        } | Where-Object { $_ } | Sort-Object -Unique -ErrorAction Stop
                    } catch {
                        Write-Error 'Could not translate license with SKU Translation table. Falling back to native Graph method.'
                        $UserLicenses = $User.AssignedLicenses | ForEach-Object {
                            $SkuId = $_.SkuId
                            if ($SubscribedSkus.ContainsKey($SkuId)) {
                                $SubscribedSkus[$SkuId]
                            } else {
                                "Unknown License ($SkuId)"
                            }
                        }
                    }

                    # Parse sign-in dates safely
                    # LastSignInDate includes both successful and failed sign-ins
                    $LastSignInDate = $null
                    $DaysSinceLastSignIn = $null

                    if ($User.SignInActivity.LastSignInDateTime) {
                        try {
                            $LastSignInDate = [DateTime]$User.SignInActivity.LastSignInDateTime
                            $DaysSinceLastSignIn = [Math]::Abs((New-TimeSpan -Start $LastSignInDate -End (Get-Date)).Days)
                        } catch {
                            $LastSignInDate = 'Invalid Date'
                            $DaysSinceLastSignIn = 'N/A'
                        }
                    } else {
                        $LastSignInDate = 'Never'
                        $DaysSinceLastSignIn = 'N/A'
                    }

                    # Parse successful sign-in date (Beta API only - excludes failed sign-ins)
                    $LastSuccessfulSignInDate = $null
                    $DaysSinceLastSuccessfulSignIn = $null

                    if ($User.SignInActivity.lastSuccessfulSignInDateTime) {
                        try {
                            $LastSuccessfulSignInDate = [DateTime]$User.SignInActivity.lastSuccessfulSignInDateTime
                            $DaysSinceLastSuccessfulSignIn = [Math]::Abs((New-TimeSpan -Start $LastSuccessfulSignInDate -End (Get-Date)).Days)
                        } catch {
                            $LastSuccessfulSignInDate = 'Invalid Date'
                            $DaysSinceLastSuccessfulSignIn = 'N/A'
                        }
                    } else {
                        $LastSuccessfulSignInDate = 'N/A'
                        $DaysSinceLastSuccessfulSignIn = 'N/A'
                    }

                    # Parse password change date
                    $LastPasswordChangeDate = $null
                    $DaysSincePasswordChange = $null

                    if ($User.LastPasswordChangeDateTime) {
                        try {
                            $LastPasswordChangeDate = [DateTime]$User.LastPasswordChangeDateTime
                            $DaysSincePasswordChange = [Math]::Abs((New-TimeSpan -Start $LastPasswordChangeDate -End (Get-Date)).Days)
                        } catch {
                            $LastPasswordChangeDate = 'Invalid Date'
                            $DaysSincePasswordChange = 'N/A'
                        }
                    } else {
                        $LastPasswordChangeDate = 'N/A'
                        $DaysSincePasswordChange = 'N/A'
                    }

                    # Determine MFA status and methods
                    $MfaStatus = 'Unknown'
                    $MfaMethods = @()
                    $IsPasswordlessCapable = $false
                    $IsSsprRegistered = $false
                    $DefaultMfaMethod = 'None'

                    if ($MfaData) {
                        $MfaStatus = if ($MfaData.IsMfaRegistered -eq $true) { 'Registered' } else { 'Not Registered' }
                        $MfaMethods = if ($MfaData.MethodsRegistered) { $MfaData.MethodsRegistered } else { @() }
                        $IsPasswordlessCapable = $MfaData.IsPasswordlessCapable -eq $true
                        $IsSsprRegistered = $MfaData.IsSsprRegistered -eq $true
                        $DefaultMfaMethod = if ($MfaData.UserPreferredMethodForSecondaryAuthentication) { $MfaData.UserPreferredMethodForSecondaryAuthentication } else { 'None' }
                    }

                    # Create individual boolean properties for each MFA method
                    $MfaMethodProperties = @{}
                    foreach ($Method in $AllMethods) {
                        $PropertyName = "Has$($Method.Name.Replace(' ', '').Replace('-', ''))"
                        $MfaMethodProperties[$PropertyName] = $MfaMethods -contains $Method.type
                    }

                    # Create comprehensive user security entry
                    $UserEntry = [PSCustomObject]@{
                        #UserId = $User.Id
                        DisplayName                        = $User.DisplayName
                        UserPrincipalName                  = $User.UserPrincipalName
                        EmailAddress                       = $User.Mail ?? 'N/A'
                        AccountEnabled                     = $User.AccountEnabled
                        UserType                           = $User.UserType
                        CreatedDateTime                    = $User.CreatedDateTime
                        UsageLocation                      = $User.UsageLocation

                        # License Information
                        AssignedLicenses                   = ($UserLicenses -join ', ')
                        LicenseCount                       = $UserLicenses.Count

                        # Sign-in Activity
                        LastSignInDate                     = $LastSignInDate
                        DaysSinceLastSignIn                = $DaysSinceLastSignIn
                        LastSuccessfulSignInDate           = $LastSuccessfulSignInDate
                        DaysSinceLastSuccessfulSignIn      = $DaysSinceLastSuccessfulSignIn
                        IsInactive                         = if ($null -ne $DaysSinceLastSuccessfulSignIn -and $DaysSinceLastSuccessfulSignIn -is [int]) {
                            if ($DaysSinceLastSuccessfulSignIn -gt $SignInLookbackDays) { $true } else { $false }
                        } else {
                            if ($DaysSinceLastSignIn -gt $SignInLookbackDays) { $true } else { $false }
                        }

                        # Password Information
                        LastPasswordChangeDate             = $LastPasswordChangeDate
                        DaysSincePasswordChange            = $DaysSincePasswordChange

                        # MFA Information
                        IsAdmin                            = if ($MfaData) { $MfaData.IsAdmin } else { $false }
                        MfaStatus                          = $MfaStatus
                        IsMfaCapable                       = if ($MfaData) { $MfaData.IsMfaCapable } else { $false }
                        IsMfaRegistered                    = if ($MfaData) { $MfaData.IsMfaRegistered } else { $false }
                        DefaultMfaMethod                   = $DefaultMfaMethod
                        SystemPreferredMfaEnabled          = if ($MfaData) { $MfaData.IsSystemPreferredAuthenticationMethodEnabled } else { $false }

                        MfaMethodsRegistered               = ($MfaMethods -join ', ')
                        MfaMethodCount                     = $MfaMethods.Count
                        IsPasswordlessCapable              = $IsPasswordlessCapable

                        # Individual MFA method properties
                        MicrosoftAuthenticatorPasswordless = $MfaMethodProperties['HasMicrosoftAuthenticatorPasswordless']
                        Fido2SecurityKey                   = $MfaMethodProperties['HasFido2SecurityKey']
                        DeviceBoundPasskey                 = $MfaMethodProperties['HasDeviceBoundPasskey']
                        MicrosoftAuthenticatorPasskey      = $MfaMethodProperties['HasMicrosoftAuthenticatorPasskey']
                        WindowsHelloPasskey                = $MfaMethodProperties['HasWindowsHelloPasskey']
                        MicrosoftAuthenticatorApp          = $MfaMethodProperties['HasMicrosoftAuthenticatorApp']
                        SoftwareOTP                        = $MfaMethodProperties['HasSoftwareOTP']
                        HardwareOTP                        = $MfaMethodProperties['HasHardwareOTP']
                        WindowsHelloforBusiness            = $MfaMethodProperties['HasWindowsHelloforBusiness']
                        TemporaryAccessPass                = $MfaMethodProperties['HasTemporaryAccessPass']
                        MacOSSecureEnclaveKey              = $MfaMethodProperties['HasMacOSSecureEnclaveKey']
                        SMS                                = $MfaMethodProperties['HasSMS']
                        VoiceCall                          = $MfaMethodProperties['HasVoiceCall']
                        Email                              = $MfaMethodProperties['HasEmail']
                        AlternativeMobilePhone             = $MfaMethodProperties['HasAlternativeMobilePhone']
                        SecurityQuestions                  = $MfaMethodProperties['HasSecurityQuestions']

                        # SSPR Information
                        IsSsprRegistered                   = $IsSsprRegistered
                        IsSsprCapable                      = if ($MfaData) { $MfaData.IsSsprCapable } else { $false }
                    }

                    $UserSecurityReport.Add($UserEntry)
                } catch {
                    Write-Warning "Error processing user $($User.UserPrincipalName): $($_.Exception.Message)"
                    continue
                }
            }

            # Generate comprehensive summary statistics using single-pass accumulation
            $Stats = @{
                EnabledUsers             = 0
                DisabledUsers            = 0
                GuestUsers               = 0
                AdminUsers               = 0
                LicensedUsers            = 0
                UnlicensedUsers          = 0
                MfaRegisteredUsers       = 0
                MfaNotRegisteredUsers    = 0
                MfaCapableUsers          = 0
                PasswordlessCapableUsers = 0
                SsprRegisteredUsers      = 0
                SsprCapableUsers         = 0
                InactiveUsers            = 0
                NeverSignedInUsers       = 0
            }

            foreach ($User in $UserSecurityReport) {
                if ($User.AccountEnabled) { $Stats.EnabledUsers++ } else { $Stats.DisabledUsers++ }
                if ($User.UserType -eq 'Guest') { $Stats.GuestUsers++ }
                if ($User.IsAdmin) { $Stats.AdminUsers++ }
                if ($User.LicenseCount -gt 0) { $Stats.LicensedUsers++ } else { $Stats.UnlicensedUsers++ }
                if ($User.IsMfaRegistered) { $Stats.MfaRegisteredUsers++ } else { $Stats.MfaNotRegisteredUsers++ }
                if ($User.IsMfaCapable) { $Stats.MfaCapableUsers++ }
                if ($User.IsPasswordlessCapable) { $Stats.PasswordlessCapableUsers++ }
                if ($User.IsSsprRegistered) { $Stats.SsprRegisteredUsers++ }
                if ($User.IsSsprCapable) { $Stats.SsprCapableUsers++ }
                if ($User.IsInactive) { $Stats.InactiveUsers++ }
                if ($User.LastSignInDate -eq 'Never') { $Stats.NeverSignedInUsers++ }
            }

            $TotalUsers = $UserSecurityReport.Count
            $Summary = [PSCustomObject]@{
                ReportGeneratedDate      = Get-Date
                TenantId                 = $TenantId

                # User counts
                TotalUsers               = $TotalUsers
                EnabledUsers             = $Stats.EnabledUsers
                DisabledUsers            = $Stats.DisabledUsers
                GuestUsers               = $Stats.GuestUsers
                AdminUsers               = $Stats.AdminUsers

                # License statistics
                LicensedUsers            = $Stats.LicensedUsers
                UnlicensedUsers          = $Stats.UnlicensedUsers

                # MFA statistics
                MfaRegisteredUsers       = $Stats.MfaRegisteredUsers
                MfaNotRegisteredUsers    = $Stats.MfaNotRegisteredUsers
                MfaCapableUsers          = $Stats.MfaCapableUsers
                PasswordlessCapableUsers = $Stats.PasswordlessCapableUsers

                # SSPR statistics
                SsprRegisteredUsers      = $Stats.SsprRegisteredUsers
                SsprCapableUsers         = $Stats.SsprCapableUsers

                # Activity statistics
                InactiveUsers            = $Stats.InactiveUsers
                NeverSignedInUsers       = $Stats.NeverSignedInUsers

                # Security posture percentages
                MfaAdoptionRate          = if ($TotalUsers -gt 0) {
                    [Math]::Round(($Stats.MfaRegisteredUsers / $TotalUsers) * 100, 2)
                } else { 0 }

                SsprAdoptionRate         = if ($TotalUsers -gt 0) {
                    [Math]::Round(($Stats.SsprRegisteredUsers / $TotalUsers) * 100, 2)
                } else { 0 }
            }

            Write-Information "User security report completed - $($UserSecurityReport.Count) users processed" -InformationAction Continue

            [PSCustomObject]@{
                Summary           = $Summary
                UserDetails       = $UserSecurityReport | Sort-Object DisplayName
                MfaMethodAnalysis = $UserSecurityReport | Where-Object { $_.MfaMethodsRegistered } |
                    Group-Object { $_.MfaMethodsRegistered } |
                    Select-Object Name, Count |
                    Sort-Object Count -Descending
                LicenseAnalysis   = $UserSecurityReport | Where-Object { $_.AssignedLicenses } |
                    Group-Object { $_.AssignedLicenses } |
                    Select-Object Name, Count |
                    Sort-Object Count -Descending
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntM365UserReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntM365UserReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            # Only disconnect if we established the connection
            Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
        }
    }
}

