function Get-TntIntuneAppleCertificateReport {
    <#
    .SYNOPSIS
        Monitors Apple Device Enrollment Program (DEP) tokens and Apple Push Notification Service (APNS) certificates expiration in Microsoft Intune.

    .DESCRIPTION
        This function connects to Microsoft Graph using an app registration and generates detailed reports about
        Apple DEP tokens, APNS certificates, and VPP (Volume Purchase Program) tokens. It identifies certificates
        and tokens nearing expiration to prevent service disruptions for iOS/iPadOS and macOS device management.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER ThresholdInDays
        Number of days before expiration to flag certificates/tokens as expiring. Defaults to 30 days.

    .EXAMPLE
        Get-TntIntuneAppleCertificateReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Monitors all Apple certificates and tokens, showing those expiring within 30 days.

    .EXAMPLE
        Get-TntIntuneAppleCertificateReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -ThresholdInDays 60

        Monitors certificates with 60-day threshold.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a comprehensive report object containing:
        - Summary: Counts of items by status and type
        - AllItems: Detailed list of all certificates and tokens with status and risk level

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - DeviceManagementConfiguration.Read.All (Application)
        - DeviceManagementManagedDevices.Read.All (Application)
        - DeviceManagementApps.Read.All (Application)

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
        [ValidateRange(1, 365)]
        [int]$ThresholdInDays = 30
    )

    begin {
        # Define certificate/token types for risk assessment
        $CertificateTypeRisk = @{
            'APNS' = @{
                RiskLevel    = 'Critical'
                Impact       = 'All iOS/iPadOS/macOS devices will lose management capabilities'
                Renewability = 'Must be renewed with same Apple ID'
            }
            'DEP'  = @{
                RiskLevel    = 'High'
                Impact       = 'New device enrollment via DEP/ABM/ASM will fail'
                Renewability = 'Can be renewed with different Apple ID'
            }
            'VPP'  = @{
                RiskLevel    = 'Medium'
                Impact       = 'App deployment and license management will be affected'
                Renewability = 'Can be renewed with same Apple ID'
            }
        }

        Write-Information 'Starting Apple certificate and token expiration monitoring...' -InformationAction Continue
    }

    process {
        try {
            # Establish connection
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            # Initialize collections for certificate/token data
            $AllItems = [System.Collections.Generic.List[PSObject]]::new()
            $Errors   = [System.Collections.Generic.List[PSObject]]::new()
            $Now      = [datetime]::Now

            # Get APNS Certificate
            Write-Verbose 'Retrieving Apple Push Notification Certificate...'
            try {
                $ApnsCertUri = 'https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate'
                $ApnsCert = Invoke-MgGraphRequest -Uri $ApnsCertUri -Method GET -ErrorAction Stop

                if ($ApnsCert) {
                    $DaysUntilExpiry = ([DateTime]$ApnsCert.ExpirationDateTime - $Now).Days
                    $IsExpired = $DaysUntilExpiry -lt 0
                    $IsExpiring = $DaysUntilExpiry -le $ThresholdInDays -and $DaysUntilExpiry -ge 0

                    $ApnsItem = [PSCustomObject]@{
                        Type                    = 'APNS'
                        Name                    = 'Apple Push Notification Certificate'
                        AppleIdentifier         = $ApnsCert.AppleIdentifier ?? 'Not available'
                        ExpirationDateTime      = $ApnsCert.ExpirationDateTime
                        DaysUntilExpiry         = $DaysUntilExpiry
                        IsExpired               = $IsExpired
                        IsExpiring              = $IsExpiring
                        RiskLevel               = $CertificateTypeRisk['APNS'].RiskLevel
                        Impact                  = $CertificateTypeRisk['APNS'].Impact
                        RenewalGuidance         = $CertificateTypeRisk['APNS'].Renewability
                        LastModifiedDateTime    = $ApnsCert.LastModifiedDateTime
                        CertificateSerialNumber = $ApnsCert.CertificateSerialNumber ?? 'Not available'
                        Status                  = if ($IsExpired) { 'Expired' } elseif ($IsExpiring) { 'ExpiringSoon' } else { 'Valid' }
                    }

                    $AllItems.Add($ApnsItem)

                    Write-Verbose "APNS Certificate: $(if ($ApnsCert.ExpirationDateTime) { "Expires $($ApnsCert.ExpirationDateTime) ($($DaysUntilExpiry) days)" } else { 'No expiration data available' })"
                } else {
                    Write-Verbose 'No APNS Certificates found in the tenant'
                }
            } catch {
                # This endpoint throws a terminating error if no cert is found which messes up Invoke-SecurityReport; suppress error if 'NotFound' in error msg.
                if ($_.Exception.Message -match 'NotFound') {
                    Write-Verbose 'No APNS Certificates found in the tenant'
                } else {
                    $ErrorMsg = "Failed to retrieve APNS certificate: $($_.Exception.Message)"
                    Write-Warning $ErrorMsg
                    $Errors.Add([PSCustomObject]@{
                            Type  = 'APNS'
                            Error = $ErrorMsg
                        })
                }
            }

            # Get DEP Tokens
            Write-Verbose 'Retrieving Apple DEP (Device Enrollment Program) tokens...'
            try {
                # DEP tokens are in beta endpoint
                $DepTokensUri = 'https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings'
                $DepTokensResponse = Invoke-MgGraphRequest -Uri $DepTokensUri -Method GET -ErrorAction Stop

                if ($DepTokensResponse.value -and $DepTokensResponse.value.Count -gt 0) {
                    foreach ($DepToken in $DepTokensResponse.value) {
                        if ($DepToken.tokenExpirationDateTime) {
                            $DaysUntilExpiry = ([DateTime]$DepToken.tokenExpirationDateTime - $Now).Days
                            $IsExpired = $DaysUntilExpiry -lt 0
                            $IsExpiring = $DaysUntilExpiry -le $ThresholdInDays -and $DaysUntilExpiry -ge 0

                            $DepItem = [PSCustomObject]@{
                                Type                 = 'DEP'
                                Name                 = "$($DepToken.tokenName ?? 'DEP Token') ($($DepToken.tokenType ?? 'Unknown Type'))"
                                AppleIdentifier      = $DepToken.appleIdentifier ?? 'Not available'
                                ExpirationDateTime   = $DepToken.tokenExpirationDateTime
                                DaysUntilExpiry      = $DaysUntilExpiry
                                IsExpired            = $IsExpired
                                IsExpiring           = $IsExpiring
                                RiskLevel            = $CertificateTypeRisk['DEP'].RiskLevel
                                Impact               = $CertificateTypeRisk['DEP'].Impact
                                RenewalGuidance      = $CertificateTypeRisk['DEP'].Renewability
                                LastModifiedDateTime = $DepToken.lastModifiedDateTime
                                LastSuccessfulSync   = $DepToken.lastSuccessfulSyncDateTime
                                SyncedDeviceCount    = $DepToken.syncedDeviceCount ?? 0
                                TokenId              = $DepToken.id
                                Status               = if ($IsExpired) { 'Expired' } elseif ($IsExpiring) { 'ExpiringSoon' } else { 'Valid' }
                            }

                            $AllItems.Add($DepItem)
                        }
                    }

                    Write-Verbose "Found $($DepTokensResponse.value.Count) DEP token(s)"
                } else {
                    Write-Verbose 'No DEP tokens found in the tenant'
                }
            } catch {
                $ErrorMsg = "Failed to retrieve DEP tokens: $($_.Exception.Message)"
                Write-Warning $ErrorMsg
                $Errors.Add([PSCustomObject]@{
                        Type  = 'DEP'
                        Error = $ErrorMsg
                    })
            }

            # Get VPP Tokens
            Write-Verbose 'Retrieving Apple VPP (Volume Purchase Program) tokens...'
            try {
                # VPP tokens are in beta endpoint
                $VppTokensUri = 'https://graph.microsoft.com/beta/deviceAppManagement/vppTokens'
                $VppTokensResponse = Invoke-MgGraphRequest -Uri $VppTokensUri -Method GET -ErrorAction Stop

                if ($VppTokensResponse.value -and $VppTokensResponse.value.Count -gt 0) {
                    foreach ($VppToken in $VppTokensResponse.value) {
                        if ($VppToken.expirationDateTime) {
                            $DaysUntilExpiry = ([DateTime]$VppToken.expirationDateTime - $Now).Days
                            $IsExpired = $DaysUntilExpiry -lt 0
                            $IsExpiring = $DaysUntilExpiry -le $ThresholdInDays -and $DaysUntilExpiry -ge 0

                            $VppItem = [PSCustomObject]@{
                                Type                 = 'VPP'
                                Name                 = "$($VppToken.organizationName ?? 'VPP Token') ($($VppToken.vppTokenAccountType ?? 'Unknown Account Type'))"
                                AppleIdentifier      = $VppToken.appleId ?? 'Not available'
                                ExpirationDateTime   = $VppToken.expirationDateTime
                                DaysUntilExpiry      = $DaysUntilExpiry
                                IsExpired            = $IsExpired
                                IsExpiring           = $IsExpiring
                                RiskLevel            = $CertificateTypeRisk['VPP'].RiskLevel
                                Impact               = $CertificateTypeRisk['VPP'].Impact
                                RenewalGuidance      = $CertificateTypeRisk['VPP'].Renewability
                                LastModifiedDateTime = $VppToken.lastModifiedDateTime
                                LastSyncDateTime     = $VppToken.lastSyncDateTime
                                TokenId              = $VppToken.id
                                CountryOrRegion      = $VppToken.countryOrRegion ?? 'Not specified'
                                Status               = if ($IsExpired) { 'Expired' } elseif ($IsExpiring) { 'ExpiringSoon' } else { 'Valid' }
                            }

                            $AllItems.Add($VppItem)
                        }
                    }

                    Write-Verbose "Found $($VppTokensResponse.value.Count) VPP token(s)"
                } else {
                    Write-Verbose 'No VPP tokens found in the tenant'
                }
            } catch {
                $ErrorMsg = "Failed to retrieve VPP tokens: $($_.Exception.Message)"
                Write-Warning $ErrorMsg
                $Errors.Add([PSCustomObject]@{
                        Type  = 'VPP'
                        Error = $ErrorMsg
                    })
            }

            # Throw terminating error if no cert/token is found at all
            if ($AllItems.Count -eq 0) {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('Get-TntIntuneAppleCertificateReport failed: No Apple certificates/tokens found.'),
                    'GetTntIntuneAppleCertificateReportError',
                    [System.Management.Automation.ErrorCategory]::OperationStopped,
                    $TenantId
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        
            # Generate summary statistics
            $ExpiringCount = $AllItems.Where({ $_.IsExpiring }).Count
            $Summary = [PSCustomObject]@{
                TenantId            = $TenantId
                ReportGeneratedDate = $Now
                TotalItems          = $AllItems.Count
                ExpiringItems       = $ExpiringCount
                ExpiredItems        = $AllItems.Where({ $_.IsExpired }).Count
                ValidItems          = $AllItems.Where({ -not $_.IsExpired -and -not $_.IsExpiring }).Count
                APNSCertificates    = $AllItems.Where({ $_.Type -eq 'APNS' }).Count
                DEPTokens           = $AllItems.Where({ $_.Type -eq 'DEP' }).Count
                VPPTokens           = $AllItems.Where({ $_.Type -eq 'VPP' }).Count
            }

            Write-Information "Apple certificate monitoring completed - $($AllItems.Count) items checked ($ExpiringCount expiring soon)" -InformationAction Continue

            [PSCustomObject]@{
                Summary  = $Summary
                AllItems = $AllItems | Sort-Object Type, DaysUntilExpiry
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntIntuneAppleCertificateReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntIntuneAppleCertificateReportError',
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
