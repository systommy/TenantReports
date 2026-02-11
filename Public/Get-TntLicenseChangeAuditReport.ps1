function Get-TntLicenseChangeAuditReport {
    <#
    .SYNOPSIS
        Reports on license change audit events from directory audit logs.

    .DESCRIPTION
        Queries the Microsoft Graph directoryAudits API for license change events and provides
        a summary of license additions, removals, and most affected users over a configurable
        time period.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .PARAMETER DaysBack
        Number of days to look back for license change events. Defaults to 30.

    .EXAMPLE
        Get-TntLicenseChangeAuditReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves license change audit events from the last 30 days.

    .EXAMPLE
        Get-TntLicenseChangeAuditReport -TenantId $tid -ClientId $cid -ClientSecret $secret -DaysBack 90

        Retrieves license change audit events from the last 90 days.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Total changes, additions, removals, most changed users
        - Changes: Detailed list of license change records

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - AuditLog.Read.All (Application)

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
        [switch]$Interactive,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysBack = 30
    )

    begin {
        # Load SKU translation table for friendly license names
        $SkuHashTable = @{}
        $SkuTable = Get-SkuTranslationTable
        if ($SkuTable) {
            foreach ($SkuGroup in ($SkuTable | Group-Object GUID)) {
                $SkuHashTable[$SkuGroup.Name] = ($SkuGroup.Group | Select-Object -First 1).Product_Display_Name
            }
        } else {
            Write-Verbose 'SKU Translation Table not available.'
        }

        Write-Information 'STARTED  : License change audit analysis...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            $Changes = [System.Collections.Generic.List[PSCustomObject]]::new()

            # Build filter date
            $FilterDate = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $Filter     = "activityDateTime ge $FilterDate and activityDisplayName eq 'Change user license'"
            $Uri        = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$Filter&`$top=999"

            Write-Verbose "Querying audit logs from $FilterDate..."

            # Page through results
            do {
                $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
                foreach ($AuditEvent in $Response.value) {
                    # Skip failed events and signup noise
                    if ($AuditEvent.result -eq 'failure') { continue }

                    $InitiatedBy = if ($AuditEvent.initiatedBy.user) {
                        $AuditEvent.initiatedBy.user.userPrincipalName ?? $AuditEvent.initiatedBy.user.displayName ?? 'Unknown User'
                    } elseif ($AuditEvent.initiatedBy.app) {
                        $AuditEvent.initiatedBy.app.displayName ?? 'Unknown App'
                    } else {
                        'Unknown'
                    }

                    # Skip Signup-initiated events
                    if ($InitiatedBy -eq 'Signup') { continue }

                    $TargetUser         = @($AuditEvent.targetResources).Where({ $_.type -eq 'User' }) | Select-Object -First 1
                    $ModifiedProperties = if ($TargetUser) { $TargetUser.modifiedProperties } else { @() }

                    $AddedLicenses   = @()
                    $RemovedLicenses = @()

                    foreach ($Prop in $ModifiedProperties) {
                        if ($Prop.displayName -eq 'AssignedLicense') {
                            # Helper to extract SkuIds from the audit log license data
                            # The data can be JSON or .NET object string format like:
                            # [SkuName=O365_BUSINESS_PREMIUM, AccountId=..., SkuId=f245ecc8-..., DisabledPlans=[]]
                            $ExtractSkuIds = {
                                param([string]$RawValue)
                                if ([string]::IsNullOrWhiteSpace($RawValue)) { return @() }

                                $SkuIds = [System.Collections.Generic.List[string]]::new()

                                # Try JSON parsing first
                                try {
                                    $Parsed = $RawValue | ConvertFrom-Json -ErrorAction Stop
                                    foreach ($Item in @($Parsed)) {
                                        $Id = $Item.SkuId ?? $Item.skuId
                                        if ($Id) { $SkuIds.Add($Id) }
                                    }
                                    if ($SkuIds.Count -gt 0) { return $SkuIds.ToArray() }
                                } catch { }

                                # Fall back to regex for .NET object string format
                                # Matches: SkuId=f245ecc8-75af-4f8e-b61f-27d8114de5f3
                                $RegexMatches = [regex]::Matches($RawValue, 'SkuId=([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})')
                                foreach ($Match in $RegexMatches) {
                                    if ($Match.Groups[1].Success) {
                                        $SkuIds.Add($Match.Groups[1].Value)
                                    }
                                }
                                return $SkuIds.ToArray()
                            }

                            $AddedSkuIds = & $ExtractSkuIds $Prop.newValue
                            $RemovedSkuIds = & $ExtractSkuIds $Prop.oldValue

                            # Resolve SKU GUIDs to friendly names
                            $AddedLicenses = @($AddedSkuIds.ForEach({
                                    Resolve-SkuName -SkuId $_ -SkuHashTable $SkuHashTable
                                }))
                            $RemovedLicenses = @($RemovedSkuIds.ForEach({
                                    Resolve-SkuName -SkuId $_ -SkuHashTable $SkuHashTable
                                }))
                        }
                    }

                    # Skip events with no actual license changes
                    if ($AddedLicenses.Count -eq 0 -and $RemovedLicenses.Count -eq 0) { continue }

                    $Changes.Add([PSCustomObject]@{
                            ActivityDate    = $AuditEvent.activityDateTime
                            UserPrincipal   = $TargetUser.userPrincipalName ?? $TargetUser.displayName ?? 'Unknown'
                            UserId          = $TargetUser.id
                            AddedLicenses   = $AddedLicenses
                            RemovedLicenses = $RemovedLicenses
                            InitiatedBy     = $InitiatedBy
                            CorrelationId   = $AuditEvent.correlationId
                            Result          = $AuditEvent.result
                        })
                }

                $Uri = $Response.'@odata.nextLink'
            } while ($Uri)

            $UserChangeCounts = $Changes | Group-Object -Property UserPrincipal | Sort-Object Count -Descending
            $MostChangedUsers = ($UserChangeCounts | Select-Object -First 10).ForEach({
                    [PSCustomObject]@{
                        UserPrincipalName = $_.Name
                        ChangeCount       = $_.Count
                    }
                })

            $Summary = [PSCustomObject]@{
                TenantId            = $TenantId
                ReportGeneratedDate = Get-Date
                DaysBack            = $DaysBack
                TotalChanges        = $Changes.Count
                UniqueUsersAffected = ($Changes.UserPrincipal | Select-Object -Unique).Count
                MostChangedUsers    = $MostChangedUsers
            }

            Write-Information "FINISHED : License change audit - $($Changes.Count) changes found." -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary = $Summary
                Changes = $Changes.ToArray()
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntLicenseChangeAuditReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntLicenseChangeAuditReportError',
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
