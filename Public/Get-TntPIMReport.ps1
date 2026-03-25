function Get-TntPIMReport {
    <#
    .SYNOPSIS
        Generates a PIM (Privileged Identity Management) report for Azure AD roles.

    .DESCRIPTION
        This function analyzes PIM eligible and active role assignments, providing insights into
        PIM adoption, coverage, and activation patterns. This function REQUIRES an Azure AD Premium P2
        license to access PIM data.

        For permanent role assignments and emergency accounts (no P2 required), use Get-TntPrivilegedRoleReport.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .EXAMPLE
        Get-TntPIMReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Generates a PIM report for eligible and active role assignments.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a PIM report object with:
        - Summary: Statistics on PIM usage
        - PIMEligibleAssignments: Detailed list of eligible role assignments
        - PIMActiveAssignments: Detailed list of currently active PIM assignments
        - AssignmentsByRole: Grouped statistics per role

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - RoleManagement.Read.Directory (Application)
        - Directory.Read.All (Application)

        Prerequisites:
        - **Azure AD Premium P2 license REQUIRED** for PIM capabilities
        - Security Reader, Global Reader, or equivalent role to query PIM assignments

    .LINK
        https://github.com/systommy/TenantReports
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

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Secret', 'ApplicationSecret')]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    begin {
        Write-Information 'STARTED  : PIM report generation...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo   = Connect-TntGraphSession @ConnectionParams

            # Initialize collections
            $PIMEligibleAssignments = [System.Collections.Generic.List[PSObject]]::new()
            $PIMActiveAssignments   = [System.Collections.Generic.List[PSObject]]::new()

            # Get all role definitions to identify privileged roles
            Write-Verbose 'Retrieving role definitions...'
            $RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop

            # Client-side filtering required: Graph API does not support filtering by DisplayName array or IsBuiltIn property
            $PrivilegedRoles = @($RoleDefinitions.Where({
                    $_.DisplayName -in $script:PrivilegedRoleNames -or $_.IsBuiltIn -eq $false
                }))

            $PrivilegedRoleLookup = @{}
            foreach ($PrivilegedRole in $PrivilegedRoles) {
                $PrivilegedRoleLookup[$PrivilegedRole.Id] = $PrivilegedRole
            }

            Write-Verbose "Identified $($PrivilegedRoles.Count) privileged roles"

            # Get PIM eligible assignments
            Write-Verbose 'Retrieving PIM eligible assignments...'
            try {
                $EligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal -ErrorAction Stop

                foreach ($Schedule in $EligibleSchedules) {
                    $Role = $PrivilegedRoleLookup[$Schedule.RoleDefinitionId]
                    if ($Role) {
                        $Assignment = ConvertTo-PIMAssignment -Schedule $Schedule -Role $Role -AssignmentType 'PIM Eligible'
                        $PIMEligibleAssignments.Add($Assignment)
                    }
                }
            } catch {
                # Check if error is due to missing P2 license or permissions
                if ($_.Exception.Message -match 'Forbidden|Unauthorized|Premium|P2') {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('Get-TntPIMReport failed: This feature requires Azure AD Premium P2 license.', $_.Exception),
                        'GetPIMReportLicenseError',
                        [System.Management.Automation.ErrorCategory]::InvalidOperation,
                        $TenantId
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                } else {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-TntPIMReport failed retrieving eligible assignments: $($_.Exception.Message)", $_.Exception),
                        'GetPIMReportEligibleError',
                        [System.Management.Automation.ErrorCategory]::OperationStopped,
                        $TenantId
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }

            # Get PIM active assignments
            Write-Verbose 'Retrieving PIM active assignments...'
            try {
                $ActiveSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty Principal -ErrorAction Stop

                foreach ($Schedule in $ActiveSchedules) {
                    $Role = $PrivilegedRoleLookup[$Schedule.RoleDefinitionId]
                    if ($Role) {
                        $Assignment = ConvertTo-PIMAssignment -Schedule $Schedule -Role $Role -AssignmentType 'PIM Active'
                        $PIMActiveAssignments.Add($Assignment)
                    }
                }
            } catch {
                # Check if error is due to missing P2 license or permissions
                if ($_.Exception.Message -match 'Forbidden|Unauthorized|Premium|P2') {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('Get-TntPIMReport failed: This feature requires Azure AD Premium P2 license.', $_.Exception),
                        'GetPIMReportLicenseError',
                        [System.Management.Automation.ErrorCategory]::InvalidOperation,
                        $TenantId
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                } else {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-TntPIMReport failed retrieving active assignments: $($_.Exception.Message)", $_.Exception),
                        'GetPIMReportActiveError',
                        [System.Management.Automation.ErrorCategory]::OperationStopped,
                        $TenantId
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }

            $TotalPIMAssignments = $PIMEligibleAssignments.Count + $PIMActiveAssignments.Count
            $UniqueEligibleUsers = ($PIMEligibleAssignments.Where({ $_.PrincipalType -eq 'user' }) | Select-Object PrincipalId -Unique).Count

            $Summary = [PSCustomObject]@{
                TenantId                     = $TenantId
                ReportGeneratedDate          = Get-Date
                TotalPIMAssignments          = $TotalPIMAssignments
                PIMEligibleAssignments       = $PIMEligibleAssignments.Count
                PIMActiveAssignments         = $PIMActiveAssignments.Count
                UniqueEligibleUsers          = $UniqueEligibleUsers
                EligibleGlobalAdministrators = $PIMEligibleAssignments.Where({ $_.RoleName -eq 'Global Administrator' }).Count
                ActiveGlobalAdministrators   = $PIMActiveAssignments.Where({ $_.RoleName -eq 'Global Administrator' }).Count
            }

            Write-Information "FINISHED : PIM report - $($TotalPIMAssignments) total assignments ($($PIMEligibleAssignments.Count) eligible, $($PIMActiveAssignments.Count) active)" -InformationAction Continue

            [PSCustomObject]@{
                Summary                = $Summary
                PIMEligibleAssignments = $PIMEligibleAssignments | Sort-Object RoleName, PrincipalName
                PIMActiveAssignments   = $PIMActiveAssignments | Sort-Object ExpirationDateTime, RoleName
                AssignmentsByRole      = (($PIMEligibleAssignments + $PIMActiveAssignments) | Group-Object RoleName).ForEach({
                        [PSCustomObject]@{
                            RoleName      = $_.Name
                            EligibleCount = @($_.Group.Where({ $_.AssignmentType -eq 'PIM Eligible' })).Count
                            ActiveCount   = @($_.Group.Where({ $_.AssignmentType -eq 'PIM Active' })).Count
                        }
                    }) | Sort-Object { $_.EligibleCount + $_.ActiveCount } -Descending
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntPIMReport failed: $($_.Exception.Message)", $_.Exception),
                'GetPIMReportError',
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
