function Clear-SecureMemory {
    <#
    .SYNOPSIS
        Securely clears sensitive data from memory.

    .DESCRIPTION
        This security helper function provides centralized memory cleanup for sensitive data
        including tokens, credentials, and other security-sensitive objects. It ensures
        proper disposal of SecureString objects and clears connection parameters.

    .PARAMETER SecureStrings
        Array of SecureString objects to clear from memory.

    .PARAMETER Variables
        Array of variable names (strings) to clear from the current scope.

    .PARAMETER Objects
        Array of objects to clear and set to null.

    .PARAMETER Scope
        The scope to clear variables from. Valid values: Local, Script, Global.
        Defaults to Local.

    .EXAMPLE
        Clear-SecureMemory -SecureStrings @($SecureToken, $SecureSecret)

        Clears SecureString objects from memory.

    .EXAMPLE
        Clear-SecureMemory -Variables @('PlainTextToken', 'TempPassword') -Scope Local

        Clears specified variables from local scope.

    .EXAMPLE
        Clear-SecureMemory -Objects @($TokenObject, $CredentialObject)

        Clears object references.

    .OUTPUTS
        System.Management.Automation.PSObject
        Returns cleanup result with statistics and any issues encountered.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        SECURITY FEATURES:
        - Secure disposal of SecureString objects
        - Variable clearing across different scopes
        - Connection parameter cleanup

    .LINK
        https://systom.dev
    #>

    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter()]
        [SecureString[]]$SecureStrings = @(),

        [Parameter()]
        [string[]]$Variables = @(),

        [Parameter()]
        [ValidateSet('Local', 'Script', 'Global')]
        [string]$Scope = 'Local'
    )

    process {
        if ($SecureStrings.Count -gt 0) {
            foreach ($SecureString in $SecureStrings) {
                if ($null -ne $SecureString) {
                    try {
                        $SecureString.Dispose()
                    } catch {
                        Write-Verbose "Failed to dispose SecureString: $($_.Exception.Message)"
                    }
                }
            }
        }

        if ($Variables.Count -gt 0) {
            foreach ($VariableName in $Variables) {
                try {
                    if (Get-Variable -Name $VariableName -Scope $Scope -ErrorAction SilentlyContinue) {
                        $ScopeValue = Get-Variable -Name $VariableName -Scope $Scope -ValueOnly -ErrorAction SilentlyContinue

                        # Handle SecureString variables specifically
                        if ($ScopeValue -is [SecureString]) {
                            $ScopeValue.Dispose()
                        }

                        Remove-Variable -Name $VariableName -Scope $Scope -Force -ErrorAction Stop
                        Write-Verbose "Cleared $Scope variable: $VariableName"
                    }
                } catch {
                    Write-Verbose "Failed to clear variable '$VariableName' from $Scope scope: $($_.Exception.Message)"
                }
            }
        }

        # Clear any lingering connection-related variables from script scope
        $ConnectionVariables = @(
            'AccessToken',
            'GraphHeader',
            'TokenInfo',
            'SecureAccessToken',
            'GetSecureAuthHeader',
            'TokenCache',
            'ConnectionParams',
            'ClientSecret'
        )
        foreach ($ConnVar in $ConnectionVariables) {
            try {
                if (Get-Variable -Name $ConnVar -Scope Script -ErrorAction SilentlyContinue) {
                    $ScriptValue = Get-Variable -Name $ConnVar -Scope Script -ValueOnly -ErrorAction SilentlyContinue

                    # Handle SecureString variables specifically
                    if ($ScriptValue -is [SecureString]) {
                        $ScriptValue.Dispose()
                    }

                    Remove-Variable -Name $ConnVar -Scope Script -Force -ErrorAction Stop
                    Write-Verbose "Cleared script-level connection variable: $ConnVar"
                }
            } catch {
                Write-Verbose "Could not clear script-level variable '$ConnVar': $($_.Exception.Message)"
            }
        }
    }
}
