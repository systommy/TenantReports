function Get-SkuTranslationTable {
    <#
    .SYNOPSIS
        Lazy-loads and caches the SKU translation table from CSV.
    .NOTES
        Internal helper for TenantReports. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    if (-not $script:SkuTranslationTable -or $script:SkuTranslationTable.Count -eq 0) {
        try {
            $CsvPath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'src' | Join-Path -ChildPath 'SKUTranslationTable.csv'
            $CsvPath = [System.IO.Path]::GetFullPath($CsvPath)
            $script:SkuTranslationTable = Import-Csv -Path $CsvPath
            Write-Verbose "SKU translation table loaded ($($script:SkuTranslationTable.Count) entries)"
        } catch {
            Write-Warning "Failed to load SKU translation table: $($_.Exception.Message)"
            $script:SkuTranslationTable = @()
        }
    }

    return $script:SkuTranslationTable
}
