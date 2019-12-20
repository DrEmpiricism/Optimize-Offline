Function Get-ErrorRecord
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param ()

    $Index = 0
    $Error | ForEach-Object -Process {
        [PSCustomObject]@{
            Index     = $Index
            Exception = $PSItem.Exception.Message
            Category  = $PSItem.CategoryInfo.ToString()
            ErrorID   = $PSItem.FullyQualifiedErrorId
            Target    = $PSItem.TargetObject
            Command   = $PSItem.InvocationInfo.Line.Trim()
            Script    = $PSItem.InvocationInfo.ScriptName
            Line      = $PSItem.InvocationInfo.ScriptLineNumber
            Column    = $PSItem.InvocationInfo.OffsetInLine
        }
        $Index++
    }
}