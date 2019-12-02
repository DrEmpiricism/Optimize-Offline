Function Format-ErrorRecord
{
    [Management.Automation.ErrorRecord]$ErrorRecord = $Error[0]
    $FormattedError = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message, $ErrorRecord.FullyQualifiedErrorId, $ErrorRecord.InvocationInfo.ScriptName, $ErrorRecord.InvocationInfo.ScriptLineNumber, $ErrorRecord.InvocationInfo.OffsetInLine
    $FormattedError | Out-File -FilePath $ErrorRecordLog -Append -Encoding UTF8 -Force
    $FormattedError
}