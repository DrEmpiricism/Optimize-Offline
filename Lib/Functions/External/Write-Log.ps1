Function Write-Log
{
    [CmdletBinding(DefaultParameterSetName = 'Info')]
    Param
    (
        [Parameter(ParameterSetName = 'Info')]
        [string]$Info,
        [Parameter(ParameterSetName = 'Error')]
        [string]$Error,
        [Parameter(ParameterSetName = 'Error',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(ParameterSetName = 'Header')]
        [switch]$Header,
        [Parameter(ParameterSetName = 'Footer')]
        [switch]$Footer,
        [Parameter(ParameterSetName = 'Failed')]
        [switch]$Failed
    )

    Begin
    {
        $Timestamp = (Get-Date -Format 's')
        $LogMutex = New-Object System.Threading.Mutex($false, "SyncLogMutex")
        [void]$LogMutex.WaitOne()
    }
    Process
    {
        Switch ($PSBoundParameters.Keys)
        {
            'Header'
            {
                @"
***************************************************************************************************

$($ScriptInfo.Name) v$($ScriptInfo.Version) starting on [$(Get-Date -UFormat "%m/%d/%Y at %r")]

***************************************************************************************************
Optimizing image: $($InstallWimInfo.Name)
***************************************************************************************************

"@ | Out-File -FilePath $ScriptLog -Encoding UTF8
            }
            'Footer'
            {
                @"

***************************************************************************************************
Optimizations finalized on [$(Get-Date -UFormat "%m/%d/%Y at %r")]
***************************************************************************************************
"@ | Out-File -FilePath $ScriptLog -Encoding UTF8 -Append
            }
            'Failed'
            {
                @"

***************************************************************************************************
Optimizations failed on [$(Get-Date -UFormat "%m/%d/%Y at %r")]
***************************************************************************************************
"@ | Out-File -FilePath $ScriptLog -Encoding UTF8 -Append
            }
            'Info'
            {
                "$Timestamp [INFO]: $Info" | Out-File -FilePath $ScriptLog -Encoding UTF8 -Append
                Write-Host $Info -ForegroundColor Cyan
            }
            'Error'
            {
                "$Timestamp [ERROR]: $Error" | Out-File -FilePath $ScriptLog -Encoding UTF8 -Append
                Write-Host $Error -ForegroundColor Red
                If ($PSBoundParameters.ContainsKey('ErrorRecord'))
                {
                    $ExceptionMessage = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
                    $ErrorRecord.FullyQualifiedErrorId,
                    $ErrorRecord.InvocationInfo.ScriptName,
                    $ErrorRecord.InvocationInfo.ScriptLineNumber,
                    $ErrorRecord.InvocationInfo.OffsetInLine
                    "$Timestamp [ERROR]: $ExceptionMessage" | Out-File -FilePath $ScriptLog -Encoding UTF8 -Append
                    Write-Host $ExceptionMessage -ForegroundColor Red
                }
            }
        }
    }
    End
    {
        [void]$LogMutex.ReleaseMutex()
    }
}