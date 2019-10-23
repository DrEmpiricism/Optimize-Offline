Function Write-Log
{
	[CmdletBinding(DefaultParameterSetName = 'Info')]
	Param
	(
		[Parameter(ParameterSetName = 'Info')]
		[String]$Info,
		[Parameter(ParameterSetName = 'Error')]
		[Parameter(ParameterSetName = 'Failed')]
		[String]$Error,
		[Parameter(ParameterSetName = 'Error',
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[Parameter(ParameterSetName = 'Failed')]
		[Management.Automation.ErrorRecord]$ErrorRecord,
		[Parameter(ParameterSetName = 'Info')]
		[Parameter(ParameterSetName = 'Finalized')]
		[Switch]$Finalized,
		[Parameter(ParameterSetName = 'Info')]
		[Parameter(ParameterSetName = 'Error')]
		[Parameter(ParameterSetName = 'Failed')]
		[Switch]$Failed
	)

	Begin
	{
		$Timestamp = (Get-Date -Format 's')
		$LogMutex = New-Object System.Threading.Mutex($false, "SyncLogMutex")
		[Void]$LogMutex.WaitOne()
	}
	Process
	{
		If (!(Test-Path -Path $ScriptLog))
		{
			@"
***************************************************************************************************

$($ScriptInfo.Name) v$($ScriptInfo.Version) starting on [$(Get-Date -UFormat "%m/%d/%Y at %r")]

***************************************************************************************************
Optimizing image: $($InstallWimInfo.Name)
***************************************************************************************************

"@ | Out-File -FilePath $ScriptLog -Encoding UTF8
		}
		Switch ($PSBoundParameters.Keys)
		{
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
			'Finalized'
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
		}
	}
	End
	{
		[Void]$LogMutex.ReleaseMutex()
	}
}