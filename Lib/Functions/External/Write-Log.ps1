Function Write-Log
{
	[CmdletBinding(DefaultParameterSetName = 'Info')]
	Param
	(
		[Parameter(ParameterSetName = 'Info')]
		[String]$Info,
		[Parameter(ParameterSetName = 'Error')]
		[String]$Error,
		[Parameter(ParameterSetName = 'Error',
			ValueFromPipeline = $true,
			ValueFromPipelineByPropertyName = $true)]
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
		[IO.FileInfo]$ScriptLog = $ScriptLog
		$Timestamp = (Get-Date -Format 's')
		$LogMutex = New-Object System.Threading.Mutex($false, "LogMutex")
	}
	Process
	{
		If (!$ScriptLog.Exists)
		{
			$ScriptLog = New-Item -Path $ScriptLog -ItemType File -Force
			@"
***************************************************************************************************
Running Script : $($ScriptInfo.Name) $($ScriptInfo.Version)
Optimize Start : $(Get-Date -UFormat "%m/%d/%Y %r")
Identity Name : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Computer Name : $Env:COMPUTERNAME
***************************************************************************************************

"@ | Out-File -FilePath $ScriptLog.FullName -Encoding UTF8 -Force
		}
		Switch ($PSBoundParameters.Keys)
		{
			'Info'
			{
				[Void]$LogMutex.WaitOne()
				"$Timestamp [INFO]: $Info" | Out-File -FilePath $ScriptLog.FullName -Encoding UTF8 -Append
				Write-Host $Info -ForegroundColor Cyan
				[Void]$LogMutex.ReleaseMutex()
			}
			'Error'
			{
				[Void]$LogMutex.WaitOne()
				"$Timestamp [ERROR]: $Error" | Out-File -FilePath $ScriptLog.FullName -Encoding UTF8 -Append
				Write-Host $Error -ForegroundColor Red
				If ($PSBoundParameters.ContainsKey('ErrorRecord'))
				{
					$ExceptionMessage = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
					$ErrorRecord.FullyQualifiedErrorId,
					$ErrorRecord.InvocationInfo.ScriptName,
					$ErrorRecord.InvocationInfo.ScriptLineNumber,
					$ErrorRecord.InvocationInfo.OffsetInLine
					"$Timestamp [ERROR]: $ExceptionMessage" | Out-File -FilePath $ScriptLog.FullName -Encoding UTF8 -Append
					Write-Host $ExceptionMessage -ForegroundColor Red
				}
				[Void]$LogMutex.ReleaseMutex()
			}
			'Finalized'
			{
				@"

***************************************************************************************************
Optimizations finalized : $(Get-Date -UFormat "%m/%d/%Y %r")
***************************************************************************************************
"@ | Out-File -FilePath $ScriptLog.FullName -Encoding UTF8 -Append
			}
			'Failed'
			{
				@"

***************************************************************************************************
Optimizations failed : $(Get-Date -UFormat "%m/%d/%Y %r")
***************************************************************************************************
"@ | Out-File -FilePath $ScriptLog.FullName -Encoding UTF8 -Append
			}
		}
	}
}