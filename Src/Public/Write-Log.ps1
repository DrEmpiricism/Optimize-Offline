Function Write-Log
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	Param
	(
		[Parameter(Mandatory = $true,
			Position = 0)]
		[String]$Message,
		[ValidateSet('Info', 'Error')]
		[String]$Type = 'Info',
		[Management.Automation.ErrorRecord]$ErrorRecord,
		[Parameter(ParameterSetName = 'Finalized')]
		[Switch]$Finalized,
		[Parameter(ParameterSetName = 'Failed')]
		[Switch]$Failed,
		[Switch]$Quiet
	)

	Begin
	{
		[IO.FileInfo]$ModuleLog = $ModuleLog
		$Timestamp = (Get-Date -Format 's')
		$LogMutex = New-Object System.Threading.Mutex($false, "LogMutex")
		$Header = @"
***************************************************************************************************
Running Module : $($OptimizeOffline.BaseName) $($ManifestData.ModuleVersion) $($ManifestData.ModuleForkVersion)
Optimize Start : {0}
Identity Name  : $([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1])
Computer Name  : $Env:COMPUTERNAME
***************************************************************************************************

"@
		$Footer = @"

***************************************************************************************************
Optimizations Finalized : {0}
***************************************************************************************************
"@
		[Void]$LogMutex.WaitOne()
	}
	Process
	{
		If (!$ModuleLog.Exists)
		{
			$ModuleLog = New-Item -Path $ModuleLog -ItemType File -Force
			$Header -f $(Get-Date -UFormat "%m/%d/%Y %r") | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Force
		}
		Switch ($PSBoundParameters.Type)
		{
			'Error'
			{
				"$Timestamp [ERROR]: $Message" | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				If (!$Quiet.IsPresent) { $Host.UI.RawUI.WindowTitle = $Message; Write-Host $Message -ForegroundColor Red }
				If ($PSBoundParameters.ContainsKey('ErrorRecord') -and $null -ne $ErrorRecord)
				{
					$OptimizeErrors.Add($ErrorRecord)
					$ExceptionMessage = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message, $ErrorRecord.CategoryInfo.ToString(), $ErrorRecord.InvocationInfo.ScriptName, $ErrorRecord.InvocationInfo.ScriptLineNumber, $ErrorRecord.InvocationInfo.OffsetInLine
					"$Timestamp [ERROR]: $ExceptionMessage" | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
					If (!$Quiet.IsPresent) { Write-Host $ExceptionMessage -ForegroundColor Red }
				}
				Break
			}
			Default
			{
				"$Timestamp [INFO]: $Message" | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				If (!$Quiet.IsPresent) { $Host.UI.RawUI.WindowTitle = $Message; Write-Host $Message -ForegroundColor Cyan }
				Break
			}
		}
		Switch ($PSCmdlet.ParameterSetName)
		{
			'Finalized'
			{
				$Footer -f $(Get-Date -UFormat "%m/%d/%Y %r") | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				$Host.UI.RawUI.WindowTitle = "Optimizations Completed."
				Break
			}
			'Failed'
			{
				$Footer.Replace('Optimizations Finalized : {0}', 'Optimizations Failed : {0}') -f $(Get-Date -UFormat "%m/%d/%Y %r") | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				$Host.UI.RawUI.WindowTitle = "Optimizations Failed."
				Break
			}
		}
	}
	End
	{
		[Void]$LogMutex.ReleaseMutex()
	}
}