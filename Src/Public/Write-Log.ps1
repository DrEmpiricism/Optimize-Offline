Function Write-Log
{
	[CmdletBinding(DefaultParameterSetName = 'Info')]
	Param
	(
		[Parameter(ParameterSetName = 'Info')]
		[String]$Info,
		[Parameter(ParameterSetName = 'Error')]
		[String]$Error,
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
		[IO.FileInfo]$ModuleLog = $ModuleLog
		$Timestamp = (Get-Date -Format 's')
		$LogMutex = New-Object System.Threading.Mutex($false, "LogMutex")
		[Void]$LogMutex.WaitOne()
	}
	Process
	{
		If (!$ModuleLog.Exists)
		{
			$ModuleLog = New-Item -Path $ModuleLog -ItemType File -Force
			@"
***************************************************************************************************
Running Module : $($ManifestData.ModuleName) $($ManifestData.ModuleVersion)
Optimize Start : $(Get-Date -UFormat "%m/%d/%Y %r")
Identity Name  : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Computer Name  : $Env:COMPUTERNAME
***************************************************************************************************

"@ | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Force
		}
		Switch ($PSBoundParameters.Keys)
		{
			'Info'
			{
				"$Timestamp [INFO]: $Info" | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				$Host.UI.RawUI.WindowTitle = $Info
				Write-Host $Info -ForegroundColor Cyan
			}
			'Error'
			{
				"$Timestamp [ERROR]: $Error" | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				$Host.UI.RawUI.WindowTitle = $Error
				Write-Host $Error -ForegroundColor Red
			}
			'Finalized'
			{
				@"

***************************************************************************************************
Optimizations Finalized : $(Get-Date -UFormat "%m/%d/%Y %r")
***************************************************************************************************
"@ | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				$Host.UI.RawUI.WindowTitle = "Optimizations Completed."
			}
			'Failed'
			{
				@"

***************************************************************************************************
Optimizations Failed : $(Get-Date -UFormat "%m/%d/%Y %r")
***************************************************************************************************
"@ | Out-File -FilePath $ModuleLog.FullName -Encoding UTF8 -Append -Force
				$Host.UI.RawUI.WindowTitle = "Optimizations Failed."
			}
		}
	}
	End
	{
		[Void]$LogMutex.ReleaseMutex()
	}
}