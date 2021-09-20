Function Get-CapabilityPackages {

	[CmdletBinding()]

	Param (
		[Parameter(Mandatory = $true,
			HelpMessage = 'full path to the root directory of the offline Windows image that you will service.')]
		[String]$Path,
		[Parameter(Mandatory = $false,
			HelpMessage = 'Specifies a temporary directory that will be used when extracting files for use during servicing. The directory must exist locally. If not specified, the \Windows\%Temp% directory will be used')]
		[String]$ScratchDirectory,
		[Parameter(Mandatory = $false,
			HelpMessage = 'the full path and file name to log to. If not set, the default is %WINDIR%\Logs\Dism\dism.log')]
		[String]$LogPath
	)

	$WindowsCapabilities = Get-WindowsCapability -Path $Path -ScratchDirectory $ScratchDirectory -LogPath $LogPath -LogLevel 1 | Where-Object { $PSItem.Name -notlike "*Language.Basic*" -and $PSItem.Name -notlike "*TextToSpeech*" -and $PSItem.State -eq 'Installed' } | Select-Object -Property Name, State | Sort-Object -Property Name

	return $WindowsCapabilities

}