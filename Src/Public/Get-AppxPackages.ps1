Function Get-AppxPackages {

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

	If($Global:InstallInfo.InstallationType.ToLower().Contains('server core')) {
		return @{}
	}

	$AppxPackages = Get-AppxProvisionedPackage -Path $Path -ScratchDirectory $ScratchDirectory -LogPath $LogPath -LogLevel 1 | Select-Object -Property DisplayName, PackageName | Sort-Object -Property DisplayName

	If ($Global:InstallInfo.Build -ge '19041')
	{
		$AppxPackages = $AppxPackages | ForEach-Object -Process {
			$DisplayName = $PSItem.DisplayName; $PackageName = $PSItem.PackageName
			If ($DisplayName -eq 'Microsoft.549981C3F5F10') { $DisplayName = 'CortanaApp.View.App' }
			[PSCustomObject]@{ DisplayName = $DisplayName; PackageName = $PackageName }
		}
	}

	return $AppxPackages
}