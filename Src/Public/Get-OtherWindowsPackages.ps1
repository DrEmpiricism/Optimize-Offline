Function Get-OtherWindowsPackages {

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


	return Get-WindowsPackage -Path $Path -ScratchDirectory $ScratchDirectory -LogPath $LogPath -LogLevel 1 | Where-Object { $PSItem.ReleaseType -eq 'OnDemandPack' -or $PSItem.ReleaseType -eq 'LanguagePack' -or $PSItem.ReleaseType -eq 'FeaturePack' -and $PSItem.PackageName -notlike "*20H2Enablement*" -and $PSItem.PackageName -notlike "*LanguageFeatures-Basic*" -and $PSItem.PackageName -notlike "*LanguageFeatures-TextToSpeech*" -and $PSItem.PackageState -eq 'Installed' } | Select-Object -Property PackageName, ReleaseType | Sort-Object -Property PackageName
}