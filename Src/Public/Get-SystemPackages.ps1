Function Get-SystemPackages {
	
	$RegKeyPath = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"

	RegHives -Load

	If (!(Test-Path -Path $RegKeyPath)) {
		return @()
	}

	$InboxAppsPackages = Get-ChildItem -Path $RegKeyPath -Name | ForEach-Object -Process {
		$DisplayName = $PSItem.Split('_')[0]; $PackageName = $PSItem
		If ($DisplayName -like '1527c705-839a-4832-9118-54d4Bd6a0c89') { $DisplayName = 'Microsoft.Windows.FilePicker' }
		If ($DisplayName -like 'c5e2524a-ea46-4f67-841f-6a9465d9d515') { $DisplayName = 'Microsoft.Windows.FileExplorer' }
		If ($DisplayName -like 'E2A4F912-2574-4A75-9BB0-0D023378592B') { $DisplayName = 'Microsoft.Windows.AppResolverUX' }
		If ($DisplayName -like 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE') { $DisplayName = 'Microsoft.Windows.AddSuggestedFoldersToLibarayDialog' }
		[PSCustomObject]@{ DisplayName = $DisplayName; PackageName = $PackageName }
	} | Sort-Object -Property DisplayName

	RegHives -Unload

	return $InboxAppsPackages
}