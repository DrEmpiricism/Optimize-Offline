RegHives -Load
If($SelectiveRegistry.DisableWindowsUpgrade) {

	$TargetReleaseVersionInfo = $null

	Switch ($Global:InstallInfo.Build) {
		"17134" { $TargetReleaseVersionInfo = "1803" }
		"17763" { $TargetReleaseVersionInfo = "1809" }
		"18362" { $TargetReleaseVersionInfo = "1903" }
		"18363" { $TargetReleaseVersionInfo = "1909" }
		"19041" { $TargetReleaseVersionInfo = "2004" }
		"19042" { $TargetReleaseVersionInfo = "2009" }
		"19043" { $TargetReleaseVersionInfo = "21H1" }
	}

	If ($Global:InstallInfo.Build -ge "19044") {
		$TargetReleaseVersionInfo = "21H2"
	}

	If ($Global:InstallInfo.Build -ge "22500") {
		$TargetReleaseVersionInfo = "22H2"
	}

	If ($TargetReleaseVersionInfo){

		Log $OptimizeData.SelectiveRegistryWindowsUpgrade

		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value "2"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value "1"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferUpdatePeriod" -Type DWord -Value "1"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferUpgrade" -Type DWord -Value "1"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferUpgradePeriod" -Type DWord -Value "1"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Type DWord -Value "1"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Type String -Value $TargetReleaseVersionInfo

		If ($Global:InstallInfo.Build -ge "17134" -and $Global:InstallInfo.Build -le "20348") { RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ProductVersion" -Type String -Value "Windows 10" }

		If ($Global:InstallInfo.Build -ge "22000") { RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ProductVersion" -Type String -Value "Windows 11" }
		
	}
	Start-Sleep 1
}
If($SelectiveRegistry.DisableWindowsUpdateMicrosoft) {
	Log $OptimizeData.SelectiveRegistryWindowsUpdateMS
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Type DWord -Value "1"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Type DWord -Value "1"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Type String -Value " "
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Type String -Value " "
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateServiceUrlAlternate" -Type String -Value " "
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Type DWord -Value "1"
	Start-Sleep 1
}

If($SelectiveRegistry.DisableDriverUpdate) {
	Log $OptimizeData.SelectiveRegistryDriverUpdate
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value "1"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value "1"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value "1"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value "0" 
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value "1"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value "1"
	Start-Sleep 1
}

If($SelectiveRegistry.DormantOneDrive) {
	Log $OptimizeData.SelectiveRegistryDormantOneDrive
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Type DWord -Value "0"
	Start-Sleep 1
}

# classic search in explorer
If($SelectiveRegistry.ClassicSearchExplorer -and $Global:InstallInfo.Build -ge '18363') {

	Log $OptimizeData.SelectiveRegistryClassicSearchExplorer

	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" -Name "(default)" -Value "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" -Type String -Force

	Start-Sleep 1
}

If($SelectiveRegistry.RemoveTaskbarPinnedIcons){

	Log $OptimizeData.SelectiveRegistryRemoveTaskbarPinnedIcons

	## Disable taskbar taskview button
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type Dword -Value "0" -Force
	
	If($Global:InstallInfo.Build -ge '18362') {
		#Hide MeetNow icon in taskbar
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type dword -Value "1"
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type dword -Value "1"
	}

	if($Global:InstallInfo.Build -le '19044'){
		RegKey -Path "HKLM:\WIM_HKCU\Software\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord
	}

	# Disable News & Interests icon
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type dword -Value "2"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type dword -Value "0"

	If($Global:InstallInfo.Build -ge '22000') {
		#Remove Chat icon in taskbar
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Name "ChatIcon" -Type dword -Value "3"
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type dword -Value "0"

		## Disable widgets button
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type Dword -Value "0" -Force
	}

	Start-Sleep 1

}

If($SelectiveRegistry.W11ClassicContextMenu -and $Global:InstallInfo.Build -ge '22000') {
	Log $OptimizeData.SelectiveRegistryW11ClassicContextMenu
	# Classic context menus
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Type String -Force
	Start-Sleep 1
}

if($SelectiveRegistry.DisableTeamsApp -and $Global:InstallInfo.Build -ge '10240') {
	Log $OptimizeData.SelectiveRegistryDisableTeamsApp
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -Name "ConfigureChatAutoInstall" -Value "0" -Type DWord -Force
	Start-Sleep 1
}

if($SelectiveRegistry.DisableVirtualizationSecurity -and $Global:InstallInfo.Build -ge '22000') {
	Log $OptimizeData.SelectiveRegistryDisableVirtualizationSecurity
	RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -Value "0" -Type DWord -Force
	RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "0" -Type DWord -Force
	Start-Sleep 1
}



if ($SelectiveRegistry.ExplorerUIRibbon) {
	if ($Global:InstallInfo.Build -le "19044"){
		Log $OptimizeData.SelectiveRegistryExplorerUIRibbon
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" -Value "" -Type String -Force
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" -Value "" -Type String -Force
		Start-Sleep 1
	} elseif ($Global:InstallInfo.Build -eq "22000") {
		Log $OptimizeData.SelectiveRegistryExplorerUIRibbon
		# RegKey -Path "HKLM:\WIM_HKCU\Software\Classes\CLSID\{d93ed569-3b3e-4bff-8355-3c44f6a52bb5}\InprocServer32" -Name "(default)" -Value "" -Type String -Force
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{d93ed569-3b3e-4bff-8355-3c44f6a52bb5}\InprocServer32" -Name "(default)" -Value "" -Type String -Force
		Start-Sleep 1
	}
}

RegHives -Unload

if($SelectiveRegistry.AmoledBlackTheme -and $Global:InstallInfo.Build -ge '10240') {
	Log $OptimizeData.SelectiveRegistryAmoledBlackTheme
	Import-Registry -Path (Get-ChildItem -Path $OptimizeOffline.SelectiveRegistry -Filter AMOLED_black_theme.reg).FullName
	Start-Sleep 1
}

if($SelectiveRegistry.RunAsTiContextMenu){
	Log $OptimizeData.SelectiveRegistryRunAsTiContextMenu
	Import-Registry -Path (Get-ChildItem -Path $OptimizeOffline.SelectiveRegistry -Filter RunAsTi.reg).FullName
	Start-Sleep 1
}

Clear-Host
