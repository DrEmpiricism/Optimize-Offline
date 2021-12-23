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
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value "1"
	Start-Sleep 1
}

If($SelectiveRegistry.DormantOneDrive) {
	Log $OptimizeData.SelectiveRegistryDormantOneDrive
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Type DWord -Value "0"
	Start-Sleep 1
}

If ($SelectiveRegistry.Disable3rdPartyApps) {

	Log $OptimizeData.SelectiveRegistryDisable3rdPartyApps

	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type Dword -Value "0"
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type Dword -Value "0"
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type Dword -Value "0"
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type Dword -Value "1"

	If ($Global:InstallInfo.Build -ge "22000") {
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "ConfigureStartPins" -Type String -Value '{"pinnedList": [{}]}'
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "ConfigureStartPins_ProviderSet" -Type Dword -Value "0"
	}
	Start-Sleep 1
}

RegHives -Unload

Clear-Host
