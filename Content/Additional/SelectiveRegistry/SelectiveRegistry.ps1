RegHives -Load
if($SelectiveRegistry.DisableWindowsUpdate -eq $true) {
	Log $OptimizeData.SelectiveRegistryWindowsUpdate
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "OptInOOBE" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Name "AutoDownload" -Type DWord -Value 2
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" -Name "RegisteredWithAU" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUpdateAgent/Operational" -Name "Enabled" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Operational" -Name "Enabled" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "HideMCTLink" -Type DWord -Value 1
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
	# https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#29-windows-update	
# Add a REG_DWORD value named DoNotConnectToWindowsUpdateInternetLocations to 
# HKEY_LOCAL_MACHINE        \Software\Policies\Microsoft\Windows\WindowsUpdate        and set the value to 1.        
RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Type DWord -Value 1
#-and-

#Add a REG_DWORD value named DisableWindowsUpdateAccess to 
#HKEY_LOCAL_MACHINE          \Software\Policies\Microsoft\Windows\WindowsUpdate        and set the value to 1.
RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Type DWord -Value 1
#-and-

#Add a REG_SZ value named WUServer to 
# HKEY_LOCAL_MACHINE        \Software\Policies\Microsoft\Windows\WindowsUpdate         and ensure it is blank with a space character " ".
RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Type String -Value " "
#-and-

#Add a REG_SZ value named WUStatusServer to 
# HKEY_LOCAL_MACHINE        \Software\Policies\Microsoft\Windows\WindowsUpdate and ensure it is blank with a space character " ".
RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Type String -Value " "
#-and-

#Add a REG_SZ value named UpdateServiceUrlAlternate to 
#HKEY_LOCAL_MACHINE         \Software\Policies\Microsoft\Windows\WindowsUpdate and ensure it is blank with a space character " ".
RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateServiceUrlAlternate" -Type String -Value " "
#-and-

#Add a REG_DWORD value named UseWUServer to 
#HKEY_LOCAL_MACHINE         \Software\Policies\Microsoft\Windows\WindowsUpdate\AU and set the value to 1 (one).
RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Type DWord -Value 1
Start-Sleep 1
}

if($SelectiveRegistry.DisableDriverUpdate -eq $true) {
	Log $OptimizeData.SelectiveRegistryDriverUpdate
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1 
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0 
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
	Start-Sleep 1
}

if($SelectiveRegistry.DormantOneDrive -eq $true) {
	Log $OptimizeData.SelectiveRegistryDormantOneDrive
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Type DWord -Value 0
	Start-Sleep 1
}

if($SelectiveRegistry.DisableWindowsUpdate -and $SelectiveRegistry.DisableDriverUpdate) {
	RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\wuauserv" -Name "Start" -Type DWord -Value 4
}

RegHives -Unload

Clear-Host
