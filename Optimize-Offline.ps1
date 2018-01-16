#Requires -RunAsAdministrator
#Requires -Version 5
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 Creator's Update builds RS2 and RS3.
	
	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, privacy and security enhancements, cleaner aesthetics, increased performance and a significantly better user experience.
		Does not perform any changes to an installed or live system nor can it optimize a live system.
		Makes multiple changes to both the offline system and registry hives to enhance security, usability and privacy while also improving performance.
		Generates installation scripts (OOBE and SetupComplete) to accommodate offline changes.
		Checks the health of the image both before and after the script runs to ensure the image retains a healthy status.
		Detects what System Applications were removed, and further removes any associated drivers or services associated with them.
		Adds removed System Applications' scheduled tasks to the SetupComplete script to be automatically disabled during Windows installation.
		Optional Features and Windows Packages can be removed and/or disabled by adding them to the editable field list and using their respective switches.
		It is up to the end-user to be aware of all changes made prior to running this script.
	
	.PARAMETER ImagePath
		The path to a Windows Installation ISO or an Install.WIM.
	
	.PARAMETER Index
		If using a multi-index image, specify the index of the image.
	
	.PARAMETER Build
		The build number of the image.
	
	.PARAMETER SelectApps
		Prompts the user to determine whether or not a Provisioning Application Package is removed or skipped.
	
	.PARAMETER AllApps
		Automatically removes all Provisioning Application Packages.
	
	.PARAMETER UseWhiteList
		Automatically removes all Provisioning Application Packages not included in the WhiteList.
	
	.PARAMETER SystemApps
		Removes the provisioning and installation of System Applications.
	
	.PARAMETER OptimizeRegistry
		Adds optimized entries and values to the image registry hives.
	
	.PARAMETER DisableFeatures
		Disables all Windows Optional Features included in the DisableList.
	
	.PARAMETER RemovePackages
		Removes all Windows Packages included in the RemovalList.
	
	.PARAMETER AddDrivers
		A resolvable path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.PARAMETER AddFeatures
		Invokes the Additional-Features function script.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -AllApps -SystemApps -OptimizeRegistry -DisableFeatures -RemovePackages -AddDrivers "E:\DriverFolder" -AddFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\Win10Pro.iso" -Build 16299 -SelectApps -SystemApps -OptimizeRegistry -DisableFeatures -RemovePackages -AddDrivers "E:\DriverFolder" -AddFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ISO "D:\Win Images\Win10Pro.iso" -Index 2 -Build 16299 -UseWhiteList -SysApps -RegEdit -Features -Packages -Drivers "E:\DriverFolder" -AddFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -WIM "D:\WIM Files\Win10Pro\install.wim" -Index 3 -Build 15063 -Select -SysApps -RegEdit -Features -Packages -Drivers "E:\DriverFolder\OEM12.inf" -AddFeatures

	.NOTES
		Be aware that removing the Provisioning Application Package "Microsoft.XBOX.TCUI, or removing the System Application "XboxCallableUI," will "break" the App Troubleshooter.
	
	.NOTES
		===========================================================================
		Created on:   	11/30/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        2.0.7
		Last updated:	01/16/2018
		===========================================================================
#>
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')]
	[ValidateScript({ Test-Path $(Resolve-Path $_) })]
	[Alias('ISO', 'WIM')]
	[string]$ImagePath,
	[Parameter(HelpMessage = 'If using a multi-index image, specify the index of the image.')]
	[ValidateRange(1, 16)]
	[int]$Index = 1,
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The build number of the image.')]
	[ValidateRange(15063, 16299)]
	[int]$Build,
	[Parameter(HelpMessage = 'Prompts the user to determine whether or not a Provisioned App Package is removed.')]
	[Alias('Select')]
	[switch]$SelectApps,
	[Parameter(HelpMessage = 'Automatically removes all Provisioned App Packages.')]
	[switch]$AllApps,
	[Parameter(HelpMessage = 'Automatically removes all Provisioned App Packages not included in the WhiteList.')]
	[Alias('WhiteList')]
	[switch]$UseWhiteList,
	[Parameter(HelpMessage = 'Removes the provisioning and installation of System Apps.')]
	[Alias('SysApps')]
	[switch]$SystemApps,
	[Parameter(HelpMessage = 'Adds optimized entries and values to the image registry hives.')]
	[Alias('RegEdit')]
	[switch]$OptimizeRegistry,
	[Parameter(HelpMessage = 'Disables all Windows Optional Features included in the DisableList.')]
	[Alias('Features')]
	[switch]$DisableFeatures,
	[Parameter(HelpMessage = 'Removes all Windows Packages included in the RemovalList.')]
	[Alias('Packages')]
	[switch]$RemovePackages,
	[Parameter(Mandatory = $false,
			   HelpMessage = 'The path to a collection of driver packages, or a driver .inf file, to be injected into the image.')]
	[ValidateScript({ Test-Path $(Resolve-Path $_) })]
	[Alias('Drivers')]
	[string]$AddDrivers,
	[Parameter(HelpMessage = 'Calls the Additional-Features function script.')]
	[switch]$AddFeatures
)

## *************************************************************************************************
## *          THE FIELDS BELOW CAN BE EDITED TO FURTHER ACCOMMODATE REMOVAL REQUIREMENTS.          *
## *************************************************************************************************

## System Apps to remove. Adding ImmersiveControlPanel or ShellExperienceHost to this list will result in a NON-FUNCTIONAL final image.
[string[]]$SystemAppsList = @(
	"contactsupport"
	"ContentDeliveryManager"
	#"Cortana"
	"HolographicFirstRun"
	"HoloShell"
	"holoitemplayerapp"
	"Holograms"
	"holocamera"
	"MicrosoftEdge"
	"ParentalControls"
	"PPIProjection"
	"SecHealthUI"
	"SecureAssessmentBrowser"
	#"XboxGameCallableUI"
)

## Provisioned App Packages to keep if using the -UseWhiteList switch. Add the Apps' display name to the list. Do NOT use wildcards.
[string[]]$AppWhiteList = @(
	"Microsoft.DesktopAppInstaller"
	"Microsoft.Windows.Photos"
	#"Microsoft.WindowsCalculator"
	"Microsoft.Xbox.TCUI"
	"Microsoft.StorePurchaseApp"
	"Microsoft.WindowsStore"
)

## Features to be disabled if using the -DisableFeatures switch. Wildcards accepted.
[string[]]$FeatureDisableList = @(
	"*WorkFolders-Client*"
	"*WindowsMediaPlayer*"
	"*Internet-Explorer*"
)

## Packages to be removed if using the -RemovePackages switch. Wildcards accepted.
[string[]]$PackageRemovalList = @(
	"*ContactSupport*"
	"*QuickAssist*"
	"*InternetExplorer*"
	"*MediaPlayer*"
)

## Switches to be used when the Additional-Features function script is called.
$AdditionalFeatures = "-ContextMenu -SystemImages -NetFx3 -OfflineServicing -HostsFile"

## *************************************************************************************************
## *                                      END EDITABLE FIELDS.                                     *
## *************************************************************************************************

If (!(Test-Path -Path "$PSScriptRoot\Helper-Script.ps1"))
{
	Throw "The required Helper Script is not in the root directory."
}

. .\Helper-Script.ps1

#region Script Variables
$Host.UI.RawUI.WindowTitle = "Optimizing image."
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = "SilentlyContinue"
$Script = "Optimize-Offline"
$ErrorMessage = "$_.Exception.Message"
$TimeStamp = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
$LogFile = "$env:TEMP\Optimize-Offline.log"
#endregion Script Variables

If (!(Verify-Admin))
{
	Write-Warning -Message "Administrative access is required. Please re-launch PowerShell with elevation and re-run $Script."
	Break
}

If ($SelectApps -and $AllApps)
{
	Throw "The SelectApps switch and AllApps switch cannot be enabled at the same time."
}

If ($SelectApps -and $UseWhiteList)
{
	Throw "The SelectApps switch and UseWhiteList switch cannot be enabled at the same time."
}

If ($AllApps -and $UseWhiteList)
{
	Throw "The AllApps switch and UseWhiteList switch cannot be enabled at the same time."
}

If (Get-WindowsImage -Mounted)
{
	Write-Output ''
	Write-Verbose "Active mount location detected. Performing clean-up." -Verbose
	$GetMountedImage = Get-WindowsImage -Mounted
	$QueryAppData = REG QUERY HKLM | FindStr 'AppData'
	$QueryWIM = REG QUERY HKLM | FindStr 'WIM'
	If (Verify-OfflineHives)
	{
		[void](Unload-OfflineHives)
	}
	If ($QueryAppData -match "C:")
	{
		[void]($QueryAppData.ForEach({ REG UNLOAD $_ }))
	}
	If ($QueryWIM -ne $null)
	{
		[void]($QueryWIM.ForEach({ REG UNLOAD $_ }))
	}
	[void](Dismount-WindowsImage -Path $GetMountedImage.MountPath -Discard)
	Remove-Item -Path $GetMountedImage.MountPath -Recurse -Force
	$ImageParentPath = Split-Path -Path $GetMountedImage.ImagePath -Parent
	Remove-Item -Path $ImageParentPath -Recurse -Force
	[void](Clear-WindowsCorruptMountPoint)
	Write-Output ''
	Write-Output "Clean-up complete."
	Start-Sleep 3
	Clear-Host
}

If (([IO.FileInfo]$ImagePath).Extension -like ".ISO")
{
	$ISOPath = (Resolve-Path $ImagePath).Path
	$MountISO = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
	$DriveLetter = ($MountISO | Get-Volume).DriveLetter
	$InstallWIM = "$($DriveLetter):\sources\install.wim"
	If (Test-Path -Path $InstallWIM)
	{
		Write-Output ''
		Write-Verbose "Copying WIM from the ISO to a temporary directory." -Verbose
		Copy-Item -Path $InstallWIM -Destination $env:TEMP -Force
		Dismount-DiskImage -ImagePath $ISOPath -StorageType ISO
		If (([IO.FileInfo]"$env:TEMP\install.wim").IsReadOnly) { ATTRIB -R $env:TEMP\install.wim }
		Clear-Host
	}
	Else
	{
		Dismount-DiskImage -ImagePath $ISOPath -StorageType ISO
		Throw "$ISOPath does not contain valid Windows Installation media."
	}
}
ElseIf (([IO.FileInfo]$ImagePath).Extension -like ".WIM")
{
	$WIMPath = (Resolve-Path $ImagePath).Path
	If (Test-Path -Path $WIMPath)
	{
		Write-Output ''
		Write-Verbose "Copying WIM to a temporary directory." -Verbose
		Copy-Item -Path $ImagePath -Destination $env:TEMP\install.wim -Force
		If (([IO.FileInfo]"$env:TEMP\install.wim").IsReadOnly) { ATTRIB -R $env:TEMP\install.wim }
		Clear-Host
	}
	Else
	{
		Throw "$WIMPath does not contain valid Windows Installation media."
	}
}

Try
{
	Write-Host "This script runs silently without any progress bars or percentages. Please be patient as it processes optimizations." -ForegroundColor Cyan
	Start-Sleep 8
	Clear-Host
	$Error.Clear()
	Process-Log -Output "$Script Starting." -LogPath $LogFile -Level Info
	Start-Sleep 3
	[void]($WorkFolder = Create-WorkDirectory)
	[void]($TempFolder = Create-TempDirectory)
	[void]($ImageFolder = Create-ImageDirectory)
	[void]($MountFolder = Create-MountDirectory)
	Move-Item -Path $env:TEMP\install.wim -Destination $ImageFolder -Force
	$ImageFile = "$ImageFolder\install.wim"
	
}
Catch [System.Exception]
{
	Write-Output ''
	Process-Log -Output "$ErrorMessage" -LogPath $LogFile -Level Error
	If ("$env:TEMP\install.wim")
	{
		Remove-Item -Path "$env:TEMP\install.wim" -Force
	}
	Remove-Item -Path $WorkFolder -Recurse -Force
	Remove-Item -Path $TempFolder -Recurse -Force
	Remove-Item -Path $ImageFolder -Recurse -Force
	Remove-Item -Path $MountFolder -Recurse -Force
	Break
}

Try
{
	Write-Output ''
	Process-Log -Output "Mounting Image." -LogPath $LogFile -Level Info
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
}
Catch [System.IO.IOException]
{
	Write-Output ''
	Process-Log -Output "Failed to mount the Windows Image." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}

Try
{
	[void](Load-OfflineHives)
	$WIMProperties = Get-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	If ($WIMProperties.CurrentBuildNumber -ge "15063")
	{
		Write-Output ''
		Write-Output "The image build [$($WIMProperties.CurrentBuildNumber)] is supported."
		Start-Sleep 3
		Write-Output ''
	}
	Else
	{
		Write-Output ''
		Write-Warning "The image build [$($WIMProperties.CurrentBuildNumber)] is not supported."
		Break
	}
}
Catch [System.Exception]
{
	Write-Output ''
	Process-Log -Output "Image build [$($WIMProperties.CurrentBuildNumber)] is not supported." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}
Finally
{
	[void](Unload-OfflineHives)
}

Try
{
	Process-Log -Output "Verifying image health." -LogPath $LogFile -Level Info
	$ScriptStartHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth
	If ($ScriptStartHealthCheck.ImageHealthState -eq "Healthy")
	{
		Write-Output ''
		Write-Output "The image is healthy."
		Start-Sleep 3
		Clear-Host
	}
	Else
	{
		Write-Output ''
		Write-Warning "The image has been flagged for corruption. Further servicing is required before the image can be optimized."
		Break
	}
}
Catch [System.IO.IOException]
{
	Write-Output ''
	Process-Log -Output "Failed to verify the image health." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}
Catch [System.Exception]
{
	Write-Output ''
	Process-Log -Output "Script terminated due to image corruption." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}

If ($UseWhiteList)
{
	Process-Log -Output "Removing all Provisioning Application Packages not WhiteListed." -LogPath $LogFile -Level Info
	Start-Sleep 3; "`n"
	$AppWhiteList.ForEach({ Write-Output "WhiteListed:`t$_"; Write-Output "$TimeStamp INFO: Skipping Provisioning Application Package: $($_)" >> $LogFile }); "`n"; Write-Verbose "Please wait." -Verbose
	[void](Get-AppxProvisionedPackage -Path $MountFolder | ? { $_.DisplayName -notin $AppWhiteList } | Remove-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder)
}

If ($SelectApps -or $AllApps)
{
	$AppPackages = Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
		If ($SelectApps)
		{
			$AppSelect = Read-Host "Remove Provisioning Application Package:" $_.DisplayName "(Y/N)"
			If ($AppSelect -eq "y")
			{
				Process-Log -Output "Removing Provisioning Application Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
				[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
				$AppSelect = ''
			}
			Else
			{
				Process-Log -Output "Skipping Provisioning Application Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
				$AppSelect = ''
			}
		}
		ElseIf ($AllApps)
		{
			Process-Log -Output "Removing Provisioning Application Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
			[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
		}
	}
}

If ($SelectApps -or $AllApps -or $UseWhiteList)
{
	$AddStartMenuLayout = {
		$LayoutTemplate = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6">
        <start:Group Name="">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationID="Microsoft.Windows.Computer" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationID="Microsoft.Windows.ControlPanel" />
          <start:DesktopApplicationTile Size="1x1" Column="4" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="4" Row="1" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="5" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="5" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\UWP File Explorer.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
    <CustomTaskbarLayoutCollection>
      <defaultlayout:TaskbarLayout>
        <taskbar:TaskbarPinList>
          <taskbar:UWA AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
        </taskbar:TaskbarPinList>
      </defaultlayout:TaskbarLayout>
    </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
		$LayoutModificationXML = Join-Path -Path "$MountFolder\Users\Default\AppData\Local\Microsoft\Windows\Shell" -ChildPath "LayoutModification.xml"
		Set-Content -Path $LayoutModificationXML -Value $LayoutTemplate -Force
	}
	$AddUWPExplorer = {
		$WshShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WshShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UWP File Explorer.lnk")
		$Shortcut.TargetPath = "C:\Windows\explorer.exe"
		$Shortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
		$Shortcut.IconLocation = "imageres.dll,-1023"
		$Shortcut.WorkingDirectory = "C:\Windows"
		$Shortcut.Description = "The UWP File Explorer Application."
		$Shortcut.Save()
	}
	Clear-Host
	Process-Log -Output "Applying a custom Start Menu and Taskbar Layout." -LogPath $LogFile -Level Info
	Start-Sleep 3
	& $AddStartMenuLayout
	& $AddUWPExplorer
}

#region Registry Optimizations
If ($OptimizeRegistry)
{
	Try
	{
		$SystemPrivacy = {
			#****************************************************************
			Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Telemetry and Data Collecting." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Windows Update Peer-to-Peer Distribution." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Windows Auto-Update and Auto-Reboot." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Windows' Peer-to-Peer Networking Service." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling 'Find My Device'." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Enabling PIN requirement for pairing devices." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" /v "RequirePinForPairing" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Home Group Services." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Text Suggestions and Screen Monitoring." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" /v "AllowScreenMonitoring" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" /v "AllowTextSuggestions" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Steps Recorder." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling App Location Services and Sensors." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "DENY" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /v "Value" /t REG_SZ /d "DENY" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d "2" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling System Location Services and Sensors." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling User Location Services and Sensors." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Error Reporting." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling WiFi Sense." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Windows Asking for Feedback." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f)
			#****************************************************************	
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling the Password Reveal button." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Non-Explicit App Synchronization." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Apps Accessing Phone, SMS/Text Messaging and Call History." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v "Value" /t REG_SZ /d "Deny" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Cross-Device Experiences." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Windows Media Player Statistics Tracking." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f)
			#****************************************************************
		}
		$SystemSettings = {
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Explorer Tips, Sync Notifications and Document Tracking." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowInfoTip" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FolderContentsInfoTip" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartButtonBalloonTip" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontUsePowerShellOnWinX" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentProgForNewUserInStartMenu" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling System Advertisements and Windows Spotlight." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "IncludeEnterpriseSpotlight" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Toast Notifications." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Feature Advertisement Notifications." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoBalloonFeatureAdvertisements" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling System Tray Promotion Notifications." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoSystraySystemPromotion" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling System and Settings Syncronization." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Automatic Download of Bloatware Apps and Suggestions." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Windows 'Getting to Know Me.'" >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Notifications on Lock Screen." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Reminders and Incoming VoIP Calls on Lock Screen." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Lock Screen Camera and Overlays." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "LockScreenOverlaysDisabled" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Preview Build Telemetry." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Map Auto Downloads." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Speech Model Updates." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f)
			#****************************************************************
		}
		$UserExperience = {
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling First Log-on Animation." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Changing Search Bar to Magnifying Glass Icon." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Moving Drive Letter Before Drive Label." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowDriveLettersFirst" /t REG_DWORD /d "4" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Enabling Dark Theme for Settings and Modern Apps." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Increasing Taskbar Transparency." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling 'Shortcut' text for Shortcuts." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Enabling Explorer opens to This PC." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing Windows Store Icon from Taskbar." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoPinningStoreToTaskbar" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing Windows Mail Icon from Taskbar." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v "MailPin" /t REG_DWORD /d "2" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling the Windows Mail Application." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" /v "ManualLaunchAllowed" /t REG_DWORD /d "0" /f)
			#****************************************************************
			If ($Build -ge "16299")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing People Icon from Taskbar" >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************		
				[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f)
				[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f)
			}
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling 'How do you want to open this file?' prompt." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Switching to Smaller Control Panel Icons." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "StartupPage" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Adding This PC Icon to Desktop." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d "0" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Live Tiles." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************	
			[void](REG ADD "HKLM\WIM_HKCU\Software\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Connected Drive Autoplay and Autorun." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling GameDVR and the Xbox Services." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f)
			[void](REG ADD "HKLM\WIM_HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Enabling Developer Mode and Application Sideloading." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Appx" /v "AllowDevelopmentWithoutDevLicense" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Appx" /v "AllowAllTrustedApps" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Appx" /v "AllowDevelopmentWithoutDevLicense" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Appx" /v "AllowAllTrustedApps" /t REG_DWORD /d "1" /f)
		}
		$Usability = {
			If ($Build -ge "16299")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.glb\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" /f)
			}
			ElseIf ($Build -le "15063")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" /f)
			}
			If ($Build -ge "15063")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3ds\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dae\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dxf\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.wrl\Shell\3D Print" /f)
			}
			ElseIf ($Build -lt "15063")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\T3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\T3D Print" /f)
				[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\T3D Print" /f)
			}
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Restore Previous Versions' Property Tab." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Restore Previous Versions' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f)
			#****************************************************************
			If ($Build -ge "16299")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing 'Share' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************		
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f)
			}
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Give Access To' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" /t REG_SZ /d "" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Cast To Device' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Hiding Recently and Frequently Used Items in Explorer." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f)
			#****************************************************************
			If ($Build -ge "16299")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing all User Folders from This PC." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
			}
			ElseIf ($Build -le "15063")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Removing all User Folders from This PC." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f)
			}
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing Drives from the Navigation Pane." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /f)
			[void](REG DELETE "HKLM\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Cleaning up Control Panel CPL links." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************		
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowCpl" /t REG_DWORD /d "1" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "1" /t REG_SZ /d "Microsoft.OfflineFiles" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "2" /t REG_SZ /d "Microsoft.EaseOfAccessCenter" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "3" /t REG_SZ /d "Microsoft.PhoneAndModem" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "4" /t REG_SZ /d "Microsoft.RegionAndLanguage" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "5" /t REG_SZ /d "Microsoft.ScannersAndCameras" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "6" /t REG_SZ /d "Microsoft.SpeechRecognition" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "7" /t REG_SZ /d "Microsoft.SyncCenter" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "8" /t REG_SZ /d "Microsoft.Infrared" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "9" /t REG_SZ /d "Microsoft.ColorManagement" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "10" /t REG_SZ /d "Microsoft.Fonts" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "11" /t REG_SZ /d "Microsoft.Troubleshooting" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "12" /t REG_SZ /d "Microsoft.InternetOptions" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "13" /t REG_SZ /d "Microsoft.HomeGroup" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "14" /t REG_SZ /d "Microsoft.DateAndTime" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "15" /t REG_SZ /d "Microsoft.AutoPlay" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "16" /t REG_SZ /d "Microsoft.DeviceManager" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "17" /t REG_SZ /d "Microsoft.FolderOptions" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "18" /t REG_SZ /d "Microsoft.RegionAndLanguage" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "19" /t REG_SZ /d "Microsoft.TaskbarAndStartMenu" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "20" /t REG_SZ /d "Microsoft.PenAndTouch" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "21" /t REG_SZ /d "Microsoft.BackupAndRestore" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "22" /t REG_SZ /d "Microsoft.DevicesAndPrinters" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "23" /t REG_SZ /d "Microsoft.WindowsDefender" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "24" /t REG_SZ /d "Microsoft.WindowsFirewall" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "25" /t REG_SZ /d "Microsoft.WorkFolders" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "26" /t REG_SZ /d "Microsoft.WindowsAnytimeUpgrade" /f)
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" /v "27" /t REG_SZ /d "Microsoft.Language" /f)
			If ($Build -ge "16299")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps" /f)
			}
			ElseIf ($Build -eq "15063")
			{
				#****************************************************************
				Write-Output '' >> $WorkFolder\Registry-Optimizations.log
				Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
				#****************************************************************
				[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking" /f)
			}
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Recent Document History." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Disabling Automatic Sound Reduction." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f)
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Enabling Component Clean-up with Reset Base." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableResetbase" /t REG_DWORD /d "0" /f)
		}
		Write-Output ''
		Process-Log -Output "Optimizing the Image Registry." -LogPath $LogFile -Level Info
		[void](Load-OfflineHives)
		& $SystemPrivacy
		& $SystemSettings
		& $UserExperience
		& $Usability
		[void](Unload-OfflineHives)
		$RegistryComplete = $true
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "$ErrorMessage" -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
}
#endregion Registry Optimizations

If ($SystemApps)
{
	Write-Output ''
	Write-Verbose "Removing System Applications." -Verbose
	[void](Load-OfflineHives)
	$InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
	ForEach ($SystemApp in $SystemAppsList)
	{
		$InboxApps = (Get-ChildItem -Path $InboxAppsKey).Name.Split("\") | ? { $_ -like "*$SystemApp*" }
		ForEach ($InboxApp in $InboxApps)
		{
			Write-Output "$TimeStamp INFO: Removing System Application: $($InboxApp.Split("_")[0])" >> $LogFile
			$FullKeyPath = "$InboxAppsKey\$InboxApp"
			$Subkey = $FullKeyPath.Substring(6)
			[void](REG DELETE HKLM\$Subkey /F)
		}
	}
	[void](Unload-OfflineHives)
	$SystemAppsComplete = $true
}

If ($SystemAppsComplete -eq $true -and $SystemAppsList -contains "SecHealthUI")
{
	Try
	{
		Write-Output ''
		Process-Log -Output "Disabling remaining Windows Defender services to complete its removal." -LogPath $LogFile -Level Info
		$Software = "HKLM:\WIM_HKLM_SOFTWARE"
		$System = "HKLM:\WIM_HKLM_SYSTEM"
		[void](Load-OfflineHives)
		If (!(Test-Path -Path "$Software\Policies\Microsoft\Windows Defender"))
		{
			[void](New-Item -Path "$Software\Policies\Microsoft\Windows Defender" -Force)
			[void](New-Item -Path "$Software\Policies\Microsoft\Windows Defender\Spynet" -Force)
			[void](New-Item -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force)
			[void](New-Item -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -PropertyType DWord -Value 1 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -PropertyType DWord -Value 0 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType DWord -Value 2 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -PropertyType DWord -Value 1 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -PropertyType DWord -Value 1 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -PropertyType DWord -Value 1 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -PropertyType DWord -Value 2 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -PropertyType DWord -Value 0 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -PropertyType DWord -Value 0 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -PropertyType DWord -Value 2 -Force)
		}
		Else
		{
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2 -Force)
		}
		If (!(Test-Path -Path "$Software\Policies\Microsoft\MRT"))
		{
			[void](New-Item -Path "$Software\Policies\Microsoft\MRT" -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -PropertyType DWord -Value 1 -Force)
			[void](New-ItemProperty -Path "$Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -PropertyType DWord -Value 1 -Force)
		}
		Else
		{
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Force)
			[void](Set-ItemProperty -Path "$Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Force)
		}
		If (Test-Path -Path "$Software\Microsoft\Windows\CurrentVersion\Run")
		{
			[void](Remove-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force)
		}
		If ($Build -ge "16299" -and $RegistryComplete -eq $true)
		{
			[void](Set-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsdefender" -Force)
		}
		ElseIf ($Build -eq "15063" -and $RegistryComplete -eq $true)
		{
			[void](Set-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsdefender" -Force)
		}
		$DisableDefenderComplete = $true
	}
	Catch [System.IO.IOException], [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "Failed to disable the remaining SecHealthUI services." -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
	Finally
	{
		[void](Unload-OfflineHives)
	}
}

If ($DisableDefenderComplete -eq $true -and $Build -ge "16299")
{
	Write-Output ''
	Process-Log -Output "Disabling Windows-Defender-Default-Defintions." -LogPath $LogFile -Level Info
	[void](Disable-WindowsOptionalFeature -Path $MountFolder -FeatureName "Windows-Defender-Default-Definitions" -ScratchDirectory $TempFolder)
}

If ($DisableFeatures)
{
	Write-Output ''
	Process-Log -Output "Disabling all Windows Features included in the Feature Disable List." -LogPath $LogFile -Level Info
	$WindowsFeatures = Get-WindowsOptionalFeature -Path $MountFolder
	ForEach ($Feature in $FeatureDisableList)
	{
		[void]($WindowsFeatures.Where({ $_.FeatureName -like $Feature }) | Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $TempFolder)
	}
}

If ($RemovePackages)
{
	Write-Output ''
	Process-Log -Output "Removing all Windows Packages included in the Package Removal List." -LogPath $LogFile -Level Info
	$WindowsPackages = Get-WindowsPackage -Path $MountFolder
	ForEach ($Package in $PackageRemovalList)
	{
		[void]($WindowsPackages.Where({ $_.PackageName -like $Package }) | Remove-WindowsPackage -Path $MountFolder -ScratchDirectory $TempFolder)
	}
}

If ($AddDrivers)
{
	If ((Test-Path -Path $AddDrivers -PathType Container) -eq $true)
	{
		Write-Output ''
		Process-Log -Output "Injecting driver packages into the image." -LogPath $LogFile -Level Info
		[void](Add-WindowsDriver -Path $MountFolder -Driver $AddDrivers -Recurse -ForceUnsigned)
		Get-WindowsDriver -Path $MountFolder | Format-List | Out-File $WorkFolder\DriverPackageList.txt -Force
	}
	ElseIf ((Test-Path -Path $AddDrivers -PathType Leaf) -eq $true -and ([IO.FileInfo]$AddDrivers).Extension -like ".INF")
	{
		Write-Output ''
		Process-Log -Output "Injecting driver package into the image." -LogPath $LogFile -Level Info
		[void](Add-WindowsDriver -Path $MountFolder -Driver $AddDrivers -ForceUnsigned)
		Get-WindowsDriver -Path $MountFolder | Format-List | Out-File $WorkFolder\DriverPackageList.txt -Force
	}
	Else
	{
		Write-Output ''
		Process-Log -Output "$AddDrivers is not a valid driver package path." -LogPath $LogFile -Level Error
	}
}

If ($RegistryComplete -eq $true)
{
	Write-Output ''
	Process-Log -Output "Creating OOBE and SetupComplete scripts." -LogPath $LogFile -Level Info
	Start-Sleep 3
	If ($DisableDefenderComplete -eq $true -and $SystemAppsList -contains "XboxGameCallableUI")
	{
		& $OOBE1
		$OOBEScriptComplete = $true
	}
	ElseIf ($DisableDefenderComplete -eq $true -and $SystemAppsList -notcontains "XboxGameCallableUI")
	{
		& $OOBE2
		$OOBEScriptComplete = $true
	}
	ElseIf ($DisableDefenderComplete -ne $true -and $SystemAppsList -contains "XboxGameCallableUI")
	{
		& $OOBE3
		$OOBEScriptComplete = $true
	}
	Else
	{
		& $OOBE4
		$OOBEScriptComplete = $true
	}
}

If ($OOBEScriptComplete -eq $true)
{
	If ($DisableDefenderComplete -eq $true)
	{
		& $SETUPCOMPLETE1
		$SetupCompleteComplete = $true
	}
	ElseIf ($DisableDefenderComplete -ne $true)
	{
		& $SETUPCOMPLETE2
		$SetupCompleteComplete = $true
	}
}
ElseIf ($OOBEScriptComplete -ne $true)
{
	& $SETUPCOMPLETE3
	$SetupCompleteComplete = $true
}

If ($AddFeatures)
{
	Try
	{
		Clear-Host
		Process-Log -Output "Invoking the Additional-Features function script." -LogPath $LogFile -Level Info
		Start-Sleep 3
		. .\Additional-Features.ps1
		Invoke-Expression -Command "Additional-Features $AdditionalFeatures"
	}
	Catch [System.IO.FileNotFoundException]
	{
		Write-Output ''
		Process-Log -Output "Additional-Features function script not found." -LogPath $LogFile -Level Error
	}
}

Try
{
	Clear-Host
	Process-Log -Output "Verifying the image health before finalizing." -LogPath $LogFile -Level Info
	$ScriptEndHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth
	If ($ScriptEndHealthCheck.ImageHealthState -eq "Healthy")
	{
		Write-Output ''
		Write-Output "The image is healthy."
		Start-Sleep 3
	}
	Else
	{
		Write-Output ''
		Write-Warning "The image has been flagged for corruption. Further servicing is recommended."
		Start-Sleep 3
	}
}
Catch [System.IO.IOException]
{
	Write-Output ''
	Process-Log -Output "Failed to verify the image health." -LogPath $LogFile -Level Error
}

Try
{
	Write-Output ''
	Process-Log -Output "Saving Image and Dismounting." -LogPath $LogFile -Level Info
	If (Verify-OfflineHives)
	{
		[void](Unload-OfflineHives)
	}
	[void](Dismount-WindowsImage -Path $MountFolder -Save -CheckIntegrity -ScratchDirectory $TempFolder)
}
Catch [System.IO.IOException], [System.Exception]
{
	Write-Output ''
	Process-Log -Output "An I/O error occured while trying to save and dismount the Windows Image." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}

Try
{
	Write-Output ''
	Process-Log -Output "Rebuilding and compressing the new image." -LogPath $LogFile -Level Info
	[void](Export-WindowsImage -CheckIntegrity -CompressionType maximum -SourceImagePath $ImageFile -SourceIndex $Index -DestinationImagePath $WorkFolder\install.wim -ScratchDirectory $TempFolder)
}
Catch [System.IO.IOException], [System.Exception]
{
	Write-Output ''
	Process-Log -Output "An I/O error occured while trying to rebuild and compress the the new image." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}

Try
{
	Write-Output ''
	Process-Log -Output "Finalizing Script." -LogPath $LogFile -Level Info
	[void]($SaveFolder = Create-SaveDirectory)
	Move-Item -Path $WorkFolder\*.txt -Destination $SaveFolder -Force
	Move-Item -Path $WorkFolder\*.log -Destination $SaveFolder -Force
	Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force
	Remove-Item -Path $TempFolder -Recurse -Force
	Remove-Item -Path $ImageFolder -Recurse -Force
	Remove-Item -Path $MountFolder -Recurse -Force
	Remove-Item -Path $WorkFolder -Recurse -Force
	[void](Clear-WindowsCorruptMountPoint)
	Start-Sleep 3
}
Catch [System.IO.DirectoryNotFoundException], [System.IO.FileNotFoundException]
{
	Write-Output ''
	Process-Log -Output "Failed to locate all required files in $env:TEMP." -LogPath $LogFile -Level Error
}

If ($Error.Count.Equals(0))
{
	Write-Output ''
	Write-Output "Newly optimized image has been saved to $SaveFolder."
	Write-Output ''
	Process-Log -Output "$Script completed with [0] errors." -LogPath $LogFile -Level Info
	Move-Item -Path $LogFile -Destination $SaveFolder -Force
	Write-Output ''
}
Else
{
	$SaveErrorLog = Join-Path -Path $SaveFolder -ChildPath "ErrorLog.log"
	Set-Content -Path $SaveErrorLog -Value $Error
	Write-Output ''
	Write-Output "Newly optimized image has been saved to $SaveFolder."
	Write-Output ''
	Process-Log -Output "$Script completed with [$($Error.Count)] errors.`nErrorLog saved to $SaveFolder\ErrorLog.log" -LogPath $LogFile -Level Warning
	Move-Item -Path $LogFile -Destination $SaveFolder -Force
	Write-Output ''
}
# SIG # Begin signature block
# MIIJngYJKoZIhvcNAQcCoIIJjzCCCYsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUy3NEV9hgrHI+muhuvPrnJ2KA
# 68KgggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
# MCkxJzAlBgNVBAMTHk9NTklDLlRFQ0gtQ0EgQ2VydGlmaWNhdGUgUm9vdDAeFw0x
# NzExMDcwMzM4MjBaFw0zOTEyMzEyMzU5NTlaMCQxIjAgBgNVBAMTGU9NTklDLlRF
# Q0ggUG93ZXJTaGVsbCBDU0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC61XYWFHD6Mf5tjbApbKSOWTlKYm9zYpVcHJ4bCXuRwUHaZEqd13GuvxA58oxL
# sj2PjV2lzV00zFk0RyswA20H2bjQtRJ45WZWUZMpgcf6hIiFGtQCuEQnytjD0AQu
# OTGBfwngyRsKLbaEDWk7B0dlWoYCvxt1zvXSIH2YcqpfP6QLejA+nyhvuLZm0O9E
# aFvBCPc+7G68VfQCQyn+aBTQpJpH34O9Qv06B2FGSiDk+lwrKQW4juEDmrabgpYF
# TACsxVUHK/1loejOvCZFyBXiyRoNaf8tJaSqmqzeB5zZz4rFAJesWEs+iAZutvfa
# x6TzMGFtjjevzl6ZrnF7Fv/9AgMBAAGjczBxMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MFoGA1UdAQRTMFGAEApGKFjm6hqPE+12gARxOhGhKzApMScwJQYDVQQDEx5PTU5J
# Qy5URUNILUNBIENlcnRpZmljYXRlIFJvb3SCEIgU76EmbFSeTMjPeYe5TN0wCQYF
# Kw4DAh0FAAOCAQEAte3lbQnd4Wnqf6qqmemtPLIHDna+382IRzBr4+ZaK4TXqXgl
# /sPzVkwkoqroJV9mMrQPvVXjgCaHie5h5W0HeGRVdQv7biG4zRNzbheVck2LPaOo
# MDNsNCc12ab9lvK/Y7eaj19iP1Yii/VBrnY3YsNt200icymp60R1QjgvXncPxZqK
# viMg7VQWBTfQ3n7LucBhuSZaMJItbVRTlJsbXzkmCQzvG88/TDRbFqukbmDVgiZL
# RONR2KTv0PRxopIews59WGMrJseuihET4z5a3L7xeUdwXCVPn87xgqIQGaCB5jui
# 0DHgpniWmxbBuAQMPMeuwSEQV0jb5KqVUegFGDCCA0cwggIzoAMCAQICEIgU76Em
# bFSeTMjPeYe5TN0wCQYFKw4DAh0FADApMScwJQYDVQQDEx5PTU5JQy5URUNILUNB
# IENlcnRpZmljYXRlIFJvb3QwHhcNMTcxMTA3MDMzMjIyWhcNMzkxMjMxMjM1OTU5
# WjApMScwJQYDVQQDEx5PTU5JQy5URUNILUNBIENlcnRpZmljYXRlIFJvb3QwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMH3EMA2t/V0+BbvaWhgoezpQZ
# hY5NZcC/Yfs6YzAbCEBagmfT22NpAGKAd/fmsqL0DlZeBPDC8z5ga9BvxxWtvZQl
# QzCHx3wbmgrpc9AA99xEGms3lhcKea+wqEPCebK/OnSPVqqxEoGykoLQiR2BSO/m
# QL2hQPkM8kFGbX3ncUCMSdMWJR0XTcZL6zVPIpaLj0qJVEL6YoAFdlrd+6N2STex
# 9LKZhJ88dtfEiM0e81KyAkHHjPX03abSKppVTgOxG4+WZtMDZnvlpolEi5tgVy0e
# d04BBQmztKilRZILPkAgcmx89pf6Fa5Vss3Fp3Z7D+4e9nQ+4DZ/Vb1NIKZRAgMB
# AAGjczBxMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFoGA1UdAQRTMFGAEApGKFjm6hqP
# E+12gARxOhGhKzApMScwJQYDVQQDEx5PTU5JQy5URUNILUNBIENlcnRpZmljYXRl
# IFJvb3SCEIgU76EmbFSeTMjPeYe5TN0wCQYFKw4DAh0FAAOCAQEAtj1/SaELGLyj
# DP2aRLpfMq1KIBoMjJvQhYfPWugzc6GJM/v+3LomDW8yylMhQRqy6749HMfDVXtJ
# oc4KU00H2q7M5xXGX7HJlh4tFEMrT4k1WDVdxF/TgXxTlMWBfRXV/rNzSFHtHVf6
# F+dY7INqxKlbMGpg3buF/Oh8ZtPk9xhyWtwraUTsyVBlmQlMeFeKwksbaSEy72mJ
# 5DhQfVmEv1PTv/wIJ/ff8OOZ63AeJqpLcmFARbTUmQVboFEG5mU30BHHntABspLj
# kdk4PCQjdVgG8Bd7uOC3XNbmrhTehi7Uu8uOBm7RQawF1wh65SlQm5HY2tntNPzD
# qHcndUPZwjGCAncwggJzAgEBMD0wKTEnMCUGA1UEAxMeT01OSUMuVEVDSC1DQSBD
# ZXJ0aWZpY2F0ZSBSb290AhB0u1Cd2puAkkG+oZic5rsmMAkGBSsOAwIaBQCgggEP
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRSOKp8m5fHqyJTacDslIJ5XauP9DCB
# rgYKKwYBBAGCNwIBDDGBnzCBnKCBmYCBlgBBACAAZgB1AGwAbAB5ACAAYQB1AHQA
# bwBtAGEAdABlAGQAIABXAGkAbgBkAG8AdwBzACAAMQAwACAAUgBTADIAIABhAG4A
# ZAAgAFIAUwAzACAAbwBmAGYAbABpAG4AZQAgAGkAbQBhAGcAZQAgAG8AcAB0AGkA
# bQBpAHoAYQB0AGkAbwBuACAAcwBjAHIAaQBwAHQALjANBgkqhkiG9w0BAQEFAASC
# AQAROMqyHu0wqQtJA0OMkoYWHAajml+CApgmfqZGP1ifVgl3oqKwEg3HWuHFLUzM
# Iz0NibzVH/a7M5Lx9ds7AWkWRqO0MQhy99EtYJNNj0K/HiESxl5c7lVY3Gpcibsi
# a7y5VwzQvuw+RDznT4yHg4lfACihcDc349QbF2fyDhfV3fCi5VDpSAHWtt5RyGsy
# ukQNme6ZGx9yogtO2+cnOm1jS8RfvzSFbkmpTC2R+lgioe2Qp2v62y/mcjGxkhQ1
# Ln9DIGqmJZzZtrHwe0csOCjRRCPXopePEqcRiIQY7s3bQ24HyMPMApDSpzJCT5QA
# LkYMDkeuyHrvEnnBF4/1S5jK
# SIG # End signature block
