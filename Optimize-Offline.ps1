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
		Prompts the user to determine whether or not a Provisioned App Package is removed.
	
	.PARAMETER AllApps
		Automatically removes all Provisioned App Packages.
	
	.PARAMETER UseWhiteList
		Automatically removes all Provisioned App Packages not included in the WhiteList.
	
	.PARAMETER SystemApps
		Removes the provisioning and installation of System Apps.
	
	.PARAMETER OptimizeRegistry
		Adds optimized entries and values to the image registry hives.
	
	.PARAMETER DisableFeatures
		Disables all Windows Optional Features included in the DisableList.
	
	.PARAMETER RemovePackages
		Removes all Windows Packages included in the RemovalList.
	
	.PARAMETER AddDrivers
		The path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.PARAMETER AddFeatures
		Calls the Additional-Features function script.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -AllApps -SystemApps -OptimizeRegistry -DisableFeatures -RemovePackages -AddDrivers "E:\DriverFolder" -AddFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\Win10Pro.iso" -Build 16299 -SelectApps -SystemApps -OptimizeRegistry -DisableFeatures -RemovePackages -AddDrivers "E:\DriverFolder" -AddFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ISO "D:\Win Images\Win10Pro.iso" -Index 2 -Build 16299 -UseWhiteList -SysApps -RegEdit -Features -Packages -Drivers "E:\DriverFolder" -AddFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -WIM "D:\WIM Files\Win10Pro\install.wim" -Index 3 -Build 15063 -Select -SysApps -RegEdit -Features -Packages -Drivers "E:\DriverFolder\OEM12.inf" -AddFeatures
	
	.NOTES
		===========================================================================
		Created on:   	11/30/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        2.0.5
		Last updated:	01/03/2018
		===========================================================================
#>
Param
(
	[Parameter(Mandatory = $true,
			   ValueFromPipelineByPropertyName = $true,
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
$SystemAppsList = @"
contactsupport
ContentDeliveryManager
HolographicFirstRun
HoloShell
holoitemplayerapp
Holograms
holocamera
MicrosoftEdge
ParentalControls
PPIProjection
SecHealthUI
SecureAssessmentBrowser
XboxGameCallableUI
"@

## Provisioned App Packages to keep if using the -UseWhiteList switch. Add the Apps' display name to the list. Do NOT use wildcards.
[string[]]$AppWhiteList = @(
	"Microsoft.DesktopAppInstaller"
	"Microsoft.Windows.Photos"
	"Microsoft.WindowsCalculator"
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
$AdditionalFeatures = "-ContextMenu -SystemImages -OfflineServicing -HostsFile"

## *************************************************************************************************
## *                                      END EDITABLE FIELDS.                                     *
## *************************************************************************************************

#region Script Variables
$Host.UI.RawUI.WindowTitle = "Optimizing image."
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = "SilentlyContinue"
$Script = "Optimize-Offline"
$ErrorMessage = "$_.Exception.Message"
$LogFile = "$env:TEMP\Optimize-Offline.log"
#endregion Script Variables

#region Helper Functions
Function Verify-Admin
{
	[CmdletBinding()]
	Param ()
	
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	$IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	Write-Verbose "IsUserAdmin? $IsAdmin" -Verbose
	Return $IsAdmin
}

Function Process-Log
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('LogContent')]
		[string]$Output,
		[Parameter(Mandatory = $false)]
		[string]$LogPath = "$env:SystemDrive\PowerShellLog.log",
		[Parameter(Mandatory = $false)]
		[ValidateSet('Info', 'Warning', 'Error')]
		[string]$Level = "Info",
		[switch]$NoClobber
	)
	
	Begin
	{
		$VerbosePreference = "Continue"
	}
	Process
	{
		If ((Test-Path -Path $LogPath) -and $NoClobber)
		{
			Write-Error "NoClobber was selected. Either $LogPath must be deleted or a new logging-path specified."
			Return
		}
		ElseIf (!(Test-Path -Path $LogPath))
		{
			Write-Verbose "Logging has started."
			Write-Output ''
			Start-Sleep 2
			$CreateLogFile = New-Item $LogPath -ItemType File -Force
		}
		$DateFormat = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
		Switch ($Level)
		{
			'Info' {
				Write-Verbose $Output
				$LevelPrefix = "INFO:"
			}
			'Warning' {
				Write-Warning $Output
				$LevelPrefix = "WARNING:"
			}
			'Error' {
				Write-Error $Output
				$LevelPrefix = "ERROR:"
			}
		}
		"$DateFormat $LevelPrefix $Output" | Out-File -FilePath $LogPath -Append
	}
	End { }
}

Function Create-WorkDirectory
{
	$WorkDir = [System.IO.Path]::GetTempPath()
	$WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($WorkDir)
	$WorkDir
}

Function Create-TempDirectory
{
	$TempDir = [System.IO.Path]::GetTempPath()
	$TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($TempDir)
	$TempDir
}

Function Create-ImageDirectory
{
	$ImageDir = [System.IO.Path]::GetTempPath()
	$ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($ImageDir)
	$ImageDir
}

Function Create-MountDirectory
{
	$MountDir = [System.IO.Path]::GetTempPath()
	$MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($MountDir)
	$MountDir
}

Function Create-SaveDirectory
{
	[CmdletBinding()]
	Param ()
	
	New-Item -ItemType Directory -Path $HOME\Desktop\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
}

Function Load-OfflineHives
{
	[void](REG LOAD HKLM\WIM_HKLM_COMPONENTS "$MountFolder\Windows\system32\config\COMPONENTS")
	[void](REG LOAD HKLM\WIM_HKLM_DRIVERS "$MountFolder\Windows\system32\config\DRIVERS")
	[void](REG LOAD HKLM\WIM_HKLM_SCHEMA "$MountFolder\Windows\system32\SMI\Store\Machine\SCHEMA.DAT")
	[void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\windows\system32\config\software")
	[void](REG LOAD HKLM\WIM_HKLM_SYSTEM "$MountFolder\windows\system32\config\system")
	[void](REG LOAD HKLM\WIM_HKCU "$MountFolder\Users\Default\NTUSER.DAT")
	[void](REG LOAD HKLM\WIM_HKU_DEFAULT "$MountFolder\Windows\System32\config\default")
}

Function Unload-OfflineHives
{
	Start-Sleep 3
	[gc]::collect()
	[void](REG UNLOAD HKLM\WIM_HKLM_COMPONENTS)
	[void](REG UNLOAD HKLM\WIM_HKLM_DRIVERS)
	[void](REG UNLOAD HKLM\WIM_HKLM_SCHEMA)
	[void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
	[void](REG UNLOAD HKLM\WIM_HKLM_SYSTEM)
	[void](REG UNLOAD HKLM\WIM_HKCU)
	[void](REG UNLOAD HKLM\WIM_HKU_DEFAULT)
}

Function Verify-OfflineHives
{
	[CmdletBinding()]
	Param ()
	
	$HivePaths = @(
		"HKLM:\WIM_HKLM_COMPONENTS"
		"HKLM:\WIM_HKLM_DRIVERS"
		"HKLM:\WIM_HKLM_SCHEMA"
		"HKLM:\WIM_HKLM_SOFTWARE"
		"HKLM:\WIM_HKLM_SYSTEM"
		"HKLM:\WIM_HKCU"
		"HKLM:\WIM_HKU_DEFAULT"
	) | % { $AllHivesLoaded = ((Test-Path -Path $_) -eq $true) }; Return $AllHivesLoaded
}

Function Terminate-Script
{
	[CmdletBinding()]
	Param ()
	
	Start-Sleep 3
	Write-Output ''
	Write-Verbose "Cleaning-up and terminating script. Please wait." -Verbose
	If (Verify-OfflineHives)
	{
		[void](Unload-OfflineHives)
	}
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
	[void](Move-Item -Path $LogFile -Destination $HOME\Desktop\Optimize-Offline.log -Force)
	[void](Remove-Item -Path $WorkFolder -Recurse -Force)
	[void](Remove-Item -Path $TempFolder -Recurse -Force)
	[void](Remove-Item -Path $ImageFolder -Recurse -Force)
	[void](Remove-Item -Path $MountFolder -Recurse -Force)
	[void](Clear-WindowsCorruptMountPoint)
}
#endregion Helper Functions

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
	$GetMountedImage = Get-WindowsImage -Mounted
	$QueryAppData = REG QUERY HKLM | FindStr 'AppData'
	Write-Verbose "Active mount location detected. Performing clean-up." -Verbose
	If (Verify-OfflineHives)
	{
		[void](Unload-OfflineHives)
	}
	If ($QueryAppData -match "C:")
	{
		[void]($QueryAppData.ForEach({ REG UNLOAD $_ }))
	}
	[void](Dismount-WindowsImage -Path $GetMountedImage.MountPath -Discard)
	[void](Remove-Item -Path $GetMountedImage.MountPath -Recurse -Force)
	$ImageParentPath = Split-Path -Path $GetMountedImage.ImagePath -Parent
	[void](Remove-Item -Path $ImageParentPath -Recurse -Force)
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
		Write-Verbose "Copying WIM from the ISO to a temporary directory." -Verbose
		[void](Copy-Item -Path $InstallWIM -Destination $env:TEMP -Force)
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
		Write-Verbose "Copying WIM to a temporary directory." -Verbose
		[void](Copy-Item -Path $ImagePath -Destination $env:TEMP\install.wim -Force)
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
	[void](Move-Item -Path $env:TEMP\install.wim -Destination $ImageFolder)
	$ImageFile = "$ImageFolder\install.wim"
	
}
Catch [System.Exception]
{
	Write-Output ''
	Process-Log -Output "$ErrorMessage" -LogPath $LogFile -Level Error
	If ("$env:TEMP\install.wim")
	{
		[void](Remove-Item -Path "$env:TEMP\install.wim" -Force)
	}
	[void](Remove-Item -Path $WorkFolder -Recurse -Force)
	[void](Remove-Item -Path $TempFolder -Recurse -Force)
	[void](Remove-Item -Path $ImageFolder -Recurse -Force)
	[void](Remove-Item -Path $MountFolder -Recurse -Force)
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
	Process-Log -Output "Removing all Provisioned App Packages not in the WhiteList." -LogPath $LogFile -Level Info
	Start-Sleep 3; "`n"
	$AppWhiteList.ForEach({ Write-Output "WhiteListed:`t$_" }); "`n"; Write-Verbose "Please wait." -Verbose
	[void](Get-AppxProvisionedPackage -Path $MountFolder | ? { $_.Displayname -notin $AppWhiteList } | Remove-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder)
	Get-AppxProvisionedPackage -Path $MountFolder | Format-List | Out-File $WorkFolder\AppxPackageList.txt -Force
}

If ($SelectApps -or $AllApps)
{
	Get-AppxProvisionedPackage -Path $MountFolder | % {
		If ($SelectApps)
		{
			$AppSelect = Read-Host "Remove Provisioned App Package:" $_.DisplayName "(Y/N)"
			If ($AppSelect -eq "y")
			{
				Process-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
				[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
				$AppSelect = ''
			}
			Else
			{
				Process-Log -Output "Skipping Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
				$AppSelect = ''
			}
		}
		ElseIf ($AllApps)
		{
			Process-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
			[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
		}
	}
}

If ($SelectApps -or $UseWhiteList)
{
	Get-AppxProvisionedPackage -Path $MountFolder | Format-List | Out-File $WorkFolder\AppxPackageList.txt -Force
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
	Try
	{
		$RemoveAppStr1 = @"
FOR %%I IN (
"@
		$RemoveAppStr2 = @"
) DO (
FOR /F %%A IN ('REG QUERY "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /S /F %%I /K 2^>NUL ^| FIND /I "InboxApplications"') DO IF %ERRORLEVEL% NEQ 1 (REG DELETE %%A /F 2>NUL)
)
"@
		Write-Output ''
		Process-Log -Output "Removing System Applications." -LogPath $LogFile -Level Info
		$RemoveSystemAppsScript = Join-Path -Path $TempFolder -ChildPath "SystemApp-Removal.cmd"
		Set-Content -Path $RemoveSystemAppsScript -Value ($RemoveAppStr1, $SystemAppsList, $RemoveAppStr2) -Encoding ASCII -Force
		$RemoveSystemApps = "$TempFolder\SystemApp-Removal.cmd"
		[void](Load-OfflineHives)
		Start-Process $RemoveSystemApps -WorkingDirectory $TempFolder -Verb runas -WindowStyle Hidden -Wait
		[void](Unload-OfflineHives)
		$SystemAppsComplete = $true
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "Failed to remove System Applications." -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
}

If ($SystemAppsComplete -eq $true -and $SystemAppsList -match "SecHealthUI")
{
	Try
	{
		Write-Output ''
		Process-Log -Output "Disabling remaining SecHealthUI services to complete its removal." -LogPath $LogFile -Level Info
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
	Get-WindowsOptionalFeature -Path $MountFolder | Format-Table | Out-File $WorkFolder\WindowsOptionalFeatureList.txt -Force
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
	Get-WindowsPackage -Path $MountFolder | Format-Table | Out-File $WorkFolder\WindowsPackageList.txt -Force
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
	Try
	{
		Write-Output ''
		Process-Log -Output "Creating OOBE and SetupComplete scripts." -LogPath $LogFile -Level Info
		If ($DisableDefenderComplete -eq $true -and $SystemAppsList -match "XboxGameCallableUI")
		{
			$SvcDisableOOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
			If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
			{
				[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
				$CreateOOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
				Set-Content -Path $CreateOOBEScript -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
			Else
			{
				Add-Content -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
		}
		ElseIf ($DisableDefenderComplete -eq $true -and $SystemAppsList -notmatch "XboxGameCallableUI")
		{
			$SvcDisableOOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
			If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
			{
				[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
				$CreateOOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
				Set-Content -Path $CreateOOBEScript -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
			Else
			{
				Add-Content -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
		}
		ElseIf ($DisableDefenderComplete -ne $true -and $SystemAppsList -match "XboxGameCallableUI")
		{
			$SvcDisableOOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
			If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
			{
				[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
				$CreateOOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
				Set-Content -Path $CreateOOBEScript -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
			Else
			{
				Add-Content -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
		}
		Else
		{
			$SvcDisableOOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
			If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
			{
				[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
				$CreateOOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
				Set-Content -Path $CreateOOBEScript -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
			Else
			{
				Add-Content -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $SvcDisableOOBE -Encoding ASCII -Force
				$OOBEScriptComplete = $true
			}
		}
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "$_.Exception.Message" -LogPath $LogFile -Level Error
	}
	Finally
	{
		Start-Sleep 3
	}
}

If ($OOBEScriptComplete -eq $true)
{
	Try
	{
		If ($DisableDefenderComplete -eq $true)
		{
			$SetupCompleteCMD = {
				$SetupCompleteEntries = @"
SET DEFAULTUSER0="defaultuser0"

FOR /F "TOKENS=*" %%A IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"^|FIND /I "s-1-5-21"') DO CALL :QUERY_REGISTRY "%%A"
GOTO :CONTINUE

:QUERY_REGISTRY
FOR /F "TOKENS=3" %%G IN ('REG QUERY %1 /v ProfileImagePath') DO SET PROFILEPATH=%%G
FOR /F "TOKENS=3 delims=\" %%E IN ('ECHO %PROFILEPATH%') DO SET PROFILENAME=%%E
FOR /F "TOKENS=1 delims=." %%F IN ('ECHO %PROFILENAME%') DO SET SCANREGISTRY=%%F
ECHO %DEFAULTUSER0%|FIND /I "%SCANREGISTRY%"
IF %ERRORLEVEL% EQU 1 GOTO :CONTINUE
RMDIR /S /Q "%SYSTEMDRIVE%\Users\%PROFILENAME%" >NUL
REG DELETE /F %1 >NUL 
IF EXIST "%SYSTEMDRIVE%\Users\%PROFILENAME%" GOTO :RETRY_DIR_REMOVE
GOTO :CONTINUE

:RETRY_DIR_REMOVE
TAKEOWN /F "%PROFILENAME%" >NUL
TIMEOUT /T 2 >NUL
ICACLS "%PROFILENAME%" /GRANT *S-1-1-0:F >NUL
TIMEOUT /T 2 >NUL
RMDIR /S /Q "%SYSTEMDRIVE%\Users\%PROFILENAME%" >NUL
GOTO :CONTINUE

:CONTINUE
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\ElevatedConsoles-To-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\InstallCAB-to-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\OOBE.cmd" >NUL
DEL "%~f0"
"@
				$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
				Set-Content -Path $SetupCompleteScript -Value $SetupCompleteEntries -Encoding ASCII -Force
				$SetupCompleteComplete = $true
			}
			& $SetupCompleteCMD
		}
		ElseIf ($DisableDefenderComplete -ne $true)
		{
			$SetupCompleteCMD = {
				$SetupCompleteEntries = @"
SET DEFAULTUSER0="defaultuser0"

FOR /F "TOKENS=*" %%A IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"^|FIND /I "s-1-5-21"') DO CALL :QUERY_REGISTRY "%%A"
GOTO :CONTINUE

:QUERY_REGISTRY
FOR /F "TOKENS=3" %%G IN ('REG QUERY %1 /v ProfileImagePath') DO SET PROFILEPATH=%%G
FOR /F "TOKENS=3 delims=\" %%E IN ('ECHO %PROFILEPATH%') DO SET PROFILENAME=%%E
FOR /F "TOKENS=1 delims=." %%F IN ('ECHO %PROFILENAME%') DO SET SCANREGISTRY=%%F
ECHO %DEFAULTUSER0%|FIND /I "%SCANREGISTRY%"
IF %ERRORLEVEL% EQU 1 GOTO :CONTINUE
RMDIR /S /Q "%SYSTEMDRIVE%\Users\%PROFILENAME%" >NUL
REG DELETE /F %1 >NUL 
IF EXIST "%SYSTEMDRIVE%\Users\%PROFILENAME%" GOTO :RETRY_DIR_REMOVE
GOTO :CONTINUE

:RETRY_DIR_REMOVE
TAKEOWN /F "%PROFILENAME%" >NUL
TIMEOUT /T 2 >NUL
ICACLS "%PROFILENAME%" /GRANT *S-1-1-0:F >NUL
TIMEOUT /T 2 >NUL
RMDIR /S /Q "%SYSTEMDRIVE%\Users\%PROFILENAME%" >NUL
GOTO :CONTINUE

:CONTINUE
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\ElevatedConsoles-To-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\InstallCAB-to-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\OOBE.cmd" >NUL
DEL "%~f0"
"@
				$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
				Set-Content -Path $SetupCompleteScript -Value $SetupCompleteEntries -Encoding ASCII -Force
				$SetupCompleteComplete = $true
			}
			& $SetupCompleteCMD
		}
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "$_.Exception.Message" -LogPath $LogFile -Level Error
	}
	Finally
	{
		Start-Sleep 3
	}
}
ElseIf ($OOBEScriptComplete -ne $true)
{
	Try
	{
		$SetupCompleteCMD = {
			$SetupCompleteEntries = @"
SET DEFAULTUSER0="defaultuser0"

FOR /F "TOKENS=*" %%A IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"^|FIND /I "s-1-5-21"') DO CALL :QUERY_REGISTRY "%%A"
GOTO :CONTINUE

:QUERY_REGISTRY
FOR /F "TOKENS=3" %%G IN ('REG QUERY %1 /v ProfileImagePath') DO SET PROFILEPATH=%%G
FOR /F "TOKENS=3 delims=\" %%E IN ('ECHO %PROFILEPATH%') DO SET PROFILENAME=%%E
FOR /F "TOKENS=1 delims=." %%F IN ('ECHO %PROFILENAME%') DO SET SCANREGISTRY=%%F
ECHO %DEFAULTUSER0%|FIND /I "%SCANREGISTRY%"
IF %ERRORLEVEL% EQU 1 GOTO :CONTINUE
RMDIR /S /Q "%SYSTEMDRIVE%\Users\%PROFILENAME%" >NUL
REG DELETE /F %1 >NUL 
IF EXIST "%SYSTEMDRIVE%\Users\%PROFILENAME%" GOTO :RETRY_DIR_REMOVE
GOTO :CONTINUE

:RETRY_DIR_REMOVE
TAKEOWN /F "%PROFILENAME%" >NUL
TIMEOUT /T 2 >NUL
ICACLS "%PROFILENAME%" /GRANT *S-1-1-0:F >NUL
TIMEOUT /T 2 >NUL
RMDIR /S /Q "%SYSTEMDRIVE%\Users\%PROFILENAME%" >NUL
GOTO :CONTINUE

:CONTINUE
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL "%~f0"
"@
			If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
			{
				[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
				$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
				Set-Content -Path $SetupCompleteScript -Value $SetupCompleteEntries -Encoding ASCII -Force
				$SetupCompleteComplete = $true
			}
			Else
			{
				Add-Content -Path "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd" -Value $SetupCompleteEntries -Encoding ASCII -Force
				$SetupCompleteComplete = $true
			}
		}
		& $SetupCompleteCMD
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "$ErrorMessage" -LogPath $LogFile -Level Error
	}
	Finally
	{
		Start-Sleep 3
	}
}

If ($AddFeatures)
{
	Try
	{
		Clear-Host
		Process-Log -Output "Calling the Additional-Features function script." -LogPath $LogFile -Level Info
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
	[void](Move-Item -Path $WorkFolder\*.txt -Destination $SaveFolder -Force)
	[void](Move-Item -Path $WorkFolder\*.log -Destination $SaveFolder -Force)
	[void](Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force)
	[void](Remove-Item -Path $TempFolder -Recurse -Force)
	[void](Remove-Item -Path $ImageFolder -Recurse -Force)
	[void](Remove-Item -Path $MountFolder -Recurse -Force)
	[void](Remove-Item -Path $WorkFolder -Recurse -Force)
	[void](Clear-WindowsCorruptMountPoint)
	Start-Sleep 3
}
Catch [System.IO.DirectoryNotFoundException], [System.IO.FileNotFoundException]
{
	Write-Output ''
	Process-Log -Output "Failed to locate all required files in $env:TEMP." -LogPath $LogFile -Level Error
}

Try
{
	If ($Error.Count -eq "0")
	{
		Write-Output ''
		Process-Log -Output "$Script completed with [0] errors." -LogPath $LogFile -Level Info
	}
	Else
	{
		$ErrorCount = $Error.Count
		Write-Output ''
		Process-Log -Output "$Script completed with [$ErrorCount] errors." -LogPath $LogFile -Level Warning
	}
}
Finally
{
	Write-Output ''
	Write-Output "Newly optimized image has been saved to $SaveFolder."
	[void](Move-Item -Path $LogFile -Destination $SaveFolder\Optimize-Offline.log -Force)
	Write-Output ''
}
# SIG # Begin signature block
# MIIJngYJKoZIhvcNAQcCoIIJjzCCCYsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0MO4VNTEe1wqDyEXWd16OUEx
# muGgggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
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
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQIH0nr4K2wxd4INRgRBd3Awxlo0TCB
# rgYKKwYBBAGCNwIBDDGBnzCBnKCBmYCBlgBBACAAZgB1AGwAbAB5ACAAYQB1AHQA
# bwBtAGEAdABlAGQAIABXAGkAbgBkAG8AdwBzACAAMQAwACAAUgBTADIAIABhAG4A
# ZAAgAFIAUwAzACAAbwBmAGYAbABpAG4AZQAgAGkAbQBhAGcAZQAgAG8AcAB0AGkA
# bQBpAHoAYQB0AGkAbwBuACAAcwBjAHIAaQBwAHQALjANBgkqhkiG9w0BAQEFAASC
# AQBNqjtv/8Z2dfI4cLOZcdUcrJqKixcrC2ALCsLxyDOI8mY/qMF5sYDiDSQC1mu3
# QIWg5lSCEaK1HHGad0e1m+XDpgmYyEMDKBlHe1MiTLW5+j9Qn1l4tKHE6AQzPUvA
# RMZr0T63wtzfjbJinFzulqR9xnxFbTG2vdvvWAkl0UkQolCLY64QvYdsbJJYIeqL
# k1aXvDXPk3BB/HY6JlSatdPQFnj/UezAOEQL0Zm1jhrlsfqENSkixE9+L9mM8IpT
# Drgs6tPqoQM658syeiYlTmvQBMc7vEipZXD5Q2uFS4JSOvjHaOijS+FLnGXuKCyM
# nDBexGV4ya0nXOL2/qFeoJZN
# SIG # End signature block
