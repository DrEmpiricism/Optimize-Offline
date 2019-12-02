Using module .\Src\OfflineResources.psm1
#Requires -RunAsAdministrator
<#
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.170
	 Created on:   	11/20/2019 11:53 AM
	 Created by:   	BenTheGreat
	 Filename:     	Optimize-Offline.psm1
	 Version:       4.0.0.0
	 Last updated:	12/02/2019
	-------------------------------------------------------------------------
	 Module Name: Optimize-Offline
	===========================================================================
#>
Function Optimize-Offline
{
	<#
	.SYNOPSIS
		Offline optimization framework for Windows 10 image versions 1803-to-1909 with 64-bit architectures contained within WIM files.
	
	.DESCRIPTION
		The Optimize-Offline module enables the offline optimizing of Windows 10 image (WIM) files for optimal runtime environments.
		Its intended purpose is to significantly increase the Windows 10 user experience by eliminating unnecessary bloat, enhancing privacy, improving aesthetics and increasing overall system performance.
		All optimization processes are user controlled using a configuration JSON file.
		No 3rd party programs are required to process optimizations, as Optimize-Offline utilizes an array of its own custom cmdlets, functions and wrappers to independently optimize an image.

	.PARAMETER SourcePath
		The path to a Windows 10 Installation Media ISO or a Windows image install WIM.

	.PARAMETER WindowsApps
		Removes Provisioned Windows App Packages (.appx) selectively or automatically based on the following values:

		Select: Populates and outputs a Gridview list of all Provisioned App Packages for selective removal.
		Whitelist: Automatically removes all Provisioned App Packages NOT found in the AppxWhiteList.json file.
		All: Automatically removes all Provisioned App Packages found in the image.

	.PARAMETER SystemApps
		Populates and outputs a Gridview list of System Apps for selective removal.

	.PARAMETER Capabilities
		Populates and outputs a Gridview list of Capability Packages for selective removal.

	.PARAMETER Packages
		Populates and outputs a Gridview list of Windows Cabinet File Packages for selective removal.

	.PARAMETER Features
		Populates and outputs a Gridview list of Windows Optional Features for selective disabling and enabling.

	.PARAMETER DeveloperMode
		Integrates the Developer Mode Feature into he image.

	.PARAMETER WindowsStore
		Integrates the Microsoft Windows Store and its required dependencies into the image.

	.PARAMETER MicrosoftEdge
		Integrates the Microsoft Edge Browser into the image.

	.PARAMETER Win32Calc
		Integrates the traditional Win32 Calculator into the image.

	.PARAMETER Dedup
		Integrates the Windows Server Data Deduplication Feature into the image.

	.PARAMETER DaRT
		Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools into Windows Setup and Windows Recovery based on the following values:

		Setup: Integrates DaRT 10 and Windows 10 Debugging Tools into Windows Setup only.
		Recovery: Integrates DaRT 10 and Windows 10 Debugging Tools into Windows Recovery only.
		All: Integrates DaRT 10 and Windows 10 Debugging Tools into both Windows Setup and Windows Recovery.

	.PARAMETER Registry
		Applies optimized settings into the image registry hives.

	.PARAMETER Additional
		Integrates user-specific content in the "Content/Additional" directory based on the values set in the Additional.json file.

	.PARAMETER ISO
		Creates a new bootable Windows Installation Media ISO based on the following boot-type values:

		Prompt: The efisys.bin binary bootcode is written to the ISO which requires a key press when booted to begin Windows Setup.
		No-Prompt: The efisys_noprompt.bin binary bootcode is written to the ISO which does not require a key press when booted and will begin Windows Setup automatically.

	.EXAMPLE
		Optimize-Offline -SourcePath "D:\Win10Pro\Win10Pro_Full.iso" -WindowsApps "Select" -SystemApps -Capabilities -Packages -Features -Win32Calc -Dedup -DaRT "Setup" -Registry -ISO "No-Prompt"

	.EXAMPLE
		Optimize-Offline -SourcePath "D:\Windows 10 ISOs\Win10ProForWorkstations_17663.iso" -WindowsApps "All" -SystemApps -Packages -Features -DaRT "All" -Additional -ISO "Prompt"

	.EXAMPLE
		Optimize-Offline -SourcePath "D:\Win Images\install.wim" -WindowsApps "Whitelist" -SystemApps -Capabilities -Features -Dedup -Registry -DaRT "Recovery" -Additional

	.EXAMPLE
		Optimize-Offline -SourcePath "D:\Win10 LTSC 2019\install.wim" -WindowsStore -MicrosoftEdge

	.NOTES
		Integration of Windows Store and Microsoft Edge are only applicable to Windows 10 Enterprise LTSC 2019.
		Bootable ISO media creation requires a Windows Installation Media ISO being used as the SourcePath image.

	.INPUTS
		System.IO.FileInfo

	.INPUTS
		System.Collections.Specialized.OrderedDictionary

	.LINK
		https://github.com/DrEmpiricism/Optimize-Offline/blob/master/README.md
	#>

	[CmdletBinding(HelpUri = 'https://github.com/DrEmpiricism/Optimize-Offline/blob/master/README.md')]
	Param
	(
		[Parameter(Mandatory = $true,
			HelpMessage = 'The path to a Windows 10 Installation Media ISO or a Windows image install WIM.')]
		[ValidateScript({
				If ((Test-Path -Path (Resolve-Path -Path $PSItem).Path) -and ($PSItem -ilike "*.iso")) { $PSItem }
				ElseIf ((Test-Path -Path (Resolve-Path -Path $PSItem).Path) -and ($PSItem -ilike "*.wim")) { $PSItem }
				Else { Write-Warning ('Invalid source path: "{0}"' -f $($PSItem)); Break }
			})]
		[IO.FileInfo]$SourcePath,
		[Parameter(Mandatory = $false,
			HelpMessage = 'Removes Provisioned Windows App Packages (.appx) selectively or automatically.')]
		[ValidateSet('Select', 'Whitelist', 'All')]
		[String]$WindowsApps,
		[Parameter(HelpMessage = 'Populates and outputs a Gridview list of System Apps for selective removal.')]
		[Switch]$SystemApps,
		[Parameter(HelpMessage = 'Populates and outputs a Gridview list of Capability Packages for selective removal.')]
		[Switch]$Capabilities,
		[Parameter(HelpMessage = 'Populates and outputs a Gridview list of Windows Cabinet File Packages for selective removal.')]
		[Switch]$Packages,
		[Parameter(HelpMessage = 'Populates and outputs a Gridview list of Windows Optional Features for selective disabling and enabling.')]
		[Switch]$Features,
		[Parameter(HelpMessage = 'Integrates the Developer Mode Feature into the image.')]
		[Switch]$DeveloperMode,
		[Parameter(HelpMessage = 'Integrates the Microsoft Windows Store and its required dependencies into the image.')]
		[Switch]$WindowsStore,
		[Parameter(HelpMessage = 'Integrates the Microsoft Edge Browser into the image.')]
		[Switch]$MicrosoftEdge,
		[Parameter(HelpMessage = 'Integrates the traditional Win32 Calculator into the image.')]
		[Switch]$Win32Calc,
		[Parameter(HelpMessage = 'Integrates the Windows Server Data Deduplication Feature into the image.')]
		[Switch]$Dedup,
		[Parameter(Mandatory = $false,
			HelpMessage = 'Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools into Windows Setup and Windows Recovery.')]
		[ValidateSet('Setup', 'Recovery', 'All')]
		[String]$DaRT,
		[Parameter(HelpMessage = 'Applies optimized settings into the image registry hives.')]
		[Switch]$Registry,
		[Parameter(HelpMessage = 'Integrates user-specific content in the "Content/Additional" directory based on the values set in the Additional.json file.')]
		[Switch]$Additional,
		[Parameter(Mandatory = $false,
			HelpMessage = 'Creates a new bootable Windows Installation Media ISO.')]
		[ValidateSet('Prompt', 'No-Prompt')]
		[String]$ISO
	)

	#region Local Variables
	$DefaultVariables = (Get-Variable).Name
	$ProgressPreference = 'SilentlyContinue'
	$Host.UI.RawUI.BackgroundColor = 'Black'; Clear-Host
	#endregion Local Variables

	#region Import Localized Data
	Try { Import-LocalizedData -BindingVariable OptimizedData -FileName Optimize-Offline.strings.psd1 -ErrorAction Stop }
	Catch { Write-Warning ('Failed to import the localized data file: "{0}"' -f (Split-Path -Path $OptimizeOffline.LocalizedDataStrings -Leaf)); Break }
	#endregion Import Localized Data

	#region Create the Working File Structure
	Test-Requirements

	If (Get-WindowsImage -Mounted)
	{
		$Host.UI.RawUI.WindowTitle = $OptimizedData.ActiveMountPoints
		Write-Host $OptimizedData.ActiveMountPoints -ForegroundColor Cyan
		Dismount-Images; Clear-Host
	}

	Try
	{
		Set-Location -Path $OptimizeOffline.Directory
		[Void](Clear-WindowsCorruptMountPoint)
		Get-ChildItem -Path $OptimizeOffline.Directory -Filter OfflineTemp_* -Directory | Purge
		@($TempDirectory, $ImageFolder, $WorkFolder, $ScratchFolder, $LogFolder) | Create
		$Timer = New-Object -TypeName System.Diagnostics.Stopwatch
	}
	Catch
	{
		Write-Warning $PSItem.Exception.Message
		Get-ChildItem -Path $OptimizeOffline.Directory -Filter OfflineTemp_* -Directory | Purge
		Break
	}
	#endregion Create the Working File Structure

	#region Media Export
	If ($SourcePath.Extension -eq '.ISO')
	{
		$ISOMount = (Mount-DiskImage -ImagePath $SourcePath.FullName -StorageType ISO -PassThru | Get-Volume).DriveLetter + ':'
		[Void](Get-PSDrive)
		If (!(Test-Path -Path "$ISOMount\sources\install.wim"))
		{
			Write-Warning ($OptimizedData.InvalidWindowsInstallMedia -f $SourcePath.Name)
			[Void](Dismount-DiskImage -ImagePath $SourcePath.FullName)
			$TempDirectory | Purge
			Break
		}
		Else
		{
			$Host.UI.RawUI.WindowTitle = ($OptimizedData.ExportingMedia -f $SourcePath.Name)
			Write-Host ($OptimizedData.ExportingMedia -f $SourcePath.Name) -ForegroundColor Cyan
			$ISOMedia = Create -Path (Join-Path -Path $TempDirectory -ChildPath $SourcePath.BaseName) -PassThru
			$ISOMedia | Export-Clixml -Path (Join-Path -Path $WorkFolder -ChildPath ISOMedia.xml) -Force
			$DynamicParams.ISOMedia = $true
			ForEach ($Item In Get-ChildItem -Path $ISOMount -Recurse)
			{
				$ISOExport = $ISOMedia.FullName + $Item.FullName.Replace($ISOMount, $null)
				Copy-Item -Path $Item.FullName -Destination $ISOExport
			}
			Get-ChildItem -Path "$($ISOMedia.FullName)\sources" -Include install.wim, boot.wim -Recurse | Move-Item -Destination $ImageFolder -PassThru | Set-ItemProperty -Name IsReadOnly -Value $false
			$InstallWim = Get-ChildItem -Path $ImageFolder -Filter install.wim | Select-Object -ExpandProperty FullName
			$BootWim = Get-ChildItem -Path $ImageFolder -Filter boot.wim | Select-Object -ExpandProperty FullName
			If ($BootWim) { $DynamicParams.Boot = $true }
			[Void](Dismount-DiskImage -ImagePath $SourcePath.FullName)
		}
	}
	ElseIf ($SourcePath.Extension -eq '.WIM')
	{
		$Host.UI.RawUI.WindowTitle = ($OptimizedData.CopyingWIM -f $SourcePath.DirectoryName)
		Write-Host ($OptimizedData.CopyingWIM -f $SourcePath.DirectoryName) -ForegroundColor Cyan
		Copy-Item -Path $SourcePath.FullName -Destination $ImageFolder
		Get-ChildItem -Path $ImageFolder -Filter $SourcePath.Name | Rename-Item -NewName install.wim -PassThru | Set-ItemProperty -Name IsReadOnly -Value $false
		$InstallWim = Get-ChildItem -Path $ImageFolder -Filter install.wim | Select-Object -ExpandProperty FullName
		If ($ISO) { Remove-Variable -Name ISO }
	}
	#endregion Media Export

	#region Image Metadata and Validation
	If ((Get-WindowsImage -ImagePath $InstallWim).Count -gt 1)
	{
		Do
		{
			$Host.UI.RawUI.WindowTitle = $OptimizedData.SelectWindows10Edition
			$EditionList = Get-WindowsImage -ImagePath $InstallWim | Select-Object -Property @{ Label = 'Index'; Expression = { ($PSItem.ImageIndex) } }, @{ Label = 'Name'; Expression = { ($PSItem.ImageName) } }, @{ Label = 'Size (GB)'; Expression = { '{0:N2}' -f ($PSItem.ImageSize / 1GB) } } | Out-GridView -Title "Select the Windows 10 Edition to Optimize." -OutputMode Single
			$ImageIndex = $EditionList.Index
		}
		While ($EditionList.Length -eq 0)
		$Host.UI.RawUI.WindowTitle = $null
	}
	Else { $ImageIndex = 1 }

	Try
	{
		$InstallInfo = WimData -WimFile $InstallWim -Index $ImageIndex
		$InstallInfo | Export-Clixml -Path (Join-Path -Path $WorkFolder -ChildPath InstallInfo.xml) -Force
	}
	Catch
	{
		Write-Warning $OptimizedData.FailedToRetrieveMetadata
		$TempDirectory | Purge
		Break
	}

	If (!$InstallInfo.Version.StartsWith(10))
	{
		Write-Warning ($OptimizedData.UnsupportedImageVersion -f $InstallInfo.Version)
		$TempDirectory | Purge
		Break
	}

	If ($InstallInfo.Architecture -ne 'amd64')
	{
		Write-Warning ($OptimizedData.UnsupportedImageArch -f $InstallInfo.Architecture)
		$TempDirectory | Purge
		Break
	}

	If ($InstallInfo.InstallationType.Contains('Server') -or $InstallInfo.InstallationType.Contains('WindowsPE'))
	{
		Write-Warning ($OptimizedData.UnsupportedImageType -f $InstallInfo.InstallationType)
		$TempDirectory | Purge
		Break
	}

	If ($InstallInfo.Build -ge '17134' -and $InstallInfo.Build -le '18362')
	{
		If ($InstallInfo.Build -eq '18362' -and $InstallInfo.Language -ne 'en-US' -and $MicrosoftEdge) { Remove-Variable -Name MicrosoftEdge }
		If ($InstallInfo.Build -lt '17763' -and $MicrosoftEdge) { Remove-Variable -Name MicrosoftEdge }
		If ($InstallInfo.Build -eq '17134' -and $DeveloperMode) { Remove-Variable -Name DeveloperMode }
		If ($InstallInfo.Language -ne 'en-US' -and $Win32Calc) { Remove-Variable -Name Win32Calc }
		If ($InstallInfo.Build -gt '17134' -and $InstallInfo.Language -ne 'en-US' -and $Dedup) { Remove-Variable -Name Dedup }
		If ($InstallInfo.Language -ne 'en-US' -and $DaRT) { Remove-Variable -Name DaRT }
		If ($InstallInfo.Name -like "*LTSC*")
		{
			$DynamicParams.LTSC = $true
			If ($WindowsApps) { Remove-Variable -Name WindowsApps }
			If ($Win32Calc) { Remove-Variable -Name Win32Calc }
		}
		Else
		{
			If ($WindowsStore) { Remove-Variable -Name WindowsStore }
			If ($MicrosoftEdge) { Remove-Variable -Name MicrosoftEdge }
		}
	}
	Else
	{
		Write-Warning ($OptimizedData.UnsupportedImageBuild -f $InstallInfo.Build)
		$TempDirectory | Purge
		Break
	}
	#endregion Image Metadata and Validation

	#region Image Preparation
	Try
	{
		"$Env:SystemRoot\Logs\DISM\dism.log" | Purge
		Log -Info ($OptimizedData.SupportedImageBuild -f $InstallInfo.Build)
		Start-Sleep 3; $Timer.Start(); $Error.Clear()
		$InstallMount | Create
		$MountInstallParams = @{
			ImagePath        = $InstallWim
			Index            = $ImageIndex
			Path             = $InstallMount
			ScratchDirectory = $ScratchFolder
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		Log -Info ($OptimizedData.MountingImage -f $InstallInfo.Name)
		[Void](Mount-WindowsImage @MountInstallParams)
	}
	Catch
	{
		Log -Error ($OptimizedData.FailedMountingImage -f $InstallInfo.Name, $(FormatError))
		Stop
	}

	If (Test-Path -Path (Join-Path -Path $InstallMount -ChildPath 'Windows\System32\Recovery\winre.wim'))
	{
		$WinREPath = Join-Path -Path $InstallMount -ChildPath 'Windows\System32\Recovery\winre.wim'
		Copy-Item -Path $WinREPath -Destination $ImageFolder -Force
		$RecoveryWim = Get-ChildItem -Path $ImageFolder -Filter winre.wim | Select-Object -ExpandProperty FullName
		$DynamicParams.Recovery = $true
	}

	If ($DynamicParams.Boot)
	{
		$BootInfo = WimData -WimFile $BootWim -Index 2
		Try
		{
			$BootMount | Create
			$MountBootParams = @{
				Path             = $BootMount
				ImagePath        = $BootWim
				Index            = 2
				ScratchDirectory = $ScratchFolder
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			Log -Info ($OptimizedData.MountingImage -f $BootInfo.Name)
			[Void](Mount-WindowsImage @MountBootParams)
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedMountingImage -f $BootInfo.Name, $(FormatError))
			Stop
		}
	}

	If ($DynamicParams.Recovery)
	{
		$RecoveryInfo = WimData -WimFile $RecoveryWim -Index 1
		Try
		{
			$RecoveryMount | Create
			$MountRecoveryParams = @{
				Path             = $RecoveryMount
				ImagePath        = $RecoveryWim
				Index            = 1
				ScratchDirectory = $ScratchFolder
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			Log -Info ($OptimizedData.MountingImage -f $RecoveryInfo.Name)
			[Void](Mount-WindowsImage @MountRecoveryParams)
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedMountingImage -f $RecoveryInfo.Name, $(FormatError))
			Stop
		}
	}

	If ((Repair-WindowsImage -Path $InstallMount -CheckHealth).ImageHealthState -eq 'Healthy')
	{
		Log -Info $OptimizedData.PreOptimizedImageHealthHealthy
		Start-Sleep 3; Clear-Host
	}
	Else
	{
		Log -Error $OptimizedData.PreOptimizedImageHealthCorrupted
		Stop
	}
	#endregion Image Preparation

	#region Provisioned App Package Removal
	If ($WindowsApps -and (Get-AppxProvisionedPackage -Path $InstallMount).Count -gt 0)
	{
		$RemovedAppxPackages = [Collections.Generic.List[Object]]::New()
		Switch ($PSBoundParameters.WindowsApps)
		{
			'Select'
			{
				$Host.UI.RawUI.WindowTitle = "Remove Provisioned App Packages."
				$AppxPackages = Get-AppxProvisionedPackage -Path $InstallMount | Select-Object -Property DisplayName, PackageName | Sort-Object -Property DisplayName | Out-GridView -Title "Remove Provisioned App Packages." -PassThru
				If ($AppxPackages)
				{
					Try
					{
						$AppxPackages | ForEach-Object -Process {
							$RemoveAppxParams = @{
								Path             = $InstallMount
								PackageName      = $PSItem.PackageName
								ScratchDirectory = $ScratchFolder
								LogPath          = $DISMLog
								ErrorAction      = 'Stop'
							}
							Log -Info ($OptimizedData.RemovingWindowsApp -f $PSItem.DisplayName)
							[Void](Remove-AppxProvisionedPackage @RemoveAppxParams)
							$RemovedAppxPackages.Add($PSItem.DisplayName)
							$RemovedAppxPackages.Add($PSItem.PackageName)
						}
					}
					Catch
					{
						Log -Error ($OptimizedData.FailedRemovingWindowsApps -f $(FormatError))
						Stop
					}
				}
			}
			'Whitelist'
			{
				If (Test-Path -Path $ContentPath.AppxWhitelist)
				{
					Try
					{
						$WhitelistJSON = Get-Content -Path $ContentPath.AppxWhitelist -Raw | ConvertFrom-Json
						Get-AppxProvisionedPackage -Path $InstallMount | ForEach-Object -Process {
							If ($PSItem.DisplayName -notin $WhitelistJSON.DisplayName)
							{
								$RemoveAppxParams = @{
									Path             = $InstallMount
									PackageName      = $PSItem.PackageName
									ScratchDirectory = $ScratchFolder
									LogPath          = $DISMLog
									ErrorAction      = 'Stop'
								}
								Log -Info ($OptimizedData.RemovingWindowsApp -f $PSItem.DisplayName)
								[Void](Remove-AppxProvisionedPackage @RemoveAppxParams)
								$RemovedAppxPackages.Add($PSItem.DisplayName)
								$RemovedAppxPackages.Add($PSItem.PackageName)
							}
						}
					}
					Catch
					{
						Log -Error ($OptimizedData.FailedRemovingWindowsApps -f $(FormatError))
						Stop
					}
				}
			}
			'All'
			{
				Try
				{
					Get-AppxProvisionedPackage -Path $InstallMount | ForEach-Object -Process {
						$RemoveAppxParams = @{
							Path             = $InstallMount
							PackageName      = $PSItem.PackageName
							ScratchDirectory = $ScratchFolder
							LogPath          = $DISMLog
							ErrorAction      = 'Stop'
						}
						Log -Info ($OptimizedData.RemovingWindowsApp -f $PSItem.DisplayName)
						[Void](Remove-AppxProvisionedPackage @RemoveAppxParams)
						$RemovedAppxPackages.Add($PSItem.DisplayName)
					}
				}
				Catch
				{
					Log -Error ($OptimizedData.FailedRemovingWindowsApps -f $(FormatError))
					Stop
				}
			}
		}
		$DynamicParams.WindowsApps = $WindowsApps; Clear-Host
		$Host.UI.RawUI.WindowTitle = $null
	}
	#endregion Provisioned App Package Removal

	#region System App Removal
	If ($SystemApps.IsPresent)
	{
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Remove System Apps."
		Write-Warning $OptimizedData.SystemAppsWarning
		Start-Sleep 5
		$InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
		RegHives -Load
		$InboxAppsPackages = Get-ChildItem -Path $InboxAppsKey -Name | ForEach-Object -Process {
			$Name = $PSItem.Split('_')[0]
			$PackageName = $PSItem
			If ($Name -like '1527c705-839a-4832-9118-54d4Bd6a0c89') { $Name = 'Microsoft.Windows.FilePicker' }
			If ($Name -like 'c5e2524a-ea46-4f67-841f-6a9465d9d515') { $Name = 'Microsoft.Windows.FileExplorer' }
			If ($Name -like 'E2A4F912-2574-4A75-9BB0-0D023378592B') { $Name = 'Microsoft.Windows.AppResolverUX' }
			If ($Name -like 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE') { $Name = 'Microsoft.Windows.AddSuggestedFoldersToLibarayDialog' }
			[PSCustomObject]@{
				Name        = $Name
				PackageName = $PackageName
			}
		} | Sort-Object -Property Name | Out-GridView -Title "Remove System Apps." -PassThru
		If ($InboxAppsPackages)
		{
			Clear-Host
			$RemovedSystemApps = [Collections.Generic.List[Object]]::New()
			Try
			{
				$InboxAppsPackages | ForEach-Object -Process {
					$PackageKey = (Join-Path -Path $InboxAppsKey -ChildPath $PSItem.PackageName) -replace 'HKLM:', 'HKLM'
					Log -Info ($OptimizedData.RemovingSystemApp -f $PSItem.Name)
					$RET = StartExe $REG -Arguments ('DELETE "{0}" /F' -f $PackageKey)
					If ($RET -eq 1) { Log -Error ($OptimizedData.FailedRemovingSystemApp -f $PSItem.Name); Return }
					$RemovedSystemApps.Add($PSItem.Name)
					Start-Sleep 2
				}
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedRemovingSystemApps -f $(FormatError))
				Stop
			}
			Finally
			{
				RegHives -Unload
			}
			$DynamicParams.SystemApps = $true; RegHives -Unload; Clear-Host
			$Host.UI.RawUI.WindowTitle = $null
		}
	}
	#endregion System App Removal

	#region Removed Package Clean-up
	If ($DynamicParams.WindowsApps -or $DynamicParams.SystemApps)
	{
		Try
		{
			Log -Info $OptimizedData.RemovePackageCleanup
			If ($DynamicParams.WindowsApps)
			{
				If ((Get-AppxProvisionedPackage -Path $InstallMount).Count -eq 0) { Get-ChildItem -Path "$InstallMount\Program Files\WindowsApps" -Force | Purge -Force }
				Else { Get-ChildItem -Path "$InstallMount\Program Files\WindowsApps" -Force | Where-Object -Property Name -In $RemovedAppxPackages | Purge -Force }
			}
			$Visibility = [Text.StringBuilder]::New(); [Void]$Visibility.Append('hide:')
			RegHives -Load
			If ($RemovedAppxPackages -contains 'Microsoft.WindowsMaps')
			{
				RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0 -Type DWord
				If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord }
				[Void]$Visibility.Append('maps;maps-downloadmaps;')
			}
			If ($RemovedAppxPackages -contains 'Microsoft.Wallet' -and (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService")) { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord }
			If ($RemovedAppxPackages -contains 'Microsoft.Windows.Photos')
			{
				@('.bmp', '.cr2', '.dib', '.gif', '.ico', '.jfif', '.jpe', '.jpeg', '.jpg', '.jxr', '.png', '.tif', '.tiff', '.wdp') | ForEach-Object -Process {
					RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($PSItem)" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String
					RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($PSItem)\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value 0 -Type Binary
				}
				@('Paint.Picture', 'giffile', 'jpegfile', 'pngfile') | ForEach-Object -Process {
					RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($PSItem)\shell\open" -Name "MuiVerb" -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" -Type ExpandString
					RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($PSItem)\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type ExpandString
				}
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043" -Type String
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type ExpandString
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Type String
			}
			If ($RemovedAppxPackages -like "*Xbox*" -or $RemovedSystemApps -contains 'Microsoft.XboxGameCallableUI')
			{
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord
				@("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach-Object -Process { If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($PSItem)") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($PSItem)" -Name "Start" -Value 4 -Type DWord } }
				[Void]$Visibility.Append('gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking;quietmomentsgame;')
				If ($InstallInfo.Build -lt '17763') { [Void]$Visibility.Append('gaming-trueplay;') }
			}
			If ($RemovedAppxPackages -contains 'Microsoft.YourPhone' -or $RemovedSystemApps -contains 'Microsoft.Windows.CallingShellApp')
			{
				[Void]$Visibility.Append('mobile-devices;mobile-devices-addphone;mobile-devices-addphone-direct;')
				If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\PhoneSvc") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\PhoneSvc" -Name "Start" -Value 4 -Type DWord }
			}
			If ($RemovedSystemApps -contains 'Microsoft.BioEnrollment')
			{
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" -Name "Enabled" -Value 0 -Type DWord
				If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc" -Name "Start" -Value 4 -Type DWord }
			}
			If ($RemovedSystemApps -contains 'Microsoft.Windows.SecureAssessmentBrowser')
			{
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord
			}
			If ($RemovedSystemApps -contains 'Microsoft.Windows.ContentDeliveryManager')
			{
				@("SubscribedContent-202914Enabled", "SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled",
					"SubscribedContent-310091Enabled", "SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314381Enabled", "SubscribedContent-314559Enabled",
					"SubscribedContent-314563Enabled", "SubscribedContent-338380Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled",
					"SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled", "SubscribedContent-353698Enabled", "SubscribedContent-8800010Enabled",
					"ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RemediationRequired",
					"RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContentEnabled") | ForEach-Object -Process { RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $($PSItem) -Value 0 -Type DWord }
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
			}
			If ($RemovedSystemApps -contains 'Microsoft.Windows.SecHealthUI')
			{
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Name "Notification_Suppress" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AppAndBrowser_EdgeSmartScreenOff" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "SmartScreenEnabled" -Value "Off" -Type String
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord
				@("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach-Object -Process { If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($PSItem)") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($PSItem)" -Name "Start" -Value 4 -Type DWord } }
				@("HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP", "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderApiLogger", "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderAuditLogger") | Purge
				Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force
				If (!$DynamicParams.LTSC)
				{
					RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord
					RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord
				}
				If ($InstallInfo.Build -ge '17763')
				{
					RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControlEnabled" -Value 1 -Type DWord
					RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControl" -Value "Anywhere" -Type String
				}
				RegHives -Unload
				If (Get-WindowsOptionalFeature -Path $InstallMount -FeatureName Windows-Defender-Default-Definitions | Where-Object -Property State -EQ Enabled)
				{
					Log -Info $OptimizedData.DisablingDefenderOptionalFeature
					[Void](Disable-WindowsOptionalFeature -Path $InstallMount -FeatureName Windows-Defender-Default-Definitions -Remove -NoRestart -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
				}
				[Void]$Visibility.Append('windowsdefender;')
				$DynamicParams.SecHealthUI = $true
			}
			If ($Visibility.Length -gt 5)
			{
				If (!(RegHives -Test)) { RegHives -Load }
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value $Visibility.ToString().TrimEnd(';') -Type String
				RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value $Visibility.ToString().TrimEnd(';') -Type String
			}
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedRemovePackageCleanup -f $(FormatError))
			Stop
		}
		Finally
		{
			If (RegHives -Test) { RegHives -Unload }
		}
	}
	#endregion Removed Package Clean-up

	#region Import Custom App Associations
	If (Test-Path -Path $ContentPath.CustomAppAssociations)
	{
		Log -Info $OptimizedData.ImportingCustomAppAssociations
		$RET = StartExe $DISM -Arguments ('/Image:"{0}" /Import-DefaultAppAssociations:"{1}"' -f $InstallMount, $ContentPath.CustomAppAssociations)
		If ($RET -ne 0) { Log -Error $OptimizedData.FailedImportingCustomAppAssociations; Start-Sleep 3 }
	}
	#endregion Import Custom App Associations

	#region Windows Capability and Cabinet File Package Removal
	If ($Capabilities.IsPresent)
	{
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Remove Windows Capabilities."
		$WindowsCapabilities = Get-WindowsCapability -Path $InstallMount | Where-Object { $PSItem.Name -notlike "*Language.Basic*" -and $PSItem.Name -notlike "*TextToSpeech*" -and $PSItem.State -eq 'Installed' } | Select-Object -Property Name, State | Sort-Object -Property Name | Out-GridView -Title "Remove Windows Capabilities." -PassThru
		If ($WindowsCapabilities)
		{
			Try
			{
				$WindowsCapabilities | ForEach-Object -Process {
					$RemoveCapabilityParams = @{
						Path             = $InstallMount
						Name             = $PSItem.Name
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					Log -Info ($OptimizedData.RemovingWindowsCapability -f $PSItem.Name.Split('~')[0])
					[Void](Remove-WindowsCapability @RemoveCapabilityParams)
				}
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedRemovingWindowsCapabilities -f $(FormatError))
				Stop
			}
			$DynamicParams.Capabilities = $true; Clear-Host
			$Host.UI.RawUI.WindowTitle = $null
		}
	}

	If ($Packages.IsPresent)
	{
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Remove Windows Packages."
		$WindowsPackages = Get-WindowsPackage -Path $InstallMount | Where-Object { $PSItem.PackageName -notlike "*LanguageFeatures-Basic*" -and $PSItem.PackageName -notlike "*LanguageFeatures-TextToSpeech*" -and $PSItem.ReleaseType -eq 'OnDemandPack' -or $PSItem.ReleaseType -eq 'LanguagePack' -or $PSItem.ReleaseType -eq 'FeaturePack' -and $PSItem.PackageState -eq 'Installed' } | Select-Object -Property PackageName, ReleaseType | Sort-Object -Property ReleaseType | Out-GridView -Title "Remove Windows Packages." -PassThru
		If ($WindowsPackages)
		{
			Try
			{
				$WindowsPackages | ForEach-Object -Process {
					$RemovePackageParams = @{
						Path             = $InstallMount
						PackageName      = $PSItem.PackageName
						NoRestart        = $true
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					Log -Info ($OptimizedData.RemovingWindowsPackage -f $PSItem.PackageName.Replace('Package', $null).Split('~')[0].TrimEnd('-'))
					[Void](Remove-WindowsPackage @RemovePackageParams)
				}
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedRemovingWindowsPackages -f $(FormatError))
				Stop
			}
			$DynamicParams.Packages = $true; Clear-Host
			$Host.UI.RawUI.WindowTitle = $null
		}
	}
	#endregion Windows Capability and Cabinet File Package Removal

	#region Disable Unsafe Optional Features
	ForEach ($Feature In @('SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root'))
	{
		If (Get-WindowsOptionalFeature -Path $InstallMount -FeatureName $Feature | Where-Object -Property State -EQ Enabled)
		{
			Log -Info ($OptimizedData.DisablingUnsafeOptionalFeature -f $Feature)
			[Void](Disable-WindowsOptionalFeature -Path $InstallMount -FeatureName $Feature -Remove -NoRestart -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
		}
	}
	#endregion Disable Unsafe Optional Features

	#region Disable/Enable Optional Features
	If ($Features.IsPresent)
	{
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Disable Optional Features."
		$DisableFeatures = Get-WindowsOptionalFeature -Path $InstallMount | Where-Object State -EQ Enabled | Select-Object -Property FeatureName, State | Sort-Object -Property FeatureName | Out-GridView -Title "Disable Optional Features." -PassThru
		If ($DisableFeatures)
		{
			Try
			{
				$DisableFeatures | ForEach-Object -Process {
					$DisableFeatureParams = @{
						Path             = $InstallMount
						FeatureName      = $PSItem.FeatureName
						Remove           = $true
						NoRestart        = $true
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					Log -Info ($OptimizedData.DisablingOptionalFeature -f $PSItem.FeatureName)
					[Void](Disable-WindowsOptionalFeature @DisableFeatureParams)
				}
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedDisablingOptionalFeatures -f $(FormatError))
				Stop
			}
			$DynamicParams.DisabledOptionalFeatures = $true; Clear-Host
			$Host.UI.RawUI.WindowTitle = $null
		}
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Enable Optional Features."
		$EnableFeatures = Get-WindowsOptionalFeature -Path $InstallMount | Where-Object { $PSItem.FeatureName -notlike "SMB1Protocol*" -and $PSItem.FeatureName -ne "Windows-Defender-Default-Definitions" -and $PSItem.FeatureName -notlike "MicrosoftWindowsPowerShellV2*" -and $PSItem.State -eq "Disabled" } | Select-Object -Property FeatureName, State | Sort-Object -Property FeatureName | Out-GridView -Title "Enable Optional Features." -PassThru
		If ($EnableFeatures)
		{
			Try
			{
				$EnableFeatures | ForEach-Object -Process {
					$EnableFeatureParams = @{
						Path             = $InstallMount
						FeatureName      = $PSItem.FeatureName
						All              = $true
						LimitAccess      = $true
						NoRestart        = $true
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					Log -Info ($OptimizedData.EnablingOptionalFeature -f $PSItem.FeatureName)
					[Void](Enable-WindowsOptionalFeature @EnableFeatureParams)
				}
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedEnablingOptionalFeatures -f $(FormatError))
				Stop
			}
			$DynamicParams.EnabledOptionalFeatures = $true; Clear-Host
			$Host.UI.RawUI.WindowTitle = $null
		}
	}
	#endregion Disable/Enable Optional Features

	#region DeveloperMode Integration
	If ($DeveloperMode.IsPresent -and (Test-Path -Path $PackagePath.DevMode -Filter *DeveloperMode-Desktop-Package*.cab) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object -Property PackageName -Like *DeveloperMode*))
	{
		$DevModePackage = "$($PackagePath.DevMode)\Microsoft-OneCore-DeveloperMode-Desktop-Package~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab"
		$DevModeExpand = Create -Path (Join-Path -Path $WorkFolder -ChildPath DeveloperMode) -PassThru
		[Void](StartExe $EXPAND -Arguments ('"{0}" F:* "{1}"' -f $DevModePackage, $DevModeExpand.FullName))
		If (Test-Path -Path "$($DevModeExpand.FullName)\update.mum")
		{
			Log -Info $OptimizedData.IntegratingDeveloperMode
			$RET = StartExe $DISM -Arguments ('/Image:"{0}" /Add-Package /PackagePath:"{1}" /ScratchDir:"{2}" /LogPath:"{3}"' -f $InstallMount, "$($DevModeExpand.FullName)\update.mum", $ScratchFolder, $DISMLog)
			If ($RET -eq 0)
			{
				RegHives -Load
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Value 1 -Type DWord
				RegHives -Unload
				$DynamicParams.DeveloperMode = $true
			}
			Else { Log -Error $OptimizedData.FailedIntegratingDeveloperMode; Start-Sleep 3 }
		}
	}
	#endregion DeveloperMode Integration

	#region Windows Store Integration
	If ($WindowsStore.IsPresent -and (Test-Path -Path $PackagePath.WindowsStore -Filter Microsoft.WindowsStore*.appxbundle))
	{
		Log -Info $OptimizedData.IntegratingWindowsStore
		$StoreBundle = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.WindowsStore*.appxbundle -File | Select-Object -ExpandProperty FullName
		$PurchaseBundle = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.StorePurchaseApp*.appxbundle -File | Select-Object -ExpandProperty FullName
		$XboxBundle = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.XboxIdentityProvider*.appxbundle -File | Select-Object -ExpandProperty FullName
		$InstallerBundle = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.DesktopAppInstaller*.appxbundle -File | Select-Object -ExpandProperty FullName
		$StoreLicense = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.WindowsStore*.xml -File | Select-Object -ExpandProperty FullName
		$PurchaseLicense = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.StorePurchaseApp*.xml -File | Select-Object -ExpandProperty FullName
		$XboxLicense = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.XboxIdentityProvider*.xml -File | Select-Object -ExpandProperty FullName
		$InstallerLicense = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.DesktopAppInstaller*.xml -File | Select-Object -ExpandProperty FullName
		$DependencyPackages = Get-ChildItem -Path $PackagePath.WindowsStore -Filter Microsoft.VCLibs*.appx -File | Select-Object -ExpandProperty FullName
		$DependencyPackages += Get-ChildItem -Path $PackagePath.WindowsStore -Filter *Native.Framework*.appx -File | Select-Object -ExpandProperty FullName
		$DependencyPackages += Get-ChildItem -Path $PackagePath.WindowsStore -Filter *Native.Runtime*.appx -File | Select-Object -ExpandProperty FullName
		RegHives -Load
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord
		RegHives -Unload
		Try
		{
			$StorePackage = @{
				Path                  = $InstallMount
				PackagePath           = $StoreBundle
				DependencyPackagePath = $DependencyPackages
				LicensePath           = $StoreLicense
				ScratchDirectory      = $ScratchFolder
				LogPath               = $DISMLog
				ErrorAction           = 'Stop'
			}
			[Void](Add-AppxProvisionedPackage @StorePackage)
			$PurchasePackage = @{
				Path                  = $InstallMount
				PackagePath           = $PurchaseBundle
				DependencyPackagePath = $DependencyPackages
				LicensePath           = $PurchaseLicense
				ScratchDirectory      = $ScratchFolder
				LogPath               = $DISMLog
				ErrorAction           = 'Stop'
			}
			[Void](Add-AppxProvisionedPackage @PurchasePackage)
			$XboxPackage = @{
				Path                  = $InstallMount
				PackagePath           = $XboxBundle
				DependencyPackagePath = $DependencyPackages
				LicensePath           = $XboxLicense
				ScratchDirectory      = $ScratchFolder
				LogPath               = $DISMLog
				ErrorAction           = 'Stop'
			}
			[Void](Add-AppxProvisionedPackage @XboxPackage)
			$DependencyPackages.Clear()
			$DependencyPackages = Get-ChildItem -Path $PackagePath.WindowsStore -Filter *Native.Runtime*.appx -File | Select-Object -ExpandProperty FullName
			$InstallerPackage = @{
				Path                  = $InstallMount
				PackagePath           = $InstallerBundle
				DependencyPackagePath = $DependencyPackages
				LicensePath           = $InstallerLicense
				ScratchDirectory      = $ScratchFolder
				LogPath               = $DISMLog
				ErrorAction           = 'Stop'
			}
			[Void](Add-AppxProvisionedPackage @InstallerPackage)
			$DynamicParams.WindowsStore = $true
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedIntegratingWindowsStore -f $(FormatError))
			Stop
		}
		Finally
		{
			If (!$DynamicParams.DeveloperMode)
			{
				RegHives -Load
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 0 -Type DWord
				RegHives -Unload
			}
		}
	}
	#endregion Windows Store Integration

	#region Microsoft Edge Integration
	If ($MicrosoftEdge.IsPresent -and (Test-Path -Path $PackagePath.MicrosoftEdge -Filter Microsoft-Windows-Internet-Browser-Package*.cab) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *Internet-Browser*))
	{
		Try
		{
			Log -Info $OptimizedData.IntegratingMicrosoftEdge
			@("$($PackagePath.MicrosoftEdge)\Microsoft-Windows-Internet-Browser-Package~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab", "$($PackagePath.MicrosoftEdge)\Microsoft-Windows-Internet-Browser-Package~$($InstallInfo.Architecture)~$($InstallInfo.Language)~10.0.$($InstallInfo.Build).1.cab") | ForEach-Object -Process { [Void](Add-WindowsPackage -Path $InstallMount -PackagePath $PSItem -IgnoreCheck -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction Stop) }
			$DynamicParams.MicrosoftEdge = $true
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedIntegratingMicrosoftEdge -f $(FormatError))
			Start-Sleep 3
		}
		If ($DynamicParams.MicrosoftEdge)
		{
			RegHives -Load
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Value 0 -Type DWord
			If ($DynamicParams.SecHealthUI)
			{
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord
				RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord
			}
			RegHives -Unload
		}
	}
	#endregion Microsoft Edge Integration

	#region Win32 Calculator Integration
	If ($Win32Calc.IsPresent -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *win32calc*) -and (Test-Path -Path $PackagePath.Win32Calc -Filter Win32Calc.wim))
	{
		Try
		{
			Log -Info $OptimizedData.IntegratingWin32Calc
			$ExpandCalcParams = @{
				ImagePath        = "$($PackagePath.Win32Calc)\Win32Calc.wim"
				Index            = 1
				ApplyPath        = $InstallMount
				CheckIntegrity   = $true
				Verify           = $true
				ScratchDirectory = $ScratchFolder
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			[Void](Expand-WindowsImage @ExpandCalcParams)
			Add-Content -Path "$InstallMount\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini" -Value 'Calculator.lnk=@%SystemRoot%\System32\shell32.dll,-22019' -Encoding Unicode -Force
			$DynamicParams.Win32Calc = $true
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedIntegratingWin32Calc -f $(FormatError))
			Stop
		}
		If ($DynamicParams.Win32Calc)
		{
			RegHives -Load
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\RegisteredApplications" -Name "Windows Calculator" -Value "SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\RegisteredApplications" -Name "Windows Calculator" -Value "SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator" -Name "(default)" -Value "URL:calculator" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator" -Name "URL Protocol" -Value "" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -Name "(default)" -Value "C:\Windows\System32\win32calc.exe,0" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\win32calc.exe" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\InboxApp" -Name "56230F2FD0CC3EB4_Calculator_lnk_amd64.lnk" -Value "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk" -Type ExpandString -Force
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\App Management\WindowsFeatureCategories" -Name "COMMONSTART/Programs/Accessories/Calculator.lnk" -Value "SOFTWARE_CATEGORY_UTILITIES" -Type String -Force
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Management\WindowsFeatureCategories" -Name "COMMONSTART/Programs/Accessories/Calculator.lnk" -Value "SOFTWARE_CATEGORY_UTILITIES" -Type String -Force
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationName" -Value "%SystemRoot%\System32\win32calc.exe" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationName" -Value "%SystemRoot%\System32\win32calc.exe" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationDescription" -Value "%SystemRoot%\System32\win32calc.exe,-217" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationDescription" -Value "%SystemRoot%\System32\win32calc.exe,-217" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -Name "calculator" -Value "calculator" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -Name "calculator" -Value "calculator" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Debug" -Name "OwningPublisher" -Value "{75f48521-4131-4ac3-9887-65473224fcb2}" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Debug" -Name "Enabled" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Debug" -Name "Isolation" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Debug" -Name "ChannelAccess" -Value "O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Debug" -Name "Type" -Value 3 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Diagnostic" -Name "OwningPublisher" -Value "{75f48521-4131-4ac3-9887-65473224fcb2}" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Diagnostic" -Name "Enabled" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Diagnostic" -Name "Isolation" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Diagnostic" -Name "ChannelAccess" -Value "O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Diagnostic" -Name "Type" -Value 2 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}" -Name "(default)" -Value "Microsoft-Windows-Calculator" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}" -Name "ResourceFileName" -Value "%SystemRoot%\System32\win32calc.exe" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}" -Name "MessageFileName" -Value "%SystemRoot%\System32\win32calc.exe" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences" -Name "Count" -Value 2 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\0" -Name "(default)" -Value "Microsoft-Windows-Calculator/Diagnostic" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\0" -Name "Id" -Value 16 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\0" -Name "Flags" -Value 0 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\1" -Name "(default)" -Value "Microsoft-Windows-Calculator/Debug" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\1" -Name "Id" -Value 17 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\1" -Name "Flags" -Value 0 -Type DWord
			RegHives -Unload
		}
	}
	#endregion Win32 Calculator Integration

	#region Data Deduplication Integration
	If ($Dedup.IsPresent -and (Test-Path -Path $PackagePath.Dedup -Filter Microsoft-Windows-FileServer-ServerCore-Package*.cab) -and (Test-Path -Path $PackagePath.Dedup -Filter Microsoft-Windows-Dedup-Package*.cab) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *Windows-Dedup*) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *Windows-FileServer-ServerCore*))
	{
		Try
		{
			Log -Info $OptimizedData.IntegratingDataDedup
			@("$($PackagePath.Dedup)\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab", "$($PackagePath.Dedup)\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~$($InstallInfo.Language)~10.0.$($InstallInfo.Build).1.cab",
				"$($PackagePath.Dedup)\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab", "$($PackagePath.Dedup)\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~$($InstallInfo.Language)~10.0.$($InstallInfo.Build).1.cab") | ForEach-Object -Process { [Void](Add-WindowsPackage -Path $InstallMount -PackagePath $PSItem -IgnoreCheck -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction Stop) }
			$EnableDedup = @{
				Path             = $InstallMount
				FeatureName      = 'Dedup-Core'
				All              = $true
				LimitAccess      = $true
				NoRestart        = $true
				ScratchDirectory = $ScratchFolder
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			[Void](Enable-WindowsOptionalFeature @EnableDedup)
			$DynamicParams.DataDeduplication = $true
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedIntegratingDataDedup -f $(FormatError))
			Stop
		}
		If ($DynamicParams.DataDeduplication)
		{
			RegHives -Load
			RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" -Name "FileServer-ServerManager-DCOM-TCP-In" -Value "v2.29|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%systemroot%\\system32\\svchost.exe|Svc=RPCSS|Name=@fssmres.dll,-103|Desc=@fssmres.dll,-104|EmbedCtxt=@fssmres.dll,-100|" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" -Name "FileServer-ServerManager-SMB-TCP-In" -Value "v2.29|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=@fssmres.dll,-105|Desc=@fssmres.dll,-106|EmbedCtxt=@fssmres.dll,-100|" -Type String
			RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" -Name "FileServer-ServerManager-Winmgmt-TCP-In" -Value "v2.29|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%systemroot%\\system32\\svchost.exe|Svc=Winmgmt|Name=@fssmres.dll,-101|Desc=@fssmres.dll,-102|EmbedCtxt=@fssmres.dll,-100|" -Type String
			RegHives -Unload
		}
	}
	#endregion Data Deduplication Integration

	#region Microsoft DaRT 10 Integration
	If ($DaRT -and (Test-Path -Path $PackagePath.DaRT -Filter MSDaRT10_*.wim))
	{
		If ($InstallInfo.Build -eq '17134') { $CodeName = 'RS4' }
		ElseIf ($InstallInfo.Build -eq '17763') { $CodeName = 'RS5' }
		ElseIf ($InstallInfo.Build -eq '18362') { $CodeName = 'RS6' }
		Try
		{
			If ($PSBoundParameters.DaRT -eq 'Setup' -or $PSBoundParameters.DaRT -eq 'All' -and $DynamicParams.Boot)
			{
				Log -Info ($OptimizedData.IntegratingDaRT10 -f $CodeName, $BootInfo.Name)
				$ExpandDaRTBootParams = @{
					ImagePath        = "$($PackagePath.DaRT)\MSDaRT10_$($CodeName).wim"
					Index            = 1
					ApplyPath        = $BootMount
					CheckIntegrity   = $true
					Verify           = $true
					ScratchDirectory = $ScratchFolder
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Expand-WindowsImage @ExpandDaRTBootParams)
				If (!(Test-Path -Path "$BootMount\Windows\System32\fmapi.dll")) { Copy-Item -Path "$InstallMount\Windows\System32\fmapi.dll" -Destination "$BootMount\Windows\System32" -Force }
				@'
[LaunchApps]
%WINDIR%\System32\wpeinit.exe
%WINDIR%\System32\netstart.exe
%SYSTEMDRIVE%\setup.exe
'@ | Out-File -FilePath "$BootMount\Windows\System32\winpeshl.ini" -Force
			}
			If ($PSBoundParameters.DaRT -eq 'Recovery' -or $PSBoundParameters.DaRT -eq 'All' -and $DynamicParams.Recovery)
			{
				Log -Info ($OptimizedData.IntegratingDaRT10 -f $CodeName, $RecoveryInfo.Name)
				$ExpandDaRTRecoveryParams = @{
					ImagePath        = "$($PackagePath.DaRT)\MSDaRT10_$($CodeName).wim"
					Index            = 1
					ApplyPath        = $RecoveryMount
					CheckIntegrity   = $true
					Verify           = $true
					ScratchDirectory = $ScratchFolder
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Expand-WindowsImage @ExpandDaRTRecoveryParams)
				If (!(Test-Path -Path "$RecoveryMount\Windows\System32\fmapi.dll")) { Copy-Item -Path "$InstallMount\Windows\System32\fmapi.dll" -Destination "$RecoveryMount\Windows\System32" -Force }
				@'
[LaunchApps]
%WINDIR%\System32\wpeinit.exe
%WINDIR%\System32\netstart.exe
%SYSTEMDRIVE%\sources\recovery\recenv.exe
'@ | Out-File -FilePath "$RecoveryMount\Windows\System32\winpeshl.ini" -Force
			}
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedIntegratingDaRT10 -f $BootInfo.Name, $(FormatError))
		}
		Finally
		{
			Start-Sleep 3; Clear-Host
		}
	}
	#endregion Microsoft DaRT 10 Integration

	#region Apply Optimized Registry Settings
	If ($Registry.IsPresent)
	{
		Log -Info "Applying Optimized Registry Settings."
		Set-RegistryProperties
	}
	#endregion Apply Optimized Registry Settings

	#region Additional Content Integration
	If ($Additional.IsPresent -and (Test-Path -Path $AdditionalPath.AdditionalJSON))
	{
		$AdditionalParams = Import-AdditionalJSON
		If ($AdditionalParams.Setup -and (Test-Path -Path "$($AdditionalPath.Setup)\*"))
		{
			Log -Info $OptimizedData.ApplyingSetupContent
			"$InstallMount\Windows\Setup\Scripts" | Create
			Get-ChildItem -Path $AdditionalPath.Setup -Exclude RebootRecovery.png, RefreshExplorer.png, README.md | Copy-Item -Destination "$InstallMount\Windows\Setup\Scripts" -Recurse -Force -ErrorAction SilentlyContinue
			Start-Sleep 3
		}
		If ($AdditionalParams.Wallpaper -and (Test-Path -Path "$($AdditionalPath.Wallpaper)\*"))
		{
			Log -Info $OptimizedData.ApplyingWallpaper
			Get-ChildItem -Path $AdditionalPath.Wallpaper -Directory | Copy-Item -Destination "$InstallMount\Windows\Web\Wallpaper" -Recurse
			Get-ChildItem -Path "$($AdditionalPath.Wallpaper)\*" -Include *.jpg, *.png, *.bmp, *.gif -File | Copy-Item -Destination "$InstallMount\Windows\Web\Wallpaper" -Force -ErrorAction SilentlyContinue
			Start-Sleep 3
		}
		If ($AdditionalParams.SystemLogo -and (Test-Path -Path "$($AdditionalPath.SystemLogo)\*.bmp"))
		{
			Log -Info $OptimizedData.ApplyingSystemLogo
			"$InstallMount\Windows\System32\oobe\info\logo" | Create
			Copy-Item -Path "$($AdditionalPath.SystemLogo)\*.bmp" -Destination "$InstallMount\Windows\System32\oobe\info\logo" -Recurse -Force -ErrorAction SilentlyContinue
			Start-Sleep 3
		}
		If ($AdditionalParams.LockScreen -and (Test-Path -Path "$($AdditionalPath.LockScreen)\*.jpg"))
		{
			Log -Info $OptimizedData.ApplyingLockScreen
			Set-LockScreen
			Start-Sleep 3
		}
		If ($AdditionalParams.RegistryTemplates -and (Test-Path -Path "$($AdditionalPath.RegistryTemplates)\*.reg"))
		{
			Log -Info $OptimizedData.ImportingRegistryTemplates
			Import-RegistryTemplates
			Start-Sleep 3
		}
		If ($AdditionalParams.Unattend -and (Test-Path -Path "$($AdditionalPath.Unattend)\unattend.xml"))
		{
			Try
			{
				Log -Info $OptimizedData.ApplyingAnswerFile
				$ApplyUnattendParams = @{
					UnattendPath     = "$($AdditionalPath.Unattend)\unattend.xml"
					Path             = $InstallMount
					ScratchDirectory = $ScratchFolder
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Use-WindowsUnattend @ApplyUnattendParams)
				"$InstallMount\Windows\Panther" | Create
				Copy-Item -Path "$($AdditionalPath.Unattend)\unattend.xml" -Destination "$InstallMount\Windows\Panther" -Force -ErrorAction SilentlyContinue
				Start-Sleep 3
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedApplyingAnswerFile -f $(FormatError))
				"$InstallMount\Windows\Panther" | Purge
				Start-Sleep 3
			}
		}
		If ($AdditionalParams.Drivers)
		{
			If (Get-ChildItem -Path $AdditionalPath.InstallDrivers -Filter *.inf -Recurse)
			{
				Try
				{
					Log -Info ($OptimizedData.InjectingDriverPackages -f $InstallInfo.Name)
					Get-ChildItem -Path $AdditionalPath.InstallDrivers -Recurse -Force | ForEach-Object -Process { $PSItem.Attributes = 0x80 }
					$InstallDriverParams = @{
						Path             = $InstallMount
						Driver           = $AdditionalPath.InstallDrivers
						Recurse          = $true
						ForceUnsigned    = $true
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					[Void](Add-WindowsDriver @InstallDriverParams)
					$DynamicParams.InstallDrivers = $true
				}
				Catch
				{
					Log -Error ($OptimizedData.FailedInjectingDriverPackages -f $InstallInfo.Name, $(FormatError))
					Start-Sleep 3
				}
			}
			If ($DynamicParams.Boot -and (Get-ChildItem -Path $AdditionalPath.BootDrivers -Filter *.inf -Recurse))
			{
				Try
				{
					Log -Info ($OptimizedData.InjectingDriverPackages -f $BootInfo.Name)
					Get-ChildItem -Path $AdditionalPath.BootDrivers -Recurse -Force | ForEach-Object -Process { $PSItem.Attributes = 0x80 }
					$BootDriverParams = @{
						Path             = $BootMount
						Driver           = $AdditionalPath.BootDrivers
						Recurse          = $true
						ForceUnsigned    = $true
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					[Void](Add-WindowsDriver @BootDriverParams)
					$DynamicParams.BootDrivers = $true
				}
				Catch
				{
					Log -Error ($OptimizedData.FailedInjectingDriverPackages -f $BootInfo.Name, $(FormatError))
					Start-Sleep 3
				}
			}
			If ($DynamicParams.Recovery -and (Get-ChildItem -Path $AdditionalPath.RecoveryDrivers -Filter *.inf -Recurse))
			{
				Try
				{
					Log -Info ($OptimizedData.InjectingDriverPackages -f $RecoveryInfo.Name)
					Get-ChildItem -Path $AdditionalPath.RecoveryDrivers -Recurse -Force | ForEach-Object -Process { $PSItem.Attributes = 0x80 }
					$RecoveryDriverParams = @{
						Path             = $RecoveryMount
						Driver           = $AdditionalPath.RecoveryDrivers
						Recurse          = $true
						ForceUnsigned    = $true
						ScratchDirectory = $ScratchFolder
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					[Void](Add-WindowsDriver @RecoveryDriverParams)
					$DynamicParams.RecoveryDrivers = $true
				}
				Catch
				{
					Log -Error ($OptimizedData.FailedInjectingDriverPackages -f $RecoveryInfo.Name, $(FormatError))
					Start-Sleep 3
				}
			}
		}
		If ($AdditionalParams.NetFx3 -and $DynamicParams.ISOMedia -and (Get-WindowsOptionalFeature -Path $InstallMount -FeatureName NetFx3 | Where-Object -Property State -EQ DisabledWithPayloadRemoved) -and (Get-ChildItem -Path "$($ISOMedia.FullName)\sources\sxs" -Filter *netfx3*.cab -Recurse))
		{
			Try
			{
				Log -Info $OptimizedData.EnablingNetFx3
				$EnableNetFx3Params = @{
					Path             = $InstallMount
					FeatureName      = 'NetFx3'
					Source           = "$($ISOMedia.FullName)\sources\sxs"
					All              = $true
					LimitAccess      = $true
					NoRestart        = $true
					ScratchDirectory = $ScratchFolder
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Enable-WindowsOptionalFeature @EnableNetFx3Params)
				$DynamicParams.NetFx3 = $true
			}
			Catch
			{
				Log -Error ($OptimizedData.FailedEnablingNetFx3 -f $(FormatError))
				Start-Sleep 3
			}
		}
	}
	#endregion Additional Content Integration

	#region Image Finalization and Log and Media Creation
	Try
	{
		Log -Info $OptimizedData.CleanupStartMenu
		$LayoutModTemplate = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupsColumnCount="2" StartTileGroupCellWidth="6" FullScreenStart="false" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6">
                <start:Group Name="$($InstallInfo.Name)">
                    <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationID="Microsoft.Windows.Computer" />
                    <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationID="Microsoft.Windows.ControlPanel" />
                    <start:DesktopApplicationTile Size="1x1" Column="4" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" />
                    <start:DesktopApplicationTile Size="1x1" Column="4" Row="1" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk" />
                    <start:DesktopApplicationTile Size="1x1" Column="5" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\UWP File Explorer.lnk" />
                    <start:DesktopApplicationTile Size="1x1" Column="5" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk" />
                </start:Group>
            </defaultlayout:StartLayout>
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
		If ($RemovedSystemApps -contains 'Microsoft.Windows.FileExplorer') { $LayoutModTemplate = $LayoutModTemplate -replace 'UWP File Explorer.lnk', 'File Explorer.lnk' }
		Else
		{
			$UWPShell = New-Object -ComObject WScript.Shell
			$UWPShortcut = $UWPShell.CreateShortcut("$InstallMount\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\UWP File Explorer.lnk")
			$UWPShortcut.TargetPath = "%SystemRoot%\explorer.exe"
			$UWPShortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
			$UWPShortcut.WorkingDirectory = "%SystemRoot%"
			$UWPShortcut.Description = "UWP File Explorer"
			$UWPShortcut.Save()
			[Void][Runtime.InteropServices.Marshal]::ReleaseComObject($UWPShell)
		}
		$LayoutModTemplate | Out-File -FilePath "$InstallMount\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Encoding UTF8 -Force
	}
	Finally
	{
		Start-Sleep 3; Clear-Host
	}

	If ($DynamicParams.Count -gt 0)
	{
		Log -Info $OptimizedData.CreatingPackageSummaryLog
		$PackageLog = New-Item -Path $PackageLog -ItemType File
		If ($DynamicParams.WindowsStore) { "`tIntegrated Provisioned App Packages", (Get-AppxProvisionedPackage -Path $InstallMount | Select-Object -Property PackageName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
		If ($DynamicParams.DeveloperMode -or $DynamicParams.MicrosoftEdge -or $DynamicParams.DataDeduplication -or $DynamicParams.NetFx3) { "`tIntegrated Windows Packages", (Get-WindowsPackage -Path $InstallMount | Where-Object { $PSItem.PackageName -like "*DeveloperMode*" -or $PSItem.PackageName -like "*Internet-Browser*" -or $PSItem.PackageName -like "*Windows-FileServer-ServerCore*" -or $PSItem.PackageName -like "*Windows-Dedup*" -or $PSItem.PackageName -like "*NetFx3*" } | Select-Object -Property PackageName, PackageState) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
		If ($DynamicParams.InstallDrivers) { "`tIntegrated Drivers (Install)", (Get-WindowsDriver -Path $InstallMount | Select-Object -Property ProviderName, ClassName, BootCritical, Date, Version | Sort-Object -Property ProviderName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
		If ($DynamicParams.BootDrivers) { "`tIntegrated Drivers (Boot)", (Get-WindowsDriver -Path $BootMount | Select-Object -Property ProviderName, ClassName, BootCritical, Date, Version | Sort-Object -Property ProviderName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
		If ($DynamicParams.RecoveryDrivers) { "`tIntegrated Drivers (Recovery)", (Get-WindowsDriver -Path $RecoveryMount | Select-Object -Property ProviderName, ClassName, BootCritical, Date, Version | Sort-Object -Property ProviderName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
	}

	If ((Repair-WindowsImage -Path $InstallMount -CheckHealth).ImageHealthState -eq 'Healthy')
	{
		Log -Info $OptimizedData.PostOptimizedImageHealthHealthy
		@"
This $($InstallInfo.Name) installation was optimized with $($ManifestData.ModuleName) version $($ManifestData.ModuleVersion)
on $(Get-Date -UFormat "%m/%d/%Y at %r")
"@ | Out-File -FilePath (Join-Path -Path $InstallMount -ChildPath Optimize-Offline.txt) -Encoding Unicode -Force
		Start-Sleep 3
	}
	Else
	{
		Log -Error $OptimizedData.PostOptimizedImageHealthCorrupted
		Stop
	}

	If ($DynamicParams.Boot)
	{
		Try
		{
			Cleanup -Boot
			$DismountBootParams = @{
				Path             = $BootMount
				Save             = $true
				ScratchDirectory = $ScratchFolder
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			Log -Info ($OptimizedData.SavingDismountingImage -f $BootInfo.Name)
			[Void](Dismount-WindowsImage @DismountBootParams)
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedSavingDismountingImage -f $BootInfo.Name, $(FormatError))
			Stop
		}
	}

	If ($DynamicParams.Recovery)
	{
		Try
		{
			Cleanup -Recovery
			$DismountRecoveryParams = @{
				Path             = $RecoveryMount
				Save             = $true
				ScratchDirectory = $ScratchFolder
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			Log -Info ($OptimizedData.SavingDismountingImage -f $RecoveryInfo.Name)
			[Void](Dismount-WindowsImage @DismountRecoveryParams)
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedSavingDismountingImage -f $RecoveryInfo.Name, $(FormatError))
			Stop
		}
	}

	If ($DynamicParams.Boot)
	{
		Try
		{
			Log -Info ($OptimizedData.RebuildingExportingImage -f $BootInfo.Name)
			Get-WindowsImage -ImagePath $BootWim | ForEach-Object -Process {
				$ExportBootParams = @{
					SourceImagePath      = $BootWim
					SourceIndex          = $PSItem.ImageIndex
					DestinationImagePath = "$WorkFolder\boot.wim"
					ScratchDirectory     = $ScratchFolder
					LogPath              = $DISMLog
					ErrorAction          = 'Stop'
				}
				[Void](Export-WindowsImage @ExportBootParams)
			}
			$BootWim | Purge
			Move-Item -Path "$WorkFolder\boot.wim" -Destination $BootWim -Force
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedRebuildingExportingImage -f $BootInfo.Name, $(FormatError))
			Start-Sleep 3
		}
	}

	If ($DynamicParams.Recovery)
	{
		Try
		{
			$ExportRecoveryParams = @{
				SourceImagePath      = $RecoveryWim
				SourceIndex          = 1
				DestinationImagePath = "$WorkFolder\winre.wim"
				ScratchDirectory     = $ScratchFolder
				LogPath              = $DISMLog
				ErrorAction          = 'Stop'
			}
			Log -Info ($OptimizedData.RebuildingExportingImage -f $RecoveryInfo.Name)
			[Void](Export-WindowsImage @ExportRecoveryParams)
			$WinREPath | Purge
			Move-Item -Path "$WorkFolder\winre.wim" -Destination $WinREPath -Force
		}
		Catch
		{
			Log -Error ($OptimizedData.FailedRebuildingExportingImage -f $RecoveryInfo.Name, $(FormatError))
			Start-Sleep 3
		}
	}

	Try
	{
		Cleanup -Install
		$DismountInstallParams = @{
			Path             = $InstallMount
			Save             = $true
			ScratchDirectory = $ScratchFolder
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		Log -Info ($OptimizedData.SavingDismountingImage -f $InstallInfo.Name)
		[Void](Dismount-WindowsImage @DismountInstallParams)
	}
	Catch
	{
		Log -Error ($OptimizedData.FailedSavingDismountingImage -f $InstallInfo.Name, $(FormatError))
		Stop
	}

	Do
	{
		$CompressionList = @('Solid', 'Maximum', 'Fast', 'None') | Select-Object -Property @{ Label = 'Compression'; Expression = { ($PSItem) } } | Out-GridView -Title "Select Final Image Compression." -OutputMode Single
		$CompressionType = $CompressionList | Select-Object -ExpandProperty Compression
	}
	While ($CompressionList.Length -eq 0)

	If ($CompressionType -eq 'Solid') { Write-Warning $OptimizedData.SolidCompressionWarning; Start-Sleep 5; Clear-Host }

	Try
	{
		Log -Info ($OptimizedData.RebuildingExportingCompressed -f $InstallInfo.Name, $CompressionType)
		If ($CompressionType -eq 'Solid')
		{
			$RET = StartExe $DISM -Arguments @('/Export-Image /SourceImageFile:"{0}" /SourceIndex:{1} /DestinationImageFile:"{2}" /Compress:Recovery /LogPath:"{3}"' -f $InstallWim, $ImageIndex, "$ImageFolder\install.esd", $DISMLog)
			If ($RET -eq 0) { Purge -Path $InstallWim; $ImageFiles = @('install.esd', 'boot.wim') }
			Else { Log -Error ($OptimizedData.FailedRebuildingExportingSolid -f $InstallInfo.Name, $CompressionType); $ImageFiles = @('install.wim', 'boot.wim') }
		}
		Else
		{
			$ExportInstallParams = @{
				SourceImagePath      = $InstallWim
				SourceIndex          = $ImageIndex
				DestinationImagePath = "$WorkFolder\install.wim"
				CompressionType      = $CompressionType
				ScratchDirectory     = $ScratchFolder
				LogPath              = $DISMLog
				ErrorAction          = 'Stop'
			}
			[Void](Export-WindowsImage @ExportInstallParams)
			$InstallWim | Purge
			Move-Item -Path "$WorkFolder\install.wim" -Destination $InstallWim -Force
			$ImageFiles = @('install.wim', 'boot.wim')
		}
	}
	Catch
	{
		Log -Error ($OptimizedData.FailedRebuildingExportingCompressed -f $InstallInfo.Name, $CompressionType, $(FormatError))
		Stop
	}
	Finally
	{
		[Void](Clear-WindowsCorruptMountPoint)
	}

	If ($DynamicParams.ISOMedia)
	{
		Log -Info $OptimizedData.OptimizingWindowsMedia
		Get-ChildItem -Path $ISOMedia.FullName -Filter *.dll | Purge
		@("$($ISOMedia.FullName)\autorun.inf", "$($ISOMedia.FullName)\setup.exe", "$($ISOMedia.FullName)\ca", "$($ISOMedia.FullName)\NanoServer", "$($ISOMedia.FullName)\support", "$($ISOMedia.FullName)\upgrade",
			"$($ISOMedia.FullName)\sources\dlmanifests", "$($ISOMedia.FullName)\sources\etwproviders", "$($ISOMedia.FullName)\sources\inf", "$($ISOMedia.FullName)\sources\hwcompat", "$($ISOMedia.FullName)\sources\migration",
			"$($ISOMedia.FullName)\sources\replacementmanifests", "$($ISOMedia.FullName)\sources\servicing", "$($ISOMedia.FullName)\sources\servicingstackmisc", "$($ISOMedia.FullName)\sources\uup", "$($ISOMedia.FullName)\sources\vista", "$($ISOMedia.FullName)\sources\xp") | Purge
		@('.adml', '.mui', '.rtf', '.txt') | ForEach-Object -Process { Get-ChildItem -Path "$($ISOMedia.FullName)\sources\$($InstallInfo.Language)" -Filter *$($PSItem) -Exclude 'setup.exe.mui' -Recurse | Purge }
		@('.dll', '.gif', '.xsl', '.bmp', '.mof', '.ini', '.cer', '.exe', '.sdb', '.txt', '.nls', '.xml', '.cat', '.inf', '.sys', '.bin', '.ait', '.admx', '.dat', '.ttf', '.cfg', '.xsd', '.rtf', '.xrm-ms') | ForEach-Object -Process { Get-ChildItem -Path "$($ISOMedia.FullName)\sources" -Filter *$($PSItem) -Exclude @('EI.cfg', 'gatherosstate.exe', 'setup.exe', 'lang.ini', 'pid.txt', '*.clg') -Recurse | Purge }
		If ($DynamicParams.NetFx3) { "$($ISOMedia.FullName)\sources\sxs" | Purge }
		Get-ChildItem -Path $ImageFolder -Include $ImageFiles -Recurse | Move-Item -Destination "$($ISOMedia.FullName)\sources" -Force
		If ($ISO)
		{
			If ($ISO -eq 'Prompt' -and (!(Test-Path -Path "$($ISOMedia.FullName)\efi\Microsoft\boot\efisys.bin"))) { Log -Error "Missing the required efisys.bin bootfile for ISO creation." }
			ElseIf ($ISO -eq 'No-Prompt' -and (!(Test-Path -Path "$($ISOMedia.FullName)\efi\Microsoft\boot\efisys_noprompt.bin"))) { Log -Error "Missing the required efisys_noprompt.bin bootfile for ISO creation." }
			Else
			{
				Log -Info ($OptimizedData.CreatingISO -f $ISO)
				$NewISO = New-ISOMedia -BootType $ISO
			}
		}
	}

	Try
	{
		Log -Info $OptimizedData.FinalizingOptimizations
		$SaveDirectory = Create -Path "$($OptimizeOffline.Directory)\Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))" -PassThru
		If ($null -ne $NewISO.Path) { Move-Item -Path $NewISO.Path -Destination $SaveDirectory.FullName }
		Else
		{
			If ($DynamicParams.ISOMedia) { Move-Item -Path $ISOMedia.FullName -Destination $SaveDirectory.FullName }
			Else { Get-ChildItem -Path $ImageFolder -Include $ImageFiles -Recurse | Move-Item -Destination $SaveDirectory.FullName }
		}
	}
	Finally
	{
		$Timer.Stop()
		Start-Sleep 5
		Log -Info ($OptimizedData.OptimizationsCompleted -f $ManifestData.ModuleName, $Timer.Elapsed.Minutes.ToString(), $Error.Count) -Finalized
		@($DISMLog, "$Env:SystemRoot\Logs\DISM\dism.log") | Purge
		ForEach ($Key In $PSBoundParameters.Keys) { $ConfigParams.$Key = $PSBoundParameters.$Key }
		Export-ConfigJSON | Out-File -FilePath (Join-Path -Path $LogFolder -ChildPath Configuration.json) -Encoding UTF8 -Force
		[Void](Get-ChildItem -Path $LogFolder -Include *.log, *.json -Recurse | Compress-Archive -DestinationPath (Join-Path -Path $SaveDirectory.FullName -ChildPath OptimizeLogs.zip) -CompressionLevel Fastest)
		$InstallInfo | Write-WimObject | Out-File -FilePath (Join-Path -Path $SaveDirectory.FullName -ChildPath WimFileInfo.xml) -Encoding UTF8 -Force
		$TempDirectory | Purge
		((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $PSItem -ErrorAction Ignore }
	}
	#endregion Image Finalization and Log and Media Creation
}
Export-ModuleMember -Function Optimize-Offline
# SIG # Begin signature block
# MIIL+wYJKoZIhvcNAQcCoIIL7DCCC+gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUoiaW2d7I5aDm9Ta7y6iEzgMd
# K7GgggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
# AQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9N
# TklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTE5MDUxNTEyMDYwN1oXDTI0
# MDUxNTEyMTYwN1owRTEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/Is
# ZAEZFgVPTU5JQzEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMivWQ61s2ol9vV7TTAhP5hy2CADYNl0C/yVE7wx
# 4eEeiVfiFT+A78GJ4L1h2IbTM6EUlGAtxlz152VFBrY0Hm/nQ1WmrUrneFAb1kTb
# NLGWCyoH9ImrZ5l7NCd97XTZUYsNtbix3nMqUuPPq+UA23pekolHBCpRoDdya22K
# XEgFhOdWfKWsVSCZYiQZyT/moXO2aCmgILq0qtNvNS24grVXTX+qgr1OeiOIF+0T
# SB1oYqTNvROUJ4D6sv4Ap5hJ5PFYmbQrBnytEBGQwXyumQGoK8l/YUBbScsoSjNH
# +GkJMVox7GZObEGf1aLNMCXh7bjpXFw/RJgvBmypkWPIdOUCAwEAAaNRME8wCwYD
# VR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGzmcuTlwYRYLA1E
# /XGZHHp2+GqTMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4IBAQCk
# iQqEJdY3YdQWWM3gBqfgJOaqA4oMTAJCIwj+N3zc4UUChaMOq5kAKRRLMtXOv9fH
# 7L0658kt0+URQIB3GrtkV/h3VYdwACWQLGHvGfZ2paFQTF7vT8KA4fi8pkfRoupg
# 4PZ+drXL1Nq/Nbsr0yaakm2VSlij67grnMOdYBhwtf919qQZdvodJQKL+XipjmT3
# tapbg0FMnugL6vhsB6H8nGWO8szHws2UkiWXSmnECJLYQxZ009do3L0/J4BJvak5
# RUzNcZJIuTnifEIax68UcKHU8bFAaiz5Zns74d0qqZx6ZctYLlPI58mhSn9pohoL
# ozlL4YdE7lQ8EDTiKZTIMIIFdzCCBF+gAwIBAgITGgAAAAgLhnXW+w68VgAAAAAA
# CDANBgkqhkiG9w0BAQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmS
# JomT8ixkARkWBU9NTklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTE5MDUx
# ODE5MDQ1NloXDTIwMDUxNzE5MDQ1NlowUzEUMBIGCgmSJomT8ixkARkWBFRFQ0gx
# FTATBgoJkiaJk/IsZAEZFgVPTU5JQzEOMAwGA1UEAxMFVXNlcnMxFDASBgNVBAMT
# C0JlblRoZUdyZWF0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnkk
# jYlPGAeAApx5Qgn0lbHLI2jywWcsMl2Aff0FDH+4IemQQSQWsU+vCuunrpqvCXMB
# 7yHgecxw37BWnbfEpUyYLZAzuDUxJM1/YQclhH7yOb0GvhHaUevDMCPaqFT1/QoS
# 4PzMim9nj1CU7un8QVTnUCSivC88kJnvBA6JciUoRGU5LAjLDhrMa+v+EQjnkErb
# Y0L3bi3D+ROA23D1oS6nuq27zeRHawod1wscT+BYGiyP/7w8u/GQdGZPeNdw0168
# XCEicDUEiB/s4TI4dCr+0B80eI/8jHTYs/LFj+v6QETiQChR5Vk8lsS3On1LI8Fo
# 8Ki+PPgYCdScxiYNfQIDAQABo4ICUDCCAkwwJQYJKwYBBAGCNxQCBBgeFgBDAG8A
# ZABlAFMAaQBnAG4AaQBuAGcwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/
# BAQDAgeAMB0GA1UdDgQWBBQQg/QKzp8JFAJtalEPhIrNKV7A2jAfBgNVHSMEGDAW
# gBRs5nLk5cGEWCwNRP1xmRx6dvhqkzCByQYDVR0fBIHBMIG+MIG7oIG4oIG1hoGy
# bGRhcDovLy9DTj1PTU5JQy5URUNILUNBLENOPUFOVUJJUyxDTj1DRFAsQ049UHVi
# bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
# bixEQz1PTU5JQyxEQz1URUNIP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
# ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvgYIKwYBBQUHAQEE
# gbEwga4wgasGCCsGAQUFBzAChoGebGRhcDovLy9DTj1PTU5JQy5URUNILUNBLENO
# PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
# b25maWd1cmF0aW9uLERDPU9NTklDLERDPVRFQ0g/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMQYDVR0RBCowKKAm
# BgorBgEEAYI3FAIDoBgMFkJlblRoZUdyZWF0QE9NTklDLlRFQ0gwDQYJKoZIhvcN
# AQELBQADggEBAEyyXCN8L6z4q+gFjbm3B3TvuCAlptX8reIuDg+bY2Bn/WF2KXJm
# +FNZakUKccesxl2XUJo2O7KZBKKjZYMwEBK7NhTOvC50VupJc0p6aXrMrcOnAjAn
# NrjWbKYmc6bG7uCzuEBPlJVmnhdRLgRJKfJDAfXPWkYebV666WnggugL4ROOYtOY
# 3J8j/2cyYE6OD5YTl1ydnYzyNUeZq2IVfxw5BK83lVK5uuneg+4QQaUNWBU5mtIa
# 6t748F1ZEQm3UNk8ImFKWp4dsgAHpPC5wZo/BAMO8PP8BW3+6yvewWnUAGTU4f07
# b1SjZsLcQ6D0eCcFD+7I7MkcSz2ARu6wUOcxggKBMIICfQIBATBcMEUxFDASBgoJ
# kiaJk/IsZAEZFgRURUNIMRUwEwYKCZImiZPyLGQBGRYFT01OSUMxFjAUBgNVBAMT
# DU9NTklDLlRFQ0gtQ0ECExoAAAAIC4Z11vsOvFYAAAAAAAgwCQYFKw4DAhoFAKCB
# +zAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUuKpl6fxBYdihnRrvv+ca7vk0k7Aw
# gZoGCisGAQQBgjcCAQwxgYswgYigUoBQAFcAaQBuAGQAbwB3AHMAIABJAG0AYQBn
# AGUAIAAoAFcASQBNACkAIABvAHAAdABpAG0AaQB6AGEAdABpAG8AbgAgAG0AbwBk
# AHUAbABlAC6hMoAwaHR0cHM6Ly9naXRodWIuY29tL0RyRW1waXJpY2lzbS9PcHRp
# bWl6ZS1PZmZsaW5lMA0GCSqGSIb3DQEBAQUABIIBAB3XdSUPAI0uFw7IHizzPlzX
# EPS1peT1zOiX4lozueCAC3R5o1TI66EGU+wTzPo/MnK8MZbA4LzNp9yWLl3Ilb28
# h2sasjj7oxjBUyZYtkKj6lLIfBw+WY6CSeuL7pKO2iWrGsBy8KVFv6J/obnkh8da
# EaSC77LiXvSNAbhTTb9C89JBXQC6VTQNedoxz51egytU5f9eSbx5fmZfpsLs8cPR
# efcWzpPjeDCa/lkdLBr78anYsVbMY8I7Kn4umkCmSCxv5mrSl5EbiDu/oyepmH53
# OEe3uL+a1Kz8cS86QrKE0/qDcjvMhXaKJSChQRAihae2rP9Q6C9GyeV+/uSQJs4=
# SIG # End signature block
