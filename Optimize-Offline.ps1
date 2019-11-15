#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Module Dism
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 versions 1803-to-1909 64-bit architectures.

	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, enhanced privacy, cleaner aesthetics, increased performance and a significantly better user experience.

	.PARAMETER SourcePath
		The path to a Windows 10 Installation ISO or install.wim

	.PARAMETER WindowsApps
		Removes Appx Provisioned Packages and accepts one of the three values that determines the method in which they are removed:

		Select = Populates and outputs a Gridview list of all Appx Provisioned Packages for selective removal.
		Whitelist = Automatically removes all Appx Provisioned Packages NOT found in the AppxWhiteList.json file.
		All = Automatically removes all Appx Provisioned Packages found in the image.

	.PARAMETER SystemApps
		Populates and outputs a Gridview list of System Applications for selective removal.
		Four System Applications that can be removed use a GUID namespace instead of an identifiable name:

		1527c705-839a-4832-9118-54d4Bd6a0c89 = Microsoft.Windows.FilePicker
		c5e2524a-ea46-4f67-841f-6a9465d9d515 = Microsoft.Windows.FileExplorer
		E2A4F912-2574-4A75-9BB0-0D023378592B = Microsoft.Windows.AppResolverUX
		F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE = Microsoft.Windows.AddSuggestedFoldersToLibraryDialog

	.PARAMETER Capabilities
		Populates and outputs a Gridview list of Capability Packages for selective removal.

	.PARAMETER Packages
		Populates and outputs a Gridview list of Windows Cabinet File Packages for selective removal.

	.PARAMETER Features
		Populates and outputs a Gridview list of Windows Optional Features for selective disabling or enabling.

	.PARAMETER DeveloperMode
		Integrates the Developer Mode Feature into the image.

	.PARAMETER WindowsStore
		Integrates the Microsoft Windows Store and dependencies into the image.
		Only applicable for Windows 10 Enterprise LTSC 2019.

	.PARAMETER MicrosoftEdge
		Integrates the Microsoft Edge Browser into the image.
		Only applicable for Windows 10 Enterprise LTSC 2019.

	.PARAMETER Win32Calc
		Integrates the traditional Win32 Calculator into the image.
		NOT applicable for Windows 10 Enterprise LTSC 2019.

	.PARAMETER Dedup
		Integrates the Windows Server Data Deduplication Feature into the image.

	.PARAMETER DaRT
		Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools into Windows Setup and/or Windows Recovery.
		Accepts one of three values that determines how DaRT 10 is integrated:

		Setup = Integrates DaRT 10 into Windows Setup.
		Recovery = Integrates DaRT 10 into Windows Recovery.
		All = Integrates DaRT 10 into both Windows Setup and Windows Recovery.

	.PARAMETER Registry
		Integrates optimized registry values into the image.

	.PARAMETER Additional
		Integrates user specific content in the "Content/Additional" directory based on the values set in the Additional.json file.

	.PARAMETER ISO
		Creates a new bootable Windows Installation Media ISO.
		Applicable only when a Windows Installation Media ISO is used as the source image.
		Accepts one of two values that determines the boot-type of the ISO:

		Prompt = The efisys.bin binary bootcode is written to the ISO which requires a key press when booted to begin Windows Setup.
		No-Prompt = The efisys_noprompt.bin binary bootcode is written to the ISO which does not require a key press when booted and will begin Windows Setup automatically.

	.EXAMPLE
		.\Optimize-Offline.ps1 -SourcePath "D:\Win10Pro\Win10Pro_Full.iso" -WindowsApps "Select" -SystemApps -Capabilities -Packages -Features -Win32Calc -Dedup -DaRT "Setup" -Registry -ISO "No-Prompt"

	.EXAMPLE
		.\Optimize-Offline.ps1 -SourcePath "D:\Windows 10 ISOs\Win10ProForWorkstations_17663.iso" -WindowsApps "All" -SystemApps -Packages -Features -DaRT "All" -Additional -ISO "Prompt"

	.EXAMPLE
		.\Optimize-Offline.ps1 -SourcePath "D:\Win Images\install.wim" -WindowsApps "Whitelist" -SystemApps -Capabilities -Features -Dedup -Registry -DaRT "Recovery" -Additional

	.EXAMPLE
		.\Optimize-Offline.ps1 -SourcePath "D:\Win10 LTSC 2019\install.wim" -WindowsStore -MicrosoftEdge

	.NOTES
		===========================================================================
		Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.168
		Created by:     BenTheGreat
		Filename:     	Optimize-Offline.ps1
		Version:        3.2.7.8
		Last updated:	11/15/2019
		===========================================================================

	.INPUTS
		IO.FileInfo

	.LINK
		https://github.com/DrEmpiricism/Optimize-Offline
#>
[CmdletBinding(HelpUri = 'https://github.com/DrEmpiricism/Optimize-Offline')]
Param
(
	[Parameter(Mandatory = $true,
		HelpMessage = 'The path to a Windows 10 Installation ISO or install.wim')]
	[ValidateScript( {
			If ((Test-Path -Path (Resolve-Path -Path $_)) -and ($_ -ilike "*.iso")) { $_ }
			ElseIf ((Test-Path -Path (Resolve-Path -Path $_)) -and ($_ -ilike "*.wim")) { $_ }
			Else { Write-Warning ('Invalid source path: "{0}"' -f $($_)); Break }
		})]
	[IO.FileInfo]$SourcePath,
	[Parameter(Mandatory = $false,
		HelpMessage = 'Allows for either the selective or automated removal of Appx Provisioned Packages.')]
	[ValidateSet('Select', 'Whitelist', 'All')]
	[String]$WindowsApps,
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of System Applications for selective removal.')]
	[Switch]$SystemApps,
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of Capability Packages for selective removal.')]
	[Switch]$Capabilities,
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of Windows Cabinet File Packages for selective removal.')]
	[Switch]$Packages,
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of Windows Optional Features for selective disabling or enabling.')]
	[Switch]$Features,
	[Parameter(HelpMessage = 'Integrates the Developer Mode Feature into the image.')]
	[Switch]$DeveloperMode,
	[Parameter(HelpMessage = 'Integrates the Microsoft Windows Store and dependencies into the image.')]
	[Switch]$WindowsStore,
	[Parameter(HelpMessage = 'Integrates the Microsoft Edge Browser into the image.')]
	[Switch]$MicrosoftEdge,
	[Parameter(HelpMessage = 'Integrates the traditional Win32 Calculator into the image.')]
	[Switch]$Win32Calc,
	[Parameter(HelpMessage = 'Integrates the Windows Server Data Deduplication Feature into the image.')]
	[Switch]$Dedup,
	[Parameter(Mandatory = $false,
		HelpMessage = 'Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools into Windows Setup and/or Windows Recovery.')]
	[ValidateSet('Setup', 'Recovery', 'All')]
	[String]$DaRT,
	[Parameter(HelpMessage = 'Integrates optimized registry values into the image.')]
	[Switch]$Registry,
	[Parameter(HelpMessage = 'Integrates user specific content in the "Content/Additional" directory based on the parameters set in the Config.ini.')]
	[Switch]$Additional,
	[Parameter(Mandatory = $false,
		HelpMessage = 'Creates a new bootable Windows Installation Media ISO.')]
	[ValidateSet('Prompt', 'No-Prompt')]
	[String]$ISO
)

#region Script Variables
$DefaultVariables = (Get-Variable).Name
$ProgressPreference = 'SilentlyContinue'
$Host.UI.RawUI.BackgroundColor = 'Black'; Clear-Host
#endregion Script Variables

If (Test-Path -Path "$PSScriptRoot\Lib\OfflineProcessing.psm1")
{
	Try
	{
		Import-Module "$PSScriptRoot\Lib\OfflineProcessing.psm1" -DisableNameChecking -ErrorAction Stop
		TestReq
	}
	Catch
	{
		Write-Warning ('Failed to import the required module: "{0}"' -f $(Split-Path -Path "$PSScriptRoot\Lib\OfflineProcessing.psm1" -Leaf))
		Break
	}
}
Else
{
	Write-Warning ('The required module "{0}" is missing from path "{1}"' -f $(Split-Path -Path "$PSScriptRoot\Lib\OfflineProcessing.psm1" -Leaf), $(Split-Path -Path "$PSScriptRoot\Lib\OfflineProcessing.psm1" -Parent))
	Break
}

If (Get-WindowsImage -Mounted)
{
	$Host.UI.RawUI.WindowTitle = "Active mount points detected. Performing clean-up."
	Write-Host "Active mount points detected. Performing clean-up." -ForegroundColor Cyan
	UnmountAll; Clear-Host
}

Try
{
	Set-Location -Path $PSScriptRoot
	[Void](Clear-WindowsCorruptMountPoint)
	Get-ChildItem -Path $PSScriptRoot -Filter "OfflineTemp_*" -Directory | Purge
	@($TempDirectory, $InstallMount, $ImageDirectory, $WorkDirectory, $ScratchDirectory, $LogDirectory) | Create
	$Timer = New-Object System.Diagnostics.Stopwatch
}
Catch
{
	Write-Warning $($_.Exception.Message)
	Get-ChildItem -Path $PSScriptRoot -Filter "OfflineTemp_*" -Directory | Purge
	Break
}

If ($SourcePath.Extension -eq '.ISO')
{
	$ISOMount = (Mount-DiskImage -ImagePath $SourcePath.FullName -StorageType ISO -PassThru | Get-Volume).DriveLetter + ':'
	[Void](Get-PSDrive)
	If (!(Test-Path -Path "$ISOMount\sources\install.wim"))
	{
		Write-Warning ('"{0}" does not contain valid Windows Installation media.' -f $SourcePath.Name)
		[Void](Dismount-DiskImage -ImagePath $SourcePath.FullName)
		$TempDirectory | Purge
		Break
	}
	Else
	{
		$ISOMedia = Create -Path (Join-Path -Path $TempDirectory -ChildPath $SourcePath.BaseName) -PassThru
		Write-Host ('Exporting media from "{0}"' -f $SourcePath.Name) -ForegroundColor Cyan
		ForEach ($Item In Get-ChildItem -Path $ISOMount -Recurse)
		{
			$ISOExport = $ISOMedia.FullName + $Item.FullName.Replace($ISOMount, $null)
			Copy-Item -Path $Item.FullName -Destination $ISOExport
		}
		$DynamicParams.Add('ISOMedia', $true)
		Get-ChildItem -Path "$($ISOMedia.FullName)\sources" -Include install.wim, boot.wim -Recurse | Move-Item -Destination $ImageDirectory -PassThru | Set-ItemProperty -Name IsReadOnly -Value $false
		$InstallWim = Get-ChildItem -Path $ImageDirectory -Filter install.wim | Select-Object -ExpandProperty FullName
		$BootWim = Get-ChildItem -Path $ImageDirectory -Filter boot.wim | Select-Object -ExpandProperty FullName
		If ($BootWim) { $DynamicParams.Add('Boot', $true) }
		[Void](Dismount-DiskImage -ImagePath $SourcePath.FullName)
	}
}
ElseIf ($SourcePath.Extension -eq '.WIM')
{
	Write-Host ('Copying WIM from "{0}"' -f $SourcePath.DirectoryName) -ForegroundColor Cyan
	Copy-Item -Path $SourcePath.FullName -Destination $ImageDirectory
	Get-ChildItem -Path $ImageDirectory -Filter $SourcePath.Name | Rename-Item -NewName install.wim -PassThru | Set-ItemProperty -Name IsReadOnly -Value $false
	$InstallWim = Get-ChildItem -Path $ImageDirectory -Filter install.wim | Select-Object -ExpandProperty FullName
	If ($ISO) { Remove-Variable ISO }
}

If ((Get-WindowsImage -ImagePath $InstallWim).Count -gt 1)
{
	Do
	{
		$EditionList = Get-WindowsImage -ImagePath $InstallWim | Select-Object -Property @{ Label = 'Index'; Expression = { ($_.ImageIndex) } }, @{ Label = 'Name'; Expression = { ($_.ImageName) } }, @{ Label = 'Size (GB)'; Expression = { '{0:N2}' -f ($_.ImageSize / 1GB) } } | Out-GridView -Title "Select Windows 10 Edition." -OutputMode Single
		$ImageIndex = $EditionList.Index
	}
	While ($EditionList.Length -eq 0)
}
Else { $ImageIndex = 1 }

Try
{
	$InstallInfo = WimData -WimFile $InstallWim -Index $ImageIndex -ErrorAction Stop
}
Catch
{
	Write-Warning "Failed to retrieve necessary image metadata."
	$TempDirectory | Purge
	Break
}

If (!$InstallInfo.Version.StartsWith(10))
{
	Write-Warning "Unsupported Image Version: [$($InstallInfo.Version)]"
	$TempDirectory | Purge
	Break
}

If ($InstallInfo.Architecture -ne 'amd64')
{
	Write-Warning "Unsupported Image Architecture: [$($InstallInfo.Architecture)]"
	$TempDirectory | Purge
	Break
}

If ($InstallInfo.InstallationType.Contains('Server') -or $InstallInfo.InstallationType.Contains('WindowsPE'))
{
	Write-Warning "Unsupported Image Installation Type: [$($InstallInfo.InstallationType)]"
	$TempDirectory | Purge
	Break
}

If ($InstallInfo.Build -ge '17134' -and $InstallInfo.Build -le '18362')
{
	If ($InstallInfo.Build -eq '18362' -and $InstallInfo.Language -ne 'en-US' -and $MicrosoftEdge.IsPresent) { $MicrosoftEdge = $false }
	If ($InstallInfo.Build -lt '17763' -and $MicrosoftEdge.IsPresent) { $MicrosoftEdge = $false }
	If ($InstallInfo.Build -eq '17134' -and $DeveloperMode.IsPresent) { $DeveloperMode = $false }
	If ($InstallInfo.Language -ne 'en-US' -and $Win32Calc.IsPresent) { $Win32Calc = $false }
	If ($InstallInfo.Build -gt '17134' -and $InstallInfo.Language -ne 'en-US' -and $Dedup.IsPresent) { $Dedup = $false }
	If ($InstallInfo.Language -ne 'en-US' -and $DaRT) { Remove-Variable DaRT }
	If ($InstallInfo.Name -like "*LTSC*")
	{
		$DynamicParams.Add('LTSC', $true)
		If ($WindowsApps) { Remove-Variable WindowsApps }
		If ($Win32Calc.IsPresent) { $Win32Calc = $false }
	}
	Else
	{
		If ($WindowsStore.IsPresent) { $WindowsStore = $false }
		If ($MicrosoftEdge.IsPresent) { $MicrosoftEdge = $false }
	}
}
Else
{
	Write-Warning "Unsupported Image Build: [$($InstallInfo.Build)]"
	$TempDirectory | Purge
	Break
}

Try
{
	"$Env:SystemRoot\Logs\DISM\dism.log" | Purge
	Log -Info "Supported Image Build: [$($InstallInfo.Build)]"
	Start-Sleep 3; $Timer.Start(); $Error.Clear()
	Log -Info "Mounting $($InstallInfo.Name)"
	$MountInstallParams = @{
		ImagePath        = $InstallWim
		Index            = $ImageIndex
		Path             = $InstallMount
		ScratchDirectory = $ScratchDirectory
		LogPath          = $DISMLog
		ErrorAction      = 'Stop'
	}
	[Void](Mount-WindowsImage @MountInstallParams)
}
Catch
{
	Log -Error ('Failed to Mount {0}' -f $($InstallInfo.Name)) -ErrorRecord $Error[0]
	Stop; Break
}

If (Test-Path -Path (Join-Path -Path $InstallMount -ChildPath 'Windows\System32\Recovery\winre.wim'))
{
	$WinREPath = Join-Path -Path $InstallMount -ChildPath 'Windows\System32\Recovery\winre.wim'
	Copy-Item -Path $WinREPath -Destination $ImageDirectory -Force
	$RecoveryWim = Get-ChildItem -Path $ImageDirectory -Filter winre.wim | Select-Object -ExpandProperty FullName
	$DynamicParams.Add('Recovery', $true)
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
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		Log -Info "Mounting $($BootInfo.Name)"
		[Void](Mount-WindowsImage @MountBootParams)
	}
	Catch
	{
		Log -Error ('Failed to Mount {0}' -f $($BootInfo.Name)) -ErrorRecord $Error[0]
		Stop; Break
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
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		Log -Info "Mounting $($RecoveryInfo.Name)"
		[Void](Mount-WindowsImage @MountRecoveryParams)
	}
	Catch
	{
		Log -Error ('Failed to Mount {0}' -f $($RecoveryInfo.Name)) -ErrorRecord $Error[0]
		Stop; Break
	}
}

If ((Repair-WindowsImage -Path $InstallMount -CheckHealth).ImageHealthState -eq 'Healthy')
{
	Log -Info "Pre-Optimization Image Health State: [Healthy]"
	Start-Sleep 3; Clear-Host
}
Else
{
	Log -Error "The image has been flagged for corruption. Further servicing is required before the image can be optimized."
	Stop; Break
}

If ($WindowsApps -and (Get-AppxProvisionedPackage -Path $InstallMount).Count -gt 0)
{
	$Host.UI.RawUI.WindowTitle = "Removing Appx Provisioned Packages."
	$RemovedAppxPackages = [Collections.Generic.List[Object]]::New()
	Switch ($PSBoundParameters.WindowsApps)
	{
		'Select'
		{
			$AppxPackages = Get-AppxProvisionedPackage -Path $InstallMount | Select-Object -Property DisplayName, PackageName | Sort-Object -Property DisplayName | Out-GridView -Title "Remove Appx Provisioned Packages." -PassThru
			If ($AppxPackages)
			{
				Try
				{
					$AppxPackages | ForEach-Object -Process {
						$RemoveAppxParams = @{
							Path             = $InstallMount
							PackageName      = $($_.PackageName)
							ScratchDirectory = $ScratchDirectory
							LogPath          = $DISMLog
							ErrorAction      = 'Stop'
						}
						Log -Info ('Removing Appx Provisioned Package: {0}' -f $($_.DisplayName))
						[Void](Remove-AppxProvisionedPackage @RemoveAppxParams)
						$RemovedAppxPackages.Add($_.DisplayName)
					}
					$DynamicParams.Add('WindowsApps', $WindowsApps); Clear-Host
				}
				Catch
				{
					Log -Error "Failed to Remove Appx Provisioned Packages." -ErrorRecord $Error[0]
					Stop; Break
				}
			}
		}
		'Whitelist'
		{
			If (Test-Path -Path $WhitelistJsonPath)
			{
				Try
				{
					$WhitelistJson = Get-Content -Path $WhitelistJsonPath -Raw | ConvertFrom-Json
					Get-AppxProvisionedPackage -Path $InstallMount | ForEach-Object -Process {
						If ($_.DisplayName -notin $WhitelistJson.DisplayName)
						{
							$RemoveAppxParams = @{
								Path             = $InstallMount
								PackageName      = $($_.PackageName)
								ScratchDirectory = $ScratchDirectory
								LogPath          = $DISMLog
								ErrorAction      = 'Stop'
							}
							Log -Info ('Removing Appx Provisioned Package: {0}' -f $($_.DisplayName))
							[Void](Remove-AppxProvisionedPackage @RemoveAppxParams)
							$RemovedAppxPackages.Add($_.DisplayName)
						}
					}
					$DynamicParams.Add('WindowsApps', $WindowsApps); Clear-Host
				}
				Catch
				{
					Log -Error "Failed to Remove Appx Provisioned Packages." -ErrorRecord $Error[0]
					Stop; Break
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
						PackageName      = $($_.PackageName)
						ScratchDirectory = $ScratchDirectory
						LogPath          = $DISMLog
						ErrorAction      = 'Stop'
					}
					Log -Info ('Removing Appx Provisioned Package: {0}' -f $($_.DisplayName))
					[Void](Remove-AppxProvisionedPackage @RemoveAppxParams)
					$RemovedAppxPackages.Add($_.DisplayName)
				}
				$DynamicParams.Add('WindowsApps', $WindowsApps); Clear-Host
			}
			Catch
			{
				Log -Error "Failed to Remove Appx Provisioned Packages." -ErrorRecord $Error[0]
				Stop; Break
			}
		}
	}
}

If ($RemovedAppxPackages -and (Get-AppxProvisionedPackage -Path $InstallMount).Count -eq 0)
{
	$Host.UI.RawUI.WindowTitle = "Removing Windows App Package Files."
	Log -Info "Removing Windows App Package Files."
	Get-ChildItem -Path "$InstallMount\Program Files\WindowsApps" -Force | Purge -Force
	Start-Sleep 3
}

If (Test-Path -Path $AppAssocPath)
{
	$Host.UI.RawUI.WindowTitle = "Importing Custom App Associations."
	Log -Info "Importing Custom App Associations."
	$RET = RunExe $DISM -Arguments ('/Image:"{0}" /Import-DefaultAppAssociations:"{1}"' -f $InstallMount, $AppAssocPath)
	If ($RET -ne 0) { Log -Error "Failed to Import Custom App Associations."; Start-Sleep 3 }
}

If ($SystemApps.IsPresent)
{
	Clear-Host
	$Host.UI.RawUI.WindowTitle = "Removing System Applications."
	Write-Warning "Do NOT remove any System Application if you are unsure of its impact on a live installation."
	Start-Sleep 5
	$InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
	RegHives -Load
	$InboxAppsPackages = Get-ChildItem -Path $InboxAppsKey -Name | Select-Object -Property @{ Label = 'DisplayName'; Expression = { ($_.Split('_')[0]) } }, @{ Label = 'PackageName'; Expression = { ($_) } } | Sort-Object -Property DisplayName | Out-GridView -Title "Remove System Applications." -PassThru
	If ($InboxAppsPackages)
	{
		$RemovedSystemApps = [Collections.Generic.List[Object]]::New()
		Clear-Host
		Try
		{
			$InboxAppsPackages | ForEach-Object -Process {
				Log -Info "Removing System Application: $($_.DisplayName)"
				$PackageKey = (Join-Path -Path $InboxAppsKey -ChildPath $($_.PackageName)) -replace 'HKLM:', 'HKLM'
				$RET = RunExe $REG -Arguments ('DELETE "{0}" /F' -f $PackageKey) -ErrorAction Stop
				If ($RET -eq 1) { Log -Error "Failed to Remove System Application: $($_.DisplayName)"; Return }
				$RemovedSystemApps.Add($_.DisplayName)
				Start-Sleep 2
			}
			$DynamicParams.Add('SystemApps', $true); Clear-Host
		}
		Catch
		{
			Log -Error "Failed to Remove System Applications." -ErrorRecord $Error[0]
			Stop; Break
		}
		Finally
		{
			RegHives -Unload
		}
	}
}

If ($Capabilities.IsPresent)
{
	Clear-Host
	$Host.UI.RawUI.WindowTitle = "Removing Windows Capabilities."
	$WindowsCapabilities = Get-WindowsCapability -Path $InstallMount | Where-Object { $_.Name -notlike "*Language.Basic*" -and $_.Name -notlike "*TextToSpeech*" -and $_.State -eq 'Installed' } | Select-Object -Property Name, State | Sort-Object -Property Name | Out-GridView -Title "Remove Windows Capabilities." -PassThru
	If ($WindowsCapabilities)
	{
		Try
		{
			$WindowsCapabilities | ForEach-Object -Process {
				$RemoveCapabilityParams = @{
					Path             = $InstallMount
					Name             = $($_.Name)
					ScratchDirectory = $ScratchDirectory
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				Log -Info ('Removing Windows Capability: {0}' -f $($_.Name.Split('~')[0]))
				[Void](Remove-WindowsCapability @RemoveCapabilityParams)
			}
			$DynamicParams.Add('Capabilities', $true); Clear-Host
		}
		Catch
		{
			Log -Error "Failed to Remove Windows Capabilities." -ErrorRecord $Error[0]
			Stop; Break
		}
	}
}

If ($Packages.IsPresent)
{
	Clear-Host
	$Host.UI.RawUI.WindowTitle = "Removing Windows Packages."
	$WindowsPackages = Get-WindowsPackage -Path $InstallMount | Where-Object { $_.PackageName -notlike "*LanguageFeatures-Basic*" -and $_.PackageName -notlike "*LanguageFeatures-TextToSpeech*" -and $_.ReleaseType -eq 'OnDemandPack' -or $_.ReleaseType -eq 'LanguagePack' -or $_.ReleaseType -eq 'FeaturePack' -and $_.PackageState -eq 'Installed' } | Select-Object -Property PackageName, ReleaseType | Sort-Object -Property ReleaseType | Out-GridView -Title "Remove Windows Packages." -PassThru
	If ($WindowsPackages)
	{
		Try
		{
			$WindowsPackages | ForEach-Object -Process {
				$RemovePackageParams = @{
					Path             = $InstallMount
					PackageName      = $($_.PackageName)
					NoRestart        = $true
					ScratchDirectory = $ScratchFolder
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				Log -Info ('Removing Windows Package: {0}' -f $($_.PackageName.Replace('Package', $null).Split('~')[0]).TrimEnd('-'))
				[Void](Remove-WindowsPackage @RemovePackageParams)
			}
			$DynamicParams.Add('Packages', $true); Clear-Host
		}
		Catch
		{
			Log -Error "Failed to Remove Windows Packages." -ErrorRecord $Error[0]
			Stop; Break
		}
	}
}

If ($RemovedAppxPackages -or $RemovedSystemApps)
{
	$SB = [Text.StringBuilder]::New(); [Void]$SB.Append('hide:')
	If ($RemovedAppxPackages -contains 'Microsoft.WindowsMaps') { [Void]$SB.Append('maps;maps-downloadmaps;') }
	If ($RemovedAppxPackages -contains 'Microsoft.YourPhone' -or $RemovedSystemApps -contains 'Microsoft.Windows.CallingShellApp') { [Void]$SB.Append('mobile-devices;mobile-devices-addphone;mobile-devices-addphone-direct;') }
}

If ($RemovedSystemApps -contains 'Microsoft.Windows.SecHealthUI')
{
	$Host.UI.RawUI.WindowTitle = "Disabling Windows Defender Services, Drivers and SmartScreen Integration."
	Log -Info "Disabling Windows Defender Services, Drivers and SmartScreen Integration."
	RegHives -Load
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
	@("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach-Object -Process { If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)" -Name "Start" -Value 4 -Type DWord } }
	@("HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP", "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderApiLogger", "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderAuditLogger") | Purge
	Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force
	If (!$DynamicParams.LTSC) { RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord }
	If ($InstallInfo.Build -ge '17763')
	{
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControlEnabled" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControl" -Value "Anywhere" -Type String
	}
	RegHives -Unload
	If (Get-WindowsOptionalFeature -Path $InstallMount -FeatureName Windows-Defender-Default-Definitions | Where-Object -Property State -EQ Enabled)
	{
		$Host.UI.RawUI.WindowTitle = "Disabling Optional Feature: Windows-Defender-Default-Definitions"
		Log -Info "Disabling Optional Feature: Windows-Defender-Default-Definitions"
		[Void](Disable-WindowsOptionalFeature -Path $InstallMount -FeatureName Windows-Defender-Default-Definitions -Remove -NoRestart -ScratchDirectory $ScratchDirectory -LogPath $DISMLog -ErrorAction SilentlyContinue)
	}
	[Void]$SB.Append('windowsdefender;')
}

If ($RemovedAppxPackages -like "*Xbox*" -or $RemovedSystemApps -contains 'Microsoft.XboxGameCallableUI')
{
	$Host.UI.RawUI.WindowTitle = "Disabling Xbox Services and Drivers."
	Log -Info "Disabling Xbox Services and Drivers."
	RegHives -Load
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
	@("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach-Object -Process { If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)" -Name "Start" -Value 4 -Type DWord } }
	RegHives -Unload
	[Void]$SB.Append('gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking;quietmomentsgame;')
	If ($InstallInfo.Build -lt '17763') { [Void]$SB.Append('gaming-trueplay;') }
}

If ($SB.Length -gt 5)
{
	$Visibility = $SB.ToString().TrimEnd(';')
	RegHives -Load
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value $Visibility -Type String
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value $Visibility -Type String
	RegHives -Unload
}

ForEach ($Feature In @('SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root'))
{
	If (Get-WindowsOptionalFeature -Path $InstallMount -FeatureName $Feature | Where-Object -Property State -EQ Enabled)
	{
		$Host.UI.RawUI.WindowTitle = ('Disabling Optional Feature: {0}' -f $Feature)
		Log -Info ('Disabling Optional Feature: {0}' -f $Feature)
		[Void](Disable-WindowsOptionalFeature -Path $InstallMount -FeatureName $Feature -Remove -NoRestart -ScratchDirectory $ScratchDirectory -LogPath $DISMLog -ErrorAction SilentlyContinue)
	}
}

If ($Features.IsPresent)
{
	Clear-Host
	$Host.UI.RawUI.WindowTitle = "Disabling Optional Features."
	$DisableFeatures = Get-WindowsOptionalFeature -Path $InstallMount | Where-Object State -EQ Enabled | Select-Object -Property FeatureName, State | Sort-Object -Property FeatureName | Out-GridView -Title "Disable Optional Features." -PassThru
	If ($DisableFeatures)
	{
		Try
		{
			$DisableFeatures | ForEach-Object -Process {
				$DisableFeatureParams = @{
					Path             = $InstallMount
					FeatureName      = $($_.FeatureName)
					Remove           = $true
					NoRestart        = $true
					ScratchDirectory = $ScratchDirectory
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				Log -Info "Disabling Optional Feature: $($_.FeatureName)"
				[Void](Disable-WindowsOptionalFeature @DisableFeatureParams)
			}
			$DynamicParams.Add('DisabledOptionalFeatures', $true); Clear-Host
		}
		Catch
		{
			Log -Error "Failed to Disable Optional Features." -ErrorRecord $Error[0]
			Stop; Break
		}
	}
	Clear-Host
	$Host.UI.RawUI.WindowTitle = "Enabling Optional Features."
	$EnableFeatures = Get-WindowsOptionalFeature -Path $InstallMount | Where-Object { $_.FeatureName -notlike "*SMB1*" -and $_.FeatureName -ne "Windows-Defender-Default-Definitions" -and $_.FeatureName -ne "MicrosoftWindowsPowerShellV2Root" -and $_.State -eq "Disabled" } | Select-Object -Property FeatureName, State | Sort-Object -Property FeatureName | Out-GridView -Title "Enable Optional Features." -PassThru
	If ($EnableFeatures)
	{
		Try
		{
			$EnableFeatures | ForEach-Object -Process {
				$EnableFeatureParams = @{
					Path             = $InstallMount
					FeatureName      = $($_.FeatureName)
					All              = $true
					LimitAccess      = $true
					NoRestart        = $true
					ScratchDirectory = $ScratchDirectory
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				Log -Info "Enabling Optional Feature: $($_.FeatureName)"
				[Void](Enable-WindowsOptionalFeature @EnableFeatureParams)
			}
			$DynamicParams.Add('EnabledOptionalFeatures', $true); Clear-Host
		}
		Catch
		{
			Log -Error "Failed to Enable Optional Features." -ErrorRecord $Error[0]
			Stop; Break
		}
	}
}

If ($DeveloperMode.IsPresent -and (Test-Path -Path $DevModePath -Filter *DeveloperMode-Desktop-Package*.cab) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object -Property PackageName -Like *DeveloperMode*))
{
	$DevModePackage = "$DevModePath\Microsoft-OneCore-DeveloperMode-Desktop-Package~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab"
	$DevModeExpand = Create -Path (Join-Path -Path $WorkDirectory -ChildPath DeveloperMode) -PassThru
	[Void](RunExe $EXPAND -Arguments ('"{0}" F:* "{1}"' -f $DevModePackage, $DevModeExpand.FullName))
	If (Test-Path -Path "$($DevModeExpand.FullName)\update.mum")
	{
		$Host.UI.RawUI.WindowTitle = "Integrating the Developer Mode Feature Package."
		Log -Info "Integrating the Developer Mode Feature Package."
		$RET = RunExe $DISM -Arguments ('/Image:"{0}" /Add-Package /PackagePath:"{1}" /ScratchDir:"{2}" /LogPath:"{3}"' -f $InstallMount, "$($DevModeExpand.FullName)\update.mum", $ScratchDirectory, $DISMLog)
		If ($RET -eq 0)
		{
			RegHives -Load
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Value 1 -Type DWord
			RegHives -Unload
			$DynamicParams.Add('DeveloperMode', $true)
		}
		Else { Log -Error "Failed to Integrate the Developer Mode Feature Package."; Start-Sleep 3 }
	}
}

If ($WindowsStore.IsPresent -and (Test-Path -Path $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle))
{
	$Host.UI.RawUI.WindowTitle = "Integrating the Microsoft Store Application Packages."
	Log -Info "Integrating the Microsoft Store Application Packages."
	$StoreBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle -File | Select-Object -ExpandProperty FullName
	$PurchaseBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.appxbundle -File | Select-Object -ExpandProperty FullName
	$XboxBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.appxbundle -File | Select-Object -ExpandProperty FullName
	$InstallerBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.appxbundle -File | Select-Object -ExpandProperty FullName
	$StoreLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.xml -File | Select-Object -ExpandProperty FullName
	$PurchaseLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.xml -File | Select-Object -ExpandProperty FullName
	$IdentityLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.xml -File | Select-Object -ExpandProperty FullName
	$InstallerLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.xml -File | Select-Object -ExpandProperty FullName
	$DepAppx = @()
	$DepAppx += Get-ChildItem -Path $StoreAppPath -Filter Microsoft.VCLibs*.appx -File | Select-Object -ExpandProperty FullName
	$DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Framework*.appx -File | Select-Object -ExpandProperty FullName
	$DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx -File | Select-Object -ExpandProperty FullName
	RegHives -Load
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord
	RegHives -Unload
	Try
	{
		$StorePackage = @{
			Path                  = $InstallMount
			PackagePath           = $StoreBundle
			DependencyPackagePath = $DepAppx
			LicensePath           = $StoreLicense
			ScratchDirectory      = $ScratchDirectory
			LogPath               = $DISMLog
			ErrorAction           = 'Stop'
		}
		[Void](Add-AppxProvisionedPackage @StorePackage)
		$PurchasePackage = @{
			Path                  = $InstallMount
			PackagePath           = $PurchaseBundle
			DependencyPackagePath = $DepAppx
			LicensePath           = $PurchaseLicense
			ScratchDirectory      = $ScratchDirectory
			LogPath               = $DISMLog
			ErrorAction           = 'Stop'
		}
		[Void](Add-AppxProvisionedPackage @PurchasePackage)
		$IdentityPackage = @{
			Path                  = $InstallMount
			PackagePath           = $XboxBundle
			DependencyPackagePath = $DepAppx
			LicensePath           = $IdentityLicense
			ScratchDirectory      = $ScratchDirectory
			LogPath               = $DISMLog
			ErrorAction           = 'Stop'
		}
		[Void](Add-AppxProvisionedPackage @IdentityPackage)
		$DepAppx = @()
		$DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx -File | Select-Object -ExpandProperty FullName
		$InstallerPackage = @{
			Path                  = $InstallMount
			PackagePath           = $InstallerBundle
			DependencyPackagePath = $DepAppx
			LicensePath           = $InstallerLicense
			ScratchDirectory      = $ScratchDirectory
			LogPath               = $DISMLog
			ErrorAction           = 'Stop'
		}
		[Void](Add-AppxProvisionedPackage @InstallerPackage)
		$DynamicParams.Add('WindowsStore', $true)
	}
	Catch
	{
		Log -Error "Failed to Integrate the Microsoft Store Application Packages." -ErrorRecord $Error[0]
		Start-Sleep 3
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

If ($MicrosoftEdge.IsPresent -and (Test-Path -Path $EdgeAppPath -Filter Microsoft-Windows-Internet-Browser-Package*.cab) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *Internet-Browser*))
{
	Try
	{
		$Host.UI.RawUI.WindowTitle = "Integrating the Microsoft Edge Browser Application Packages."
		Log -Info "Integrating the Microsoft Edge Browser Application Packages."
		$EdgeBasePackage = @{
			Path             = $InstallMount
			PackagePath      = "$EdgeAppPath\Microsoft-Windows-Internet-Browser-Package~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab"
			IgnoreCheck      = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Add-WindowsPackage @EdgeBasePackage)
		$EdgeLanguagePackage = @{
			Path             = $InstallMount
			PackagePath      = "$EdgeAppPath\Microsoft-Windows-Internet-Browser-Package~$($InstallInfo.Architecture)~$($InstallInfo.Language)~10.0.$($InstallInfo.Build).1.cab"
			IgnoreCheck      = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Add-WindowsPackage @EdgeLanguagePackage)
		RegHives -Load
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -Type DWord
		If ($RemovedSystemApps -contains 'Microsoft.Windows.SecHealthUI') { RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord }
		RegHives -Unload; $DynamicParams.Add('MicrosoftEdge', $true)
	}
	Catch
	{
		Log -Error "Failed to Integrate the Microsoft Edge Browser Application Packages." -ErrorRecord $Error[0]
		Start-Sleep 3
	}
	Finally
	{
		If (RegHives -Test) { RegHives -Unload }
	}
}

If ($Win32Calc.IsPresent -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *win32calc*) -and (Test-Path -Path $Win32CalcPath -Filter Win32Calc.wim))
{
	Try
	{
		$ExpandCalcParams = @{
			ImagePath        = "$Win32CalcPath\Win32Calc.wim"
			Index            = 1
			ApplyPath        = $InstallMount
			CheckIntegrity   = $true
			Verify           = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		$Host.UI.RawUI.WindowTitle = "Integrating the Win32 Calculator."
		Log -Info "Integrating the Win32 Calculator."
		[Void](Expand-WindowsImage @ExpandCalcParams)
		Add-Content -Path "$InstallMount\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini" -Value 'Calculator.lnk=@%SystemRoot%\System32\shell32.dll,-22019' -Encoding Unicode -Force
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
		RegHives -Unload; $DynamicParams.Add('Win32Calc', $true)
	}
	Catch
	{
		Log -Error "Failed to Integrate the Win32 Calculator." -ErrorRecord $Error[0]
		Start-Sleep 3
	}
	Finally
	{
		If (RegHives -Test) { RegHives -Unload }
	}
}

If ($Dedup.IsPresent -and (Test-Path -Path $DedupPath -Filter Microsoft-Windows-FileServer-ServerCore-Package*.cab) -and (Test-Path -Path $DedupPath -Filter Microsoft-Windows-Dedup-Package*.cab) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *Windows-Dedup*) -and $null -eq (Get-WindowsPackage -Path $InstallMount | Where-Object PackageName -Like *Windows-FileServer-ServerCore*))
{
	$Host.UI.RawUI.WindowTitle = "Integrating the Data Deduplication Packages."
	Log -Info "Integrating the Data Deduplication Packages."
	Try
	{
		$FileServerCore = @{
			Path             = $InstallMount
			PackagePath      = "$DedupPath\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab"
			IgnoreCheck      = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Add-WindowsPackage @FileServerCore)
		$FileServerLang = @{
			Path             = $InstallMount
			PackagePath      = "$DedupPath\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~$($InstallInfo.Language)~10.0.$($InstallInfo.Build).1.cab"
			IgnoreCheck      = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Add-WindowsPackage @FileServerLang)
		$DedupCore = @{
			Path             = $InstallMount
			PackagePath      = "$DedupPath\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~~10.0.$($InstallInfo.Build).1.cab"
			IgnoreCheck      = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Add-WindowsPackage @DedupCore)
		$DedupLang = @{
			Path             = $InstallMount
			PackagePath      = "$DedupPath\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($InstallInfo.Architecture)~$($InstallInfo.Language)~10.0.$($InstallInfo.Build).1.cab"
			IgnoreCheck      = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Add-WindowsPackage @DedupLang)
		$EnableDedup = @{
			Path             = $InstallMount
			FeatureName      = 'Dedup-Core'
			All              = $true
			LimitAccess      = $true
			NoRestart        = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Enable-WindowsOptionalFeature @EnableDedup)
		RegHives -Load
		$FirewallRule = @{
			Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules"
			Name  = "FileServer-ServerManager-DCOM-TCP-In"
			Value = "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%systemroot%\\system32\\svchost.exe|Svc=RPCSS|Name=File Server Remote Management (DCOM-In)|Desc=Inbound rule to allow DCOM traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|"
			Type  = 'String'
		}
		RegKey @FirewallRule
		$FirewallRule = @{
			Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules"
			Name  = "FileServer-ServerManager-SMB-TCP-In"
			Value = "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=File Server Remote Management (SMB-In)|Desc=Inbound rule to allow SMB traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|"
			Type  = 'String'
		}
		RegKey @FirewallRule
		$FirewallRule = @{
			Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules"
			Name  = "FileServer-ServerManager-Winmgmt-TCP-In"
			Value = "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%systemroot%\\system32\\svchost.exe|Svc=Winmgmt|Name=File Server Remote Management (WMI-In)|Desc=Inbound rule to allow WMI traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|"
			Type  = 'String'
		}
		RegKey @FirewallRule
		$FirewallRule = @{
			Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name  = "FileServer-ServerManager-DCOM-TCP-In"
			Value = "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%systemroot%\\system32\\svchost.exe|Svc=RPCSS|Name=File Server Remote Management (DCOM-In)|Desc=Inbound rule to allow DCOM traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|"
			Type  = 'String'
		}
		RegKey @FirewallRule
		$FirewallRule = @{
			Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name  = "FileServer-ServerManager-SMB-TCP-In"
			Value = "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=File Server Remote Management (SMB-In)|Desc=Inbound rule to allow SMB traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|"
			Type  = 'String'
		}
		RegKey @FirewallRule
		$FirewallRule = @{
			Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name  = "FileServer-ServerManager-Winmgmt-TCP-In"
			Value = "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%systemroot%\\system32\\svchost.exe|Svc=Winmgmt|Name=File Server Remote Management (WMI-In)|Desc=Inbound rule to allow WMI traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|"
			Type  = 'String'
		}
		RegKey @FirewallRule
		RegHives -Unload; $DynamicParams.Add('DataDeduplication', $true)
	}
	Catch
	{
		Log -Error "Failed to Integrate the Data Deduplication Packages." -ErrorRecord $Error[0]
		Start-Sleep 3
	}
	Finally
	{
		If (RegHives -Test) { RegHives -Unload }
	}
}

If ($DaRT -and (Test-Path -Path $DaRTPath -Filter MSDaRT10_*.wim))
{
	If ($InstallInfo.Build -eq '17134') { $CodeName = 'RS4' }
	ElseIf ($InstallInfo.Build -eq '17763') { $CodeName = 'RS5' }
	ElseIf ($InstallInfo.Build -eq '18362') { $CodeName = 'RS6' }
	If ($PSBoundParameters.DaRT -eq 'Setup' -or $PSBoundParameters.DaRT -eq 'All' -and $DynamicParams.Boot)
	{
		Try
		{
			$Host.UI.RawUI.WindowTitle = "Integrating Microsoft DaRT 10 and Windows $($CodeName) Debugging Tools into $($BootInfo.Name)"
			Log -Info "Integrating Microsoft DaRT 10 and Windows $($CodeName) Debugging Tools into $($BootInfo.Name)"
			$ExpandDaRTBootParams = @{
				ImagePath        = "$DaRTPath\MSDaRT10_$($CodeName).wim"
				Index            = 1
				ApplyPath        = $BootMount
				CheckIntegrity   = $true
				Verify           = $true
				ScratchDirectory = $ScratchDirectory
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
		Catch
		{
			Log -Error "Failed to integrate Microsoft DaRT 10 into $($BootInfo.Name)" -ErrorRecord $Error[0]
		}
		Finally
		{
			Start-Sleep 3
		}
	}
	If ($PSBoundParameters.DaRT -eq 'Recovery' -or $PSBoundParameters.DaRT -eq 'All' -and $DynamicParams.Recovery)
	{
		Try
		{
			$Host.UI.RawUI.WindowTitle = "Integrating Microsoft DaRT 10 and Windows $($CodeName) Debugging Tools into $($RecoveryInfo.Name)"
			Log -Info "Integrating Microsoft DaRT 10 and Windows $($CodeName) Debugging Tools into $($RecoveryInfo.Name)"
			$ExpandDaRTRecoveryParams = @{
				ImagePath        = "$DaRTPath\MSDaRT10_$($CodeName).wim"
				Index            = 1
				ApplyPath        = $RecoveryMount
				CheckIntegrity   = $true
				Verify           = $true
				ScratchDirectory = $ScratchDirectory
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
		Catch
		{
			Log -Error "Failed to integrate Microsoft DaRT 10 into $($RecoveryInfo.Name)" -ErrorRecord $Error[0]
		}
		Finally
		{
			Start-Sleep 3
		}
	}
	Clear-Host
}

#region Registry Optimizations.
If ($Registry.IsPresent)
{
	$Host.UI.RawUI.WindowTitle = "Applying Optimizations to the Offline Registry Hives."
	Log -Info "Applying Optimizations to the Offline Registry Hives."
	$RegLog = Join-Path -Path $LogDirectory -ChildPath Registry-Optimizations.log
	RegHives -Load
	#****************************************************************#
	Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> $RegLog
	#****************************************************************#
	If ($InstallInfo.Build -ge '18362') { RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0 -Type DWord }
	ElseIf ($InstallInfo.Build -le '17763') { RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord }
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HasAboveLockTips" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -Value 1 -Type DWord
	$FirewallParams = @{
		Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
		Name  = "Block Cortana ActionUriServer.exe"
		Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe|Name=Block Cortana ActionUriServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
		Type  = 'String'
	}
	RegKey @FirewallParams
	$FirewallParams = @{
		Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
		Name  = "Block Cortana PlacesServer.exe"
		Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe|Name=Block Cortana PlacesServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
		Type  = 'String'
	}
	RegKey @FirewallParams
	$FirewallParams = @{
		Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
		Name  = "Block Cortana RemindersServer.exe"
		Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
		Type  = 'String'
	}
	RegKey @FirewallParams
	$FirewallParams = @{
		Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
		Name  = "Block Cortana RemindersShareTargetApp.exe"
		Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe|Name=Block Cortana RemindersShareTargetApp.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
		Type  = 'String'
	}
	RegKey @FirewallParams
	$FirewallParams = @{
		Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
		Name  = "Block Cortana SearchUI.exe"
		Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block Cortana SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
		Type  = 'String'
	}
	RegKey @FirewallParams
	$FirewallParams = @{
		Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
		Name  = "Block Cortana Package"
		Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Cortana Package|Desc=Block Cortana Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|Platform=2:6:2|Platform2=GTEQ|"
		Type  = 'String'
	}
	RegKey @FirewallParams
	#****************************************************************#
	Write-Output "Disabling System Telemetry, Logging, Data Collecting and Advertisements." >> $RegLog
	#****************************************************************#
	If ($DynamicParams.LTSC -or $InstallInfo.Name -like "*Enterprise*" -or $InstallInfo.Name -like "*Education*") { $TelemetryLevel = 0 } Else { $TelemetryLevel = 1 }
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value $TelemetryLevel -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value $TelemetryLevel -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value $TelemetryLevel -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 100 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Disabling Windows Tracking." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoExplicitFeedback" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord
	If (!$DynamicParams.LTSC -and !$DynamicParams.MicrosoftEdge) { RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -Type DWord }
	#****************************************************************#
	Write-Output "Disabling System Location Sensors." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String
	If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc" -Name "Start" -Value 4 -Type DWord }
	If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord }
	#****************************************************************#
	Write-Output "Disabling the Password Reveal Button." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Disabling Cross-Device Sharing and Shared Experiences." >>  $RegLog
	#***************************************************************
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Disabling WiFi Sense." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord
	#****************************************************************#
	If ($RemovedAppxPackages -contains 'Microsoft.WindowsMaps')
	{
		If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker")
		{
			#****************************************************************#
			Write-Output "Disabling the Windows Maps App Service." >> $RegLog
			#****************************************************************#
			RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord
		}
		#****************************************************************#
		Write-Output "Disabling Windows Maps Auto Update." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0 -Type DWord
	}
	If ($RemovedAppxPackages -contains 'Microsoft.Wallet' -and (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService"))
	{
		#****************************************************************#
		Write-Output "Disabling the Microsoft Wallet App Service." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord
	}
	If ($RemovedSystemApps -contains 'Microsoft.BioEnrollment')
	{
		#****************************************************************#
		Write-Output "Disabling Biometric and Microsoft Hello Services." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" -Name "Enabled" -Value 0 -Type DWord
		If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc") { RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc" -Name "Start" -Value 4 -Type DWord }
	}
	If ($RemovedSystemApps -contains 'Microsoft.Windows.SecureAssessmentBrowser')
	{
		#****************************************************************#
		Write-Output "Disabling Text Suggestions and Screen Monitoring." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord
	}
	If ($RemovedSystemApps -contains 'Microsoft.Windows.ContentDeliveryManager')
	{
		#****************************************************************#
		Write-Output "Disabling Subscribed Content Delivery and Live Tiles." >> $RegLog
		#****************************************************************#
		@("SubscribedContent-202914Enabled", "SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled",
			"SubscribedContent-310091Enabled", "SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314381Enabled", "SubscribedContent-314559Enabled",
			"SubscribedContent-314563Enabled", "SubscribedContent-338380Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled",
			"SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled", "SubscribedContent-353698Enabled", "SubscribedContent-8800010Enabled",
			"ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RemediationRequired",
			"RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContentEnabled") | ForEach-Object -Process { RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $($_) -Value 0 -Type DWord }
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
	}
	#****************************************************************#
	Write-Output "Disabling Microsoft Toast and Lockscreen Notifications." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Disabling Connected Drive Autoplay and Autorun." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
	#****************************************************************#
	Write-Output "Disabling Automatic Download File Blocking." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Disabling the Modern UI Swap File." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Value 0 -Type DWord
	#****************************************************************#
	If ($InstallInfo.Build -ge '18362')
	{
		#****************************************************************#
		Write-Output "Disabling Reserved Storage." >> $RegLog
		#****************************************************************#
		@("BaseHardReserveSize", "BaseSoftReserveSize", "HardReserveAdjustment", "MinDiskSize", "PassedPolicy", "ShippedWithReserves", "TiAttemptedInitialization") | ForEach-Object -Process { RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name $($_) -Value 0 -Type QWord }
	}
	#****************************************************************#
	Write-Output "Disabling the Automatic Clean-up of Downloads by Storage Sense." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersionStorageSense\Parameters\StoragePolicy" -Name "512" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Disabling the First Log-on Animation." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Disabling the Windows Start-up Sound." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Optimizing Taskbar Icons and Transparency." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Setting File Explorer to Open to This PC and Disabling Recently and Frequently Used Folders." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord
	#****************************************************************#
	If ($InstallInfo.Build -ge '18362')
	{
		#****************************************************************#
		Write-Output "Disabling the Sign-in Screen Acrylic Blur." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Value 1 -Type DWord
	}
	#****************************************************************#
	Write-Output "Removing the '-Shortcut' Trailing Text for Shortcuts." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value (0, 0, 0, 0) -Type Binary
	#****************************************************************#
	If (!$DynamicParams.LTSC -and !$DynamicParams.MicrosoftEdge)
	{
		#****************************************************************#
		Write-Output "Disabling the Microsoft Edge Desktop Shortcut Creation." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord
		#****************************************************************#
		Write-Output "Disabling the Microsoft Edge Start-up Pre-Launch." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord
	}
	#****************************************************************#
	Write-Output "Disabling the Windows Store and Windows Mail Icons from Taskbar." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord
	#****************************************************************#
	Write-Output "Disabling the People Icon from Taskbar." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Reducing Start Menu Delay." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "MenuShowDelay" -Value 50 -Type String
	#****************************************************************#
	Write-Output "Enabling TaskBar Icon Combining." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Enabling Small TaskBar Icons." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Disabling the 'How do you want to open this file?' Prompt." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Adding the Classic Personalization Panel and Classic Control Panel Icons." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "(default)" -Value "Personalization (Classic)" -Type String
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "InfoTip" -Value "@%SystemRoot%\\System32\\themecpl.dll,-2#immutable1" -Type ExpandString
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "System.ApplicationName" -Value "Microsoft.Personalization" -Type String
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "System.ControlPanel.Category" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "System.Software.TasksFileUrl" -Value "Internal" -Type String
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\DefaultIcon" -Name "(default)" -Value "%SystemRoot%\\System32\\themecpl.dll,-1" -Type ExpandString
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\shell\Open\Command" -Name "(default)" -Value "explorer.exe shell:::{ED834ED6-4B5A-4bfe-8F11-A626DCB6A921}" -Type String
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "(default)" -Value "Personalization" -Type String
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord
	#****************************************************************#
	If ($InstallInfo.Build -ge '17763')
	{
		#****************************************************************#
		Write-Output "Enabling the Floating Immersive Control Panel." >> $RegLog
		#****************************************************************#
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "ImmersiveSearch" -Value 1 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Flighting\Override" -Name "CenterScreenRoundedCornerRadius" -Value 9 -Type DWord
		RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Flighting\Override" -Name "ImmersiveSearchFull" -Value 1 -Type DWord
	}
	#****************************************************************#
	Write-Output "Adding 'This PC' Icon to Desktop." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Removing 'Edit with Paint 3D and 3D Print' from the Context Menu." >> $RegLog
	#****************************************************************#
	@('.3mf', '.bmp', '.fbx', '.gif', '.jfif', '.jpe', '.jpeg', '.jpg', '.png', '.tif', '.tiff') | ForEach-Object -Process { Purge -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\shell\3D Edit" }
	@('.3ds', '.3mf', '.dae', '.dxf', '.obj', '.ply', '.stl', '.wrl') | ForEach-Object -Process { Purge -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\shell\3D Print" }
	#****************************************************************#
	If ($RemovedAppxPackages -contains 'Microsoft.Windows.Photos')
	{
		#****************************************************************#
		Write-Output "Restoring Windows Photo Viewer." >> $RegLog
		#****************************************************************#
		@('.bmp', '.cr2', '.dib', '.gif', '.ico', '.jfif', '.jpe', '.jpeg', '.jpg', '.jxr', '.png', '.tif', '.tiff', '.wdp') | ForEach-Object -Process {
			RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String
			RegKey -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value 0 -Type Binary
		}
		@('Paint.Picture', 'giffile', 'jpegfile', 'pngfile') | ForEach-Object -Process {
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open" -Name "MuiVerb" -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" -Type ExpandString
			RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type ExpandString
		}
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043" -Type String
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type ExpandString
		RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Type String
	}
	#****************************************************************#
	Write-Output "Removing User Folders from This PC and Explorer." >> $RegLog
	#****************************************************************#
	@("HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}",
		"HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
		"HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}", "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}",
		"HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}",
		"HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}", "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}",
		"HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}",
		"HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}", "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",
		"HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",
		"HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}", "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",
		"HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",
		"HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}", "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",
		"HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}", "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}") | Purge
	#****************************************************************#
	Write-Output "Increasing the Icon Cache Size." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 8192 -Type String
	#****************************************************************#
	Write-Output "Disabling Automatic Thumbnail Cache Removal." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -Value 0 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -Value 0 -Type DWord
	#****************************************************************#
	Write-Output "Disabling the Sticky Keys Prompt." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type String
	#****************************************************************#
	Write-Output "Disabling Enhanced Pointer Precision." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\Mouse" -Name "MouseSpeed" -Value 0 -Type String
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0 -Type String
	RegKey -Path "HKLM:\WIM_HKCU\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0 -Type String
	#****************************************************************#
	Write-Output "Removing 'Give Access To' from the Context Menu." >> $RegLog
	#****************************************************************#
	@("HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\Sharing",
		"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\CopyHookHandlers\Sharing",
		"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Sharing",
		"HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",
		"HKLM:\WIM_HKLM_SOFTWARE\Classes\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing") | Purge
	#****************************************************************#
	Write-Output "Removing 'Share' from the Context Menu." >> $RegLog
	#****************************************************************#
	"HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ModernSharing" | Purge
	#****************************************************************#
	Write-Output "Removing 'Cast To Device' from the Context Menu." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu" -Type String
	#****************************************************************#
	Write-Output "Removing 'Restore Previous Versions' from the Context Menu." >> $RegLog
	#****************************************************************#
	@("HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}", "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
		"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}") | Purge
	#****************************************************************#
	Write-Output "Removing 'Restore Previous Versions' from Properties." >> $RegLog
	#****************************************************************#
	@("HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}", "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
		"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}") | Purge
	#****************************************************************#
	Write-Output "Enabling Long File Paths." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type DWord
	#****************************************************************#
	Write-Output "Enabling Strong Cryptography for .NET Applications." >> $RegLog
	#****************************************************************#
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
	RegKey -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
	#****************************************************************#
	RegHives -Unload
}
#endregion Registry Optimizations

If ($Additional.IsPresent -and (Test-Path -Path $AdditionalJsonPath))
{
	Clear-Host
	$ContentJson = Get-Content -Path $AdditionalJsonPath -Raw | ConvertFrom-Json
	If ($ContentJson.Integrate.Setup -and (Test-Path -Path "$AdditionalPath\Setup\*"))
	{
		$Host.UI.RawUI.WindowTitle = "Applying Setup Content."
		Log -Info "Applying Setup Content."
		"$InstallMount\Windows\Setup\Scripts" | Create
		Get-ChildItem -Path "$AdditionalPath\Setup" -Exclude RebootRecovery.png, RefreshExplorer.png, README.md | Copy-Item -Destination "$InstallMount\Windows\Setup\Scripts" -Recurse
		Start-Sleep 3
	}
	If ($ContentJson.Integrate.Wallpaper -and (Test-Path -Path "$AdditionalPath\Wallpaper\*"))
	{
		$Host.UI.RawUI.WindowTitle = "Applying Wallpaper."
		Log -Info "Applying Wallpaper."
		Get-ChildItem -Path "$AdditionalPath\Wallpaper" -Directory | Copy-Item -Destination "$InstallMount\Windows\Web\Wallpaper" -Recurse
		Get-ChildItem -Path "$AdditionalPath\Wallpaper\*" -Include *.jpg, *.png, *.bmp, *.gif -File | Copy-Item -Destination "$InstallMount\Windows\Web\Wallpaper"
		Start-Sleep 3
	}
	If ($ContentJson.Integrate.SystemLogo -and (Test-Path -Path "$AdditionalPath\SystemLogo\*.bmp"))
	{
		$Host.UI.RawUI.WindowTitle = "Applying System Logo."
		Log -Info "Applying System Logo."
		"$InstallMount\Windows\System32\oobe\info\logo" | Create
		Copy-Item -Path "$AdditionalPath\SystemLogo\*.bmp" -Destination "$InstallMount\Windows\System32\oobe\info\logo" -Recurse
		Start-Sleep 3
	}
	If ($ContentJson.Integrate.LockScreen -and (Test-Path -Path "$AdditionalPath\LockScreen\*.jpg"))
	{
		$Host.UI.RawUI.WindowTitle = "Applying LockScreen."
		Log -Info "Applying LockScreen."
		SetLock
	}
	If ($ContentJson.Integrate.RegistryTemplates -and (Test-Path -Path "$AdditionalPath\RegistryTemplates\*.reg"))
	{
		$Host.UI.RawUI.WindowTitle = "Importing Registry Templates."
		Log -Info "Importing Registry Templates."
		RegImport
	}
	If ($ContentJson.Integrate.Unattend -and (Test-Path -Path "$AdditionalPath\Unattend\unattend.xml"))
	{
		Try
		{
			$Host.UI.RawUI.WindowTitle = "Applying Answer File."
			Log -Info "Applying Answer File."
			$ApplyUnattendParams = @{
				UnattendPath     = "$AdditionalPath\Unattend\unattend.xml"
				Path             = $InstallMount
				ScratchDirectory = $ScratchDirectory
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			[Void](Use-WindowsUnattend @ApplyUnattendParams)
			"$InstallMount\Windows\Panther" | Create
			Copy-Item -Path "$AdditionalPath\Unattend\unattend.xml" -Destination "$InstallMount\Windows\Panther" -Force
			Start-Sleep 3
		}
		Catch
		{
			Log -Error "Failed to Apply Answer File." -ErrorRecord $Error[0]
			"$InstallMount\Windows\Panther" | Purge
			Start-Sleep 3
		}
	}
	If ($ContentJson.Integrate.Drivers)
	{
		If (Get-ChildItem -Path "$AdditionalPath\Drivers\Install" -Filter *.inf -Recurse)
		{
			Try
			{
				$Host.UI.RawUI.WindowTitle = "Injecting Driver Packages into $($InstallInfo.Name)"
				Log -Info "Injecting Driver Packages into $($InstallInfo.Name)"
				$InstallDriverParams = @{
					Path             = $InstallMount
					Driver           = "$AdditionalPath\Drivers\Install"
					Recurse          = $true
					ForceUnsigned    = $true
					ScratchDirectory = $ScratchDirectory
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Add-WindowsDriver @InstallDriverParams)
				$DynamicParams.Add('InstallDrivers', $true)
			}
			Catch
			{
				Log -Error "Failed to Inject Driver Packages into $($InstallInfo.Name)" -ErrorRecord $Error[0]
				Start-Sleep 3
			}
		}
		If ($DynamicParams.Boot -and (Get-ChildItem -Path "$AdditionalPath\Drivers\Boot" -Filter *.inf -Recurse))
		{
			Try
			{
				$Host.UI.RawUI.WindowTitle = "Injecting Driver Packages into $($BootInfo.Name)"
				Log -Info "Injecting Driver Packages into $($BootInfo.Name)"
				$BootDriverParams = @{
					Path             = $BootMount
					Driver           = "$AdditionalPath\Drivers\Boot"
					Recurse          = $true
					ForceUnsigned    = $true
					ScratchDirectory = $ScratchDirectory
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Add-WindowsDriver @BootDriverParams)
				$DynamicParams.Add('BootDrivers', $true)
			}
			Catch
			{
				Log -Error "Failed to Inject Driver Packages into $($BootInfo.Name)" -ErrorRecord $Error[0]
				Start-Sleep 3
			}
		}
		If ($DynamicParams.Recovery -and (Get-ChildItem -Path "$AdditionalPath\Drivers\Recovery" -Filter *.inf -Recurse))
		{
			Try
			{
				$Host.UI.RawUI.WindowTitle = "Injecting Driver Packages into $($RecoveryInfo.Name)"
				Log -Info "Injecting Driver Packages into $($RecoveryInfo.Name)"
				$RecoveryDriverParams = @{
					Path             = $RecoveryMount
					Driver           = "$AdditionalPath\Drivers\Recovery"
					Recurse          = $true
					ForceUnsigned    = $true
					ScratchDirectory = $ScratchDirectory
					LogPath          = $DISMLog
					ErrorAction      = 'Stop'
				}
				[Void](Add-WindowsDriver @RecoveryDriverParams)
				$DynamicParams.Add('RecoveryDrivers', $true)
			}
			Catch
			{
				Log -Error "Failed to Inject Driver Packages into $($RecoveryInfo.Name)" -ErrorRecord $Error[0]
				Start-Sleep 3
			}
		}
	}
	If ($ContentJson.Integrate.NetFx3 -and $DynamicParams.ISOMedia -and (Get-WindowsOptionalFeature -Path $InstallMount -FeatureName NetFx3 | Where-Object -Property State -EQ DisabledWithPayloadRemoved) -and (Get-ChildItem -Path "$($ISOMedia.FullName)\sources\sxs" -Filter *netfx3*.cab -Recurse))
	{
		Try
		{
			$Host.UI.RawUI.WindowTitle = "Enabling Windows Feature: NetFx3"
			Log -Info "Enabling Windows Feature: NetFx3"
			$EnableNetFx3Params = @{
				Path             = $InstallMount
				FeatureName      = 'NetFx3'
				Source           = "$($ISOMedia.FullName)\sources\sxs"
				All              = $true
				LimitAccess      = $true
				NoRestart        = $true
				ScratchDirectory = $ScratchDirectory
				LogPath          = $DISMLog
				ErrorAction      = 'Stop'
			}
			[Void](Enable-WindowsOptionalFeature @EnableNetFx3Params)
			$DynamicParams.Add('NetFx3', $true)
		}
		Catch
		{
			Log -Error "Failed to Enable Windows Feature: NetFx3" -ErrorRecord $Error[0]
			Start-Sleep 3
		}
	}
}

Try
{
	$Host.UI.RawUI.WindowTitle = "Cleaning-up the Start Menu Layout."
	Log -Info "Cleaning-up the Start Menu Layout."
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
	If ($RemovedSystemApps -contains 'c5e2524a-ea46-4f67-841f-6a9465d9d515')
	{
		$LayoutModTemplate = $LayoutModTemplate -replace 'UWP File Explorer.lnk', 'File Explorer.lnk'
	}
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
	$Host.UI.RawUI.WindowTitle = "Creating a Package Summary Log."
	Log -Info "Creating a Package Summary Log."
	$PackageLog = New-Item -Path $PackageLog -ItemType File
	If ($DynamicParams.WindowsStore) { "`tIntegrated Appx Provisioned Packages", (Get-AppxProvisionedPackage -Path $InstallMount | Select-Object -Property PackageName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
	If ($DynamicParams.DeveloperMode -or $DynamicParams.MicrosoftEdge -or $DynamicParams.DataDeduplication -or $DynamicParams.NetFx3) { "`tIntegrated Windows Packages", (Get-WindowsPackage -Path $InstallMount | Where-Object { $_.PackageName -like "*DeveloperMode*" -or $_.PackageName -like "*Internet-Browser*" -or $_.PackageName -like "*Windows-FileServer-ServerCore*" -or $_.PackageName -like "*Windows-Dedup*" -or $_.PackageName -like "*NetFx3*" } | Select-Object -Property PackageName, PackageState) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
	If ($DynamicParams.InstallDrivers) { "`tIntegrated Drivers (Install)", (Get-WindowsDriver -Path $InstallMount | Select-Object -Property ProviderName, ClassName, BootCritical, Date, Version | Sort-Object -Property ProviderName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
	If ($DynamicParams.BootDrivers) { "`tIntegrated Drivers (Boot)", (Get-WindowsDriver -Path $BootMount | Select-Object -Property ProviderName, ClassName, BootCritical, Date, Version | Sort-Object -Property ProviderName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
	If ($DynamicParams.RecoveryDrivers) { "`tIntegrated Drivers (Recovery)", (Get-WindowsDriver -Path $RecoveryMount | Select-Object -Property ProviderName, ClassName, BootCritical, Date, Version | Sort-Object -Property ProviderName) | Out-File -FilePath $PackageLog.FullName -Append -Encoding UTF8 }
}

If ((Repair-WindowsImage -Path $InstallMount -CheckHealth).ImageHealthState -eq 'Healthy')
{
	Log -Info "Post-Optimization Image Health State: [Healthy]"
	@"
This $($InstallInfo.Name) installation was optimized with $($ScriptInfo.Name) version $($ScriptInfo.Version) on
$(Get-Date -UFormat "%m/%d/%Y at %r")
"@ | Out-File -FilePath (Join-Path -Path $InstallMount -ChildPath Optimize-Offline.txt) -Encoding Unicode -Force
	Start-Sleep 3
}
Else
{
	Log -Error "The image has been flagged for corruption. Discarding optimizations."
	Stop; Break
}

If ($DynamicParams.Boot)
{
	Try
	{
		Cleanup -Boot
		$Host.UI.RawUI.WindowTitle = "Saving and Dismounting $($BootInfo.Name)"
		Log -Info "Saving and Dismounting $($BootInfo.Name)"
		$DismountBootParams = @{
			Path             = $BootMount
			Save             = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Dismount-WindowsImage @DismountBootParams)
	}
	Catch
	{
		Log -Error "Failed to Save and Dismount $($BootInfo.Name)" -ErrorRecord $Error[0]
		Stop; Break
	}
}

If ($DynamicParams.Recovery)
{
	Try
	{
		Cleanup -Recovery
		$Host.UI.RawUI.WindowTitle = "Saving and Dismounting $($RecoveryInfo.Name)"
		Log -Info "Saving and Dismounting $($RecoveryInfo.Name)"
		$DismountRecoveryParams = @{
			Path             = $RecoveryMount
			Save             = $true
			ScratchDirectory = $ScratchDirectory
			LogPath          = $DISMLog
			ErrorAction      = 'Stop'
		}
		[Void](Dismount-WindowsImage @DismountRecoveryParams)
	}
	Catch
	{
		Log -Error "Failed to Save and Dismount $($RecoveryInfo.Name)" -ErrorRecord $Error[0]
		Stop; Break
	}
}

If ($DynamicParams.Boot)
{
	Try
	{
		$Host.UI.RawUI.WindowTitle = "Rebuilding and Exporting $($BootInfo.Name)"
		Log -Info "Rebuilding and Exporting $($BootInfo.Name)"
		Get-WindowsImage -ImagePath $BootWim | ForEach-Object -Process {
			$ExportBootParams = @{
				SourceImagePath      = $BootWim
				SourceIndex          = $_.ImageIndex
				DestinationImagePath = "$WorkDirectory\boot.wim"
				ScratchDirectory     = $ScratchDirectory
				LogPath              = $DISMLog
				ErrorAction          = 'Stop'
			}
			[Void](Export-WindowsImage @ExportBootParams)
		}
		$BootWim | Purge
		Move-Item -Path "$WorkDirectory\boot.wim" -Destination $BootWim -Force
	}
	Catch
	{
		Log -Error "Failed to Export $($BootInfo.Name)" -ErrorRecord $Error[0]
		Start-Sleep 3
	}
}

If ($DynamicParams.Recovery)
{
	Try
	{
		$Host.UI.RawUI.WindowTitle = "Rebuilding and Exporting $($RecoveryInfo.Name)"
		Log -Info "Rebuilding and Exporting $($RecoveryInfo.Name)"
		$ExportRecoveryParams = @{
			SourceImagePath      = $RecoveryWim
			SourceIndex          = 1
			DestinationImagePath = "$WorkDirectory\winre.wim"
			ScratchDirectory     = $ScratchDirectory
			LogPath              = $DISMLog
			ErrorAction          = 'Stop'
		}
		[Void](Export-WindowsImage @ExportRecoveryParams)
		$WinREPath | Purge
		Move-Item -Path "$WorkDirectory\winre.wim" -Destination $WinREPath -Force
	}
	Catch
	{
		Log -Error "Failed to Export $($RecoveryInfo.Name)" -ErrorRecord $Error[0]
		Start-Sleep 3
	}
}

Try
{
	Cleanup -Install
	$Host.UI.RawUI.WindowTitle = "Saving and Dismounting $($InstallInfo.Name)"
	Log -Info "Saving and Dismounting $($InstallInfo.Name)"
	$DismountInstallParams = @{
		Path             = $InstallMount
		Save             = $true
		ScratchDirectory = $ScratchDirectory
		LogPath          = $DISMLog
		ErrorAction      = 'Stop'
	}
	[Void](Dismount-WindowsImage @DismountInstallParams)
}
Catch
{
	Log -Error "Failed to Save and Dismount $($InstallInfo.Name)" -ErrorRecord $Error[0]
	Stop; Break
}

Do
{
	$CompressionList = @('Solid', 'Maximum', 'Fast', 'None') | Select-Object -Property @{ Label = 'Compression'; Expression = { ($_) } } | Out-GridView -Title "Select Final Image Compression." -OutputMode Single
	$CompressionType = $CompressionList | Select-Object -ExpandProperty Compression
}
While ($CompressionList.Length -eq 0)

If ($CompressionType -eq 'Solid') { Write-Warning "Solid compression can take quite a while. Please be patient until it completes."; Start-Sleep 5; Clear-Host }

Try
{
	$Host.UI.RawUI.WindowTitle = "Rebuilding and Exporting $($InstallInfo.Name) using $CompressionType compression."
	Log -Info "Rebuilding and Exporting $($InstallInfo.Name) using $CompressionType compression."
	If ($CompressionType -eq 'Solid')
	{
		$RET = RunExe $DISM -Arguments @('/Export-Image /SourceImageFile:"{0}" /SourceIndex:{1} /DestinationImageFile:"{2}" /Compress:Recovery /LogPath:"{3}"' -f $InstallWim, $ImageIndex, "$ImageDirectory\install.esd", $DISMLog)
		If ($RET -eq 0) { Purge -Path $InstallWim; $ImageFiles = @('install.esd', 'boot.wim') }
		Else { Log -Error "Failed to export $($InstallInfo.Name) using $CompressionType compression."; $ImageFiles = @('install.wim', 'boot.wim') }
	}
	Else
	{
		$ExportInstallParams = @{
			SourceImagePath      = $InstallWim
			SourceIndex          = $ImageIndex
			DestinationImagePath = "$WorkDirectory\install.wim"
			CompressionType      = $CompressionType
			ScratchDirectory     = $ScratchDirectory
			LogPath              = $DISMLog
			ErrorAction          = 'Stop'
		}
		[Void](Export-WindowsImage @ExportInstallParams)
		$InstallWim | Purge
		Move-Item -Path "$WorkDirectory\install.wim" -Destination $InstallWim -Force
		$ImageFiles = @('install.wim', 'boot.wim')
	}
}
Catch
{
	Log -Error "Failed to Export $($InstallInfo.Name)" -ErrorRecord $Error[0]
	Stop; Break
}

If ($DynamicParams.ISOMedia)
{
	$Host.UI.RawUI.WindowTitle = "Optimizing the Windows Media File Structure."
	Log -Info "Optimizing the Windows Media File Structure."
	Get-ChildItem -Path $ISOMedia.FullName -Filter *.dll | Purge
	@("$($ISOMedia.FullName)\autorun.inf", "$($ISOMedia.FullName)\setup.exe", "$($ISOMedia.FullName)\ca", "$($ISOMedia.FullName)\NanoServer", "$($ISOMedia.FullName)\support",
		"$($ISOMedia.FullName)\upgrade", "$($ISOMedia.FullName)\sources\dlmanifests", "$($ISOMedia.FullName)\sources\etwproviders", "$($ISOMedia.FullName)\sources\inf",
		"$($ISOMedia.FullName)\sources\hwcompat", "$($ISOMedia.FullName)\sources\migration", "$($ISOMedia.FullName)\sources\replacementmanifests", "$($ISOMedia.FullName)\sources\servicing",
		"$($ISOMedia.FullName)\sources\servicingstackmisc", "$($ISOMedia.FullName)\sources\uup", "$($ISOMedia.FullName)\sources\vista", "$($ISOMedia.FullName)\sources\xp") | Purge
	If ($DynamicParams.NetFx3) { "$($ISOMedia.FullName)\sources\sxs" | Purge }
	@('.adml', '.mui', '.rtf', '.txt') | ForEach-Object -Process { Get-ChildItem -Path "$($ISOMedia.FullName)\sources\$($InstallInfo.Language)" -Filter *$($_) -Exclude 'setup.exe.mui' -Recurse | Purge }
	@('.dll', '.gif', '.xsl', '.bmp', '.mof', '.ini', '.cer', '.exe', '.sdb', '.txt', '.nls', '.xml', '.cat', '.inf', '.sys', '.bin', '.ait', '.admx', '.dat', '.ttf', '.cfg', '.xsd', '.rtf', '.xrm-ms') | ForEach-Object -Process { Get-ChildItem -Path "$($ISOMedia.FullName)\sources" -Filter *$($_) -Exclude @('EI.cfg', 'gatherosstate.exe', 'setup.exe', 'lang.ini', 'pid.txt', '*.clg') -Recurse | Purge }
	Get-ChildItem -Path $ImageDirectory -Include $ImageFiles -Recurse | Move-Item -Destination "$($ISOMedia.FullName)\sources" -Force
	If ($ISO)
	{
		If ($ISO -eq 'Prompt' -and (!(Test-Path -Path "$($ISOMedia.FullName)\efi\Microsoft\boot\efisys.bin"))) { Log -Error "Missing the required efisys.bin bootfile for ISO creation."; Start-Sleep 3 }
		ElseIf ($ISO -eq 'No-Prompt' -and (!(Test-Path -Path "$($ISOMedia.FullName)\efi\Microsoft\boot\efisys_noprompt.bin"))) { Log -Error "Missing the required efisys_noprompt.bin bootfile for ISO creation."; Start-Sleep 3 }
		Else
		{
			$Host.UI.RawUI.WindowTitle = "Creating a $ISO Bootable Windows Installation Media ISO."
			Log -Info "Creating a $ISO Bootable Windows Installation Media ISO."
			$NewISO = New-ISOMedia -BootType $ISO
		}
	}
}

Try
{
	$Host.UI.RawUI.WindowTitle = "Finalizing Optimizations."
	Log -Info "Finalizing Optimizations."
	$SaveDirectory = Create -Path "$PSScriptRoot\Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))" -PassThru
	If ($null -ne $NewISO.Path) { Move-Item -Path $NewISO.Path -Destination $SaveDirectory.FullName }
	Else
	{
		If ($DynamicParams.ISOMedia) { Move-Item -Path $ISOMedia.FullName -Destination $SaveDirectory.FullName }
		Else { Get-ChildItem -Path $ImageDirectory -Include $ImageFiles -Recurse | Move-Item -Destination $SaveDirectory.FullName }
	}
}
Finally
{
	$Timer.Stop()
	Start-Sleep 5
	$PassedParams = [Ordered]@{ }
	ForEach ($Key In $PSBoundParameters.Keys)
	{
		If ($PSBoundParameters.$Key -is [Array]) { $Value = $PSBoundParameters.$Key -join ',' }
		Else { $Value = $PSBoundParameters.$Key }
		$PassedParams.Add($Key, $Value)
	}
	If ($Error.Count -gt 0)
	{
		($Error | ForEach-Object -Process { [PSCustomObject] @{ Line = $_.InvocationInfo.ScriptLineNumber; Error = $_.Exception.Message } } | Format-Table -AutoSize -Wrap | Out-String).Trim() | Out-File -FilePath (Join-Path -Path $LogDirectory -ChildPath ErrorRecord.log) -Encoding UTF8 -Force
	}
	Log -Info "$($ScriptInfo.Name) completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($Error.Count)] errors." -Finalized
	$InstallInfo | Out-File -FilePath (Join-Path -Path $LogDirectory -ChildPath WimFileInfo.log) -Encoding UTF8 -Force
	$PassedParams | Out-File -FilePath (Join-Path -Path $LogDirectory -ChildPath PassedParameters.log) -Encoding UTF8 -Force
	@($DISMLog, "$Env:SystemRoot\Logs\DISM\dism.log") | Purge
	[Void](Get-ChildItem -Path $LogDirectory -Filter *.log | Compress-Archive -DestinationPath (Join-Path -Path $SaveDirectory.FullName -ChildPath OptimizeLogs.zip) -CompressionLevel Fastest)
	$TempDirectory | Purge
	[Void](Clear-WindowsCorruptMountPoint)
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable $_ -ErrorAction SilentlyContinue }
	$Host.UI.RawUI.WindowTitle = "Optimizations Complete."
}
# SIG # Begin signature block
# MIIMNgYJKoZIhvcNAQcCoIIMJzCCDCMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+NzAmLHmkVz+pRT4fmMkL7Y0
# oTCgggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
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
# b1SjZsLcQ6D0eCcFD+7I7MkcSz2ARu6wUOcxggK8MIICuAIBATBcMEUxFDASBgoJ
# kiaJk/IsZAEZFgRURUNIMRUwEwYKCZImiZPyLGQBGRYFT01OSUMxFjAUBgNVBAMT
# DU9NTklDLlRFQ0gtQ0ECExoAAAAIC4Z11vsOvFYAAAAAAAgwCQYFKw4DAhoFAKCC
# ATUwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPHLsEuLalrSLG3oIlHSX2fIuJB/
# MIHUBgorBgEEAYI3AgEMMYHFMIHCoGyAagBXAGkAbgBkAG8AdwBzACAAMQAwACAA
# UgBTADQALQBSAFMANgAgAG8AZgBmAGwAaQBuAGUAIABpAG0AYQBnAGUAIABvAHAA
# dABpAG0AaQB6AGEAdABpAG8AbgAgAHMAYwByAGkAcAB0AC6hUoBQaHR0cHM6Ly9n
# aXRodWIuY29tL0RyRW1waXJpY2lzbS9PcHRpbWl6ZS1PZmZsaW5lL3Jhdy9tYXN0
# ZXIvT3B0aW1pemUtT2ZmbGluZS5wczEwDQYJKoZIhvcNAQEBBQAEggEAJyJqBNxs
# 6C21uC8N42em9wcpzFgqVNBumftiCDUxyUzHIDFW4F7i4ZJLapuEe8rAx/l+h+4V
# RjQcajKpQQP8JQbrcML1C9idznuEWKagbp0CbOKIP0uXBIn0eDqGfFipsSh8CrDd
# s1BXDSnXZLnXZuBKaTTPfuC1A882yqbDLpPl/wuJi8Qtyczd/Ar4/yg/t4nDjgN+
# XqofPLs/88zuVuhUCZ5gz5lCgN6XM0G4DQ7+NRNk7Sg9kYdg+iAFk/NVoOYiF8d4
# e1PFPDZWT8NLE2KPTJr1mA1WV9hKprDHK9t+AXsmGsob5Pnt627i5IVfK+NLVuc0
# 5UZif11hC4TvdA==
# SIG # End signature block