#Requires -RunAsAdministrator
#Requires -Version 5
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for 64-bit Windows 10 builds RS2-RS5.
	
	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, enhanced privacy, cleaner aesthetics, increased performance and a significantly better user experience.
	
	.PARAMETER ImagePath
		The full path to a Windows Installation ISO or an install WIM file.
	
	.PARAMETER Index
		If using a multi-index image, specify the index of the image.
	
	.PARAMETER Build
		The build number of the Windows image being optimized.
	
	.PARAMETER MetroApps
		Select = Populates and outputs a Gridview list of all Provisioned Application Packages for selective removal.
		All = Automatically removes all Provisioned Application Packages.
	
	.PARAMETER SystemApps
		Populates and outputs a Gridview list of all System Applications for selective removal.
	
	.PARAMETER Registry
		Default = Applies optimized registry values into the registry hives of the image.
		Hardened = Applies the default optimized registry values as well as additional values to further increase device security and restrict non-explicit access.
	
	.PARAMETER Packages
		Populates and outputs a Gridview list of all installed Windows Capability Packages for selective removal.
	
	.PARAMETER Features
		Populates and outputs a Gridview list of all Optional Features for selective disabling.
	
	.PARAMETER DaRT
		Applies the Microsoft Diagnostic and Recovery Toolset (DaRT 10) to Windows Setup and/or Windows Recovery.
	
	.PARAMETER Drivers
		Injects driver packages placed in the Resources directory into the image.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -MetroApps "Select" -SystemApps -Registry "Default" -Packages -DaRT -Drivers "E:\Driver Folder"
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\Win10Pro.iso" -Index 3 -Build 17134 -MetroApps "All" -SystemApps -Registry "Hardened" -Packages
	
	.NOTES
		In order for Microsoft DaRT 10 to be applied to both the Windows Setup Boot Image (boot.wim), and the default Recovery Image (winre.wim), the source image used must be a full Windows 10 ISO.
		A full Windows 10 ISO, along with the use of the -DaRT switch, will enable the script to extract the boot.wim along with the install.wim during the start of the script.
		If only a WIM file is used with the -DaRT switch, DaRT 10 will only be applied to the default Recovery Image (winre.wim).
	
	.NOTES
		===========================================================================
		Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.150
		Created on:   	11/30/2017
		Created by:     BenTheGreat
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        3.2.0.0
		Last updated:	08/13/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The full path to a Windows Installation ISO or an install WIM file.')]
	[ValidateScript({
			If ((Test-Path $(Resolve-Path -Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
			ElseIf ((Test-Path $(Resolve-Path -Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
			Else { Throw "$_ is not a valid image path." }
		})]
	[Alias('ISO', 'WIM', 'Image', 'Source')]
	[string]$ImagePath,
	[Parameter(HelpMessage = 'If using a multi-index image, specify the index of the image.')]
	[ValidateRange(1, 16)]
	[int]$Index = 1,
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The build number of the Windows image being optimized.')]
	[ValidateRange(15063, 18204)]
	[int]$Build,
	[ValidateSet('Select', 'All')]
	[Alias('Appx')]
	[string]$MetroApps = 'Select',
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of all System Applications for selective removal.')]
	[switch]$SystemApps,
	[Parameter(HelpMessage = 'Sets optimized registry values into the offline registry hives.')]
	[ValidateSet('Default', 'Hardened')]
	[string]$Registry = 'Default',
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of all OnDemand and Language Packages for selective removal.')]
	[switch]$Packages,
	[Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Optional Features for selective disabling.')]
	[switch]$Features,
	[Parameter(HelpMessage = 'Applies the Microsoft Diagnostic and Recovery Toolset (DaRT 10) to Windows Setup and Windows Recovery.')]
	[switch]$DaRT,
	[Parameter(HelpMessage = 'Injects any driver packages within the Resources directory into the image.')]
	[switch]$Drivers
)

#region Script Variables
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = 'SilentlyContinue'
$TimeStamp = Get-Date -Format "MM-dd-yyyy hh:mm:ss tt"
$OScript = "Optimize-Offline"
$LogFile = "$Env:TEMP\Optimize-Offline.log"
$DISMLog = "$Env:TEMP\DISM.log"
#endregion Script Variables

#region Script Declarations
$Win32CalcPath = Join-Path -Path $PSScriptRoot -ChildPath '.\Resources\Win32Calc' -Resolve
$DaRTPath = Join-Path -Path $PSScriptRoot -ChildPath '.\Resources\DaRT' -Resolve
$DriverPath = Join-Path -Path $PSScriptRoot -ChildPath '.\Resources\Drivers' -Resolve
$NetFx3Path = Join-Path -Path $PSScriptRoot -ChildPath '.\Resources\NetFx3' -Resolve
#endregion Script Declarations

#region Helper Functions
Function Test-Admin
{
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	$IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	Write-Verbose "IsUserAdmin? $IsAdmin"
	Return $IsAdmin
}

Function Out-Log
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)]
		[string]$Content,
		[ValidateSet('Info', 'Error')]
		[string]$Level = "Info"
	)
	
	Switch ($Level)
	{
		'Info' { Write-Host $Content -ForegroundColor Cyan; $LogLevel = "INFO:" }
		'Error' { Write-Host $Content -ForegroundColor Red; $LogLevel = "ERROR:" }
	}
	Add-Content -Path $LogFile -Value "$LogLevel $Content"
}

Function Invoke-ProcessPrivilege
{
	[CmdletBinding()]
	[OutputType([System.Void])]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[string]$Privilege,
		[int]$Process = $PID,
		[switch]$Disable
	)
	
	Begin
	{
		Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class AccessTokens
{
    [DllImport("advapi32.dll",SetLastError = true)]
    static extern bool LookupPrivilegeValue(
        string host,
        string name,
        ref long luid);

    [DllImport("advapi32.dll",ExactSpelling = true,SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr token,
        bool disall,
        ref TOKEN_PRIVILEGES newst,
        int len,
        IntPtr prev,
        IntPtr relen);

    [DllImport("advapi32.dll",ExactSpelling = true,SetLastError = true)]
    static extern bool OpenProcessToken(
        IntPtr curProcess,
        int acc,
        ref IntPtr processToken);

    [DllImport("kernel32.dll",SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential,Pack = 1)]
    struct TOKEN_PRIVILEGES
    {
        public int Count;
        public long Luid;
        public int Attr;
    }

    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static void AdjustPrivilege(
        IntPtr curProcess,
        string privilege,
        bool enable)
    {
        var processToken = IntPtr.Zero;

        if (!OpenProcessToken(curProcess,TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,ref processToken))
        {
            throw new Win32Exception();
        }

        try
        {
            var privileges = new TOKEN_PRIVILEGES
            {
                Count = 1,
                Luid = 0,
                Attr = enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED,
            };

            if (!LookupPrivilegeValue(
                null,
                privilege,
                ref privileges.Luid))
            {
                throw new Win32Exception();
            }

            if (!AdjustTokenPrivileges(
                processToken,
                false,
                ref privileges,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                throw new Win32Exception();
            }
        }
        finally
        {
            CloseHandle(
                processToken);
        }
    }
}
'@
		$CurProcess = Get-Process -Id $Process
	}
	Process
	{
		[AccessTokens]::AdjustPrivilege($CurProcess.Handle, $Privilege, !$Disable)
	}
	End
	{
		$CurProcess.Close()
	}
}

Function Set-RegistryOwner
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0)]
		[string]$SubKey
	)
	Begin
	{
		$TakeOwnership = "SeTakeOwnershipPrivilege"
	}
	Process
	{
		$TakeOwnership | Invoke-ProcessPrivilege
		$Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
		$ACL = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
		$SID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
		$Admin = $SID.Translate([System.Security.Principal.NTAccount])
		$ACL.SetOwner($Admin)
		$Key.SetAccessControl($ACL)
		$TakeOwnership | Invoke-ProcessPrivilege -Disable
		$ACL = $Key.GetAccessControl()
		$ACL.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($Admin, "FullControl", "ContainerInherit", "None", "Allow")))
		$Key.SetAccessControl($ACL)
		$Key.Close()
	}
}

Function Set-FileOwnership
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)
	Invoke-Expression -Command ('TAKEOWN /F $Path /A')
	$ACL = Get-Acl -Path $Path
	$SID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
	$Admin = $SID.Translate([System.Security.Principal.NTAccount])
	$ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Admin, "FullControl", "None", "None", "Allow")))
	$ACL | Set-Acl -Path $Path
}

Function Set-FolderOwnership
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)
	Set-FileOwnership -Path $Path
	ForEach ($Object In Get-ChildItem -Path $Path -Recurse -Force)
	{
		If (Test-Path -Path $Object -PathType Container)
		{
			Set-FolderOwnership -Path $Object.FullName
		}
		Else
		{
			Set-FileOwnership -Path $Object.FullName
		}
	}
}

Function New-WorkDirectory
{
	$WorkDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "WorkOffline_$(Get-Random)"))
	$WorkDir = Get-Item -LiteralPath $ScriptDirectory\$WorkDir -Force
	$WorkDir
}

Function New-ScratchDirectory
{
	$TempDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "TempOffline_$(Get-Random)"))
	$TempDir = Get-Item -LiteralPath $ScriptDirectory\$TempDir -Force
	$TempDir
}

Function New-ImageDirectory
{
	$ImageDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "ImageOffline_$(Get-Random)"))
	$ImageDir = Get-Item -LiteralPath $ScriptDirectory\$ImageDir -Force
	$ImageDir
}

Function New-MountDirectory
{
	$MountDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "MountOffline_$(Get-Random)"))
	$MountDir = Get-Item -LiteralPath $ScriptDirectory\$MountDir -Force
	$MountDir
}

Function New-SaveDirectory
{
	$SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
	$SaveDir = Get-Item -LiteralPath $PSScriptRoot\$SaveDir
	$SaveDir
}

Function Mount-OfflineHives
{
	Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SOFTWARE `"$MountFolder\Windows\System32\config\software`"") -WindowStyle Hidden -Wait
	Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SYSTEM `"$MountFolder\Windows\System32\config\system`"") -WindowStyle Hidden -Wait
	Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKCU `"$MountFolder\Users\Default\NTUSER.DAT`"") -WindowStyle Hidden -Wait
	Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKU_DEFAULT `"$MountFolder\Windows\System32\config\default`"") -WindowStyle Hidden -Wait
}

Function Dismount-OfflineHives
{
	[System.GC]::Collect()
	Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SOFTWARE") -WindowStyle Hidden -Wait
	Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SYSTEM") -WindowStyle Hidden -Wait
	Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKCU") -WindowStyle Hidden -Wait
	Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKU_DEFAULT") -WindowStyle Hidden -Wait
}

Function Test-OfflineHives
{
	@("HKLM:\WIM_HKLM_SOFTWARE", "HKLM:\WIM_HKLM_SYSTEM", "HKLM:\WIM_HKCU", "HKLM:\WIM_HKU_DEFAULT") |
	ForEach { If (Test-Path -Path $_) { $HivesLoaded = $true } }; Return $HivesLoaded
}

Function Exit-Script
{
	Start-Sleep 3
	Write-Output ''
	Out-Log -Content "Cleaning-up and terminating script." -Level Info
	$Host.UI.RawUI.WindowTitle = "Terminating Script."
	If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $ScratchFolder -LogPath $DISMLog)
	[void](Clear-WindowsCorruptMountPoint)
	$SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]")); [void]$SaveDir
	If ($Error.Count)
	{
		$ErrorLog = Join-Path -Path $Env:TEMP -ChildPath "ErrorLog.log"
		Set-Content -Path $ErrorLog -Value $Error.ToArray() -Force
		Move-Item -Path $ErrorLog -Destination $SaveDir -Force
	}
	Add-Content -Path $LogFile -Value ''
	Add-Content -Path $LogFile -Value "***************************************************************************************************"
	Add-Content -Path $LogFile -Value "`t`t$($OScript) stopped at [$($TimeStamp)]"
	Add-Content -Path $LogFile -Value "***************************************************************************************************"
	Move-Item -Path $LogFile -Destination $SaveDir -Force
	Remove-Item -Path "$Env:TEMP\DISM.log" -Force
	Remove-Item -Path "$WorkFolder\Registry-Optimizations.log" -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
	Write-Output ''
}

Function New-Container
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)
	If (!(Test-Path -Path $Path))
	{
		[void](New-Item -Path $Path -ItemType Directory -Force)
	}
}
#endregion Helper Functions

If (!(Test-Admin)) { Write-Warning "Administrative access is required. Please re-launch $OScript with elevation."; Break }

Try
{
	Get-Module -ListAvailable Dism -ErrorAction Stop | Import-Module
}
Catch
{
	Write-Warning "Missing the required PowerShell Dism module."
	Break
}

Try
{
	Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
Finally
{
	$CreateScriptDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "OptimizeOfflineTemp_$(Get-Random)"))
	If ($CreateScriptDir) { $ScriptDirectory = Get-Item -LiteralPath $PSScriptRoot\$CreateScriptDir }
	$Host.UI.RawUI.WindowTitle = "Preparing image for optimizations."
}

If (([IO.FileInfo]$ImagePath).Extension -eq ".ISO")
{
	$ImagePath = (Resolve-Path -Path $ImagePath).ProviderPath
	$MountImage = Mount-DiskImage -ImagePath $ImagePath -StorageType ISO -PassThru
	$DriveLetter = ($MountImage | Get-Volume).DriveLetter
	$InstallWim = "$($DriveLetter):\sources\install.wim"
	$BootWim = "$($DriveLetter):\sources\boot.wim"
	If (Test-Path -Path $InstallWim -PathType Leaf)
	{
		Write-Host "Copying WIM from $(Split-Path -Path $ImagePath -Leaf)" -ForegroundColor Cyan
		[void]($MountFolder = New-MountDirectory)
		[void]($ImageFolder = New-ImageDirectory)
		[void]($WorkFolder = New-WorkDirectory)
		[void]($ScratchFolder = New-ScratchDirectory)
		Copy-Item -Path $InstallWim -Destination $ImageFolder -Force
		$InstallWim = Get-Item -Path "$ImageFolder\install.wim" -Force
		Set-ItemProperty -Path $InstallWim -Name IsReadOnly -Value $false
		If ((Test-Path -Path $BootWim -PathType Leaf) -and ($DaRT.IsPresent))
		{
			Copy-Item -Path $BootWim -Destination $ImageFolder -Force
			$BootWim = Get-Item -Path "$ImageFolder\boot.wim" -Force
			Set-ItemProperty -Path $BootWim -Name IsReadOnly -Value $false
			$BootIsPresent = $true
		}
		Dismount-DiskImage -ImagePath $ImagePath -StorageType ISO
	}
	Else
	{
		Write-Warning "$(Split-Path -Path $ImagePath -Leaf) does not contain valid Windows Installation media."
		Remove-Item -Path $ScriptDirectory -Recurse -Force
		Break
	}
}
ElseIf (([IO.FileInfo]$ImagePath).Extension -eq ".WIM")
{
	If (Test-Path -Path $ImagePath -Filter "install.wim")
	{
		$ImagePath = (Resolve-Path -Path $ImagePath).ProviderPath
		Write-Host "INFO: Copying WIM from $(Split-Path -Path $ImagePath -Parent)" -ForegroundColor Cyan
		[void]($MountFolder = New-MountDirectory)
		[void]($ImageFolder = New-ImageDirectory)
		[void]($WorkFolder = New-WorkDirectory)
		[void]($ScratchFolder = New-ScratchDirectory)
		Copy-Item -Path $ImagePath -Destination $ImageFolder -Force
		$InstallWim = Get-Item -Path "$ImageFolder\install.wim" -Force
		If ($InstallWim.IsReadOnly) { Set-ItemProperty -Path $InstallWim -Name IsReadOnly -Value $false }
	}
	Else
	{
		Write-Warning "$ImagePath is not an install.wim"
		Remove-Item -Path $ScriptDirectory -Recurse -Force
		Break
	}
}

If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force }
If (Test-Path -Path $DISMLog) { Remove-Item -Path $DISMLog -Force }
If (Test-Path -Path $LogFile) { Remove-Item -Path $LogFile -Force }

If ((Get-WindowsImage -ImagePath $InstallWim -Index $Index).Version -notlike "10.*")
{
	Write-Output ''
	Write-Error "The supplied image version is not supported: Requires Windows 10."
	Remove-Item -Path $ScriptDirectory -Recurse -Force
	Break
}
Else
{
	$CheckBuild = (Get-WindowsImage -ImagePath $InstallWim -Index $Index).Build
	[void](New-Item -Path $LogFile -ItemType File -Force)
	@"
***************************************************************************************************
			$($OScript) started at [$($TimeStamp)]
***************************************************************************************************

"@ | Out-File -FilePath $LogFile -Append -Encoding ASCII
}

If ($CheckBuild -lt '15063')
{
	Write-Output ''
	Write-Warning "The image build is not supported [$($CheckBuild.ToString())]"
	Remove-Item -Path $ScriptDirectory -Recurse -Force
	Break
}
Else
{
	Write-Output ''
	Out-Log -Content "The image build is supported [$($CheckBuild.ToString())]" -Level Info
	Start-Sleep 3
	Write-Output ''
	$Error.Clear()
	Out-Log -Content "Mounting Image." -Level Info
	$MountWindowsImage = @{
		ImagePath		    = $InstallWim
		Index			    = $Index
		Path			    = $MountFolder
		ScratchDirectory    = $ScratchFolder
		LogPath			    = $DISMLog
	}
	[void](Mount-WindowsImage @MountWindowsImage)
	$ImageIsMounted = $true
}

If ($ImageIsMounted.Equals($true))
{
	$StartHealthCheck = (Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState
	If ($StartHealthCheck -eq "Healthy")
	{
		Write-Output ''
		Out-Log -Content "The image health state has returned as [Healthy]" -Level Info
		Start-Sleep 3
	}
	Else
	{
		Write-Output ''
		Out-Log -Content "The image has been flagged for corruption. Further servicing is required before the image can be optimized." -Level Error
		Exit-Script
		Break
	}
}

If ($MetroApps)
{
	Try
	{
		$RemovedProvisionedApps = [System.Collections.ArrayList]@()
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Removing Metro Apps."
		If ($MetroApps -eq "Select")
		{
			$GetAppx = Get-AppxProvisionedPackage -Path $MountFolder
			$Int = 1
			ForEach ($Appx In $GetAppx)
			{
				$GetAppx = New-Object -TypeName PSObject
				$GetAppx | Add-Member -MemberType NoteProperty -Name Num -Value $Int
				$GetAppx | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Appx.DisplayName
				$GetAppx | Add-Member -MemberType NoteProperty -Name PackageName -Value $Appx.PackageName
				$Int++
				[void]$RemovedProvisionedApps.Add($GetAppx)
			}
			$RemoveAppx = $RemovedProvisionedApps | Out-GridView -Title "Remove Provisioned App Packages." -PassThru
			$PackageName = $RemoveAppx.PackageName
			If ($RemoveAppx)
			{
				$PackageName | ForEach {
					Out-Log -Content "Removing Provisioned App Package: $($_.Split('_')[0])" -Level Info
					$RemoveSelectAppx = @{
						Path			    = $MountFolder
						PackageName		    = $($_)
						ScratchDirectory    = $ScratchFolder
						LogPath			    = $DISMLog
						ErrorAction		    = "Stop"
					}
					[void](Remove-AppxProvisionedPackage @RemoveSelectAppx)
				}
			}
		}
		ElseIf ($MetroApps -eq "All")
		{
			Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
				Out-Log -Content "Removing Provisioned App Package: $($_.DisplayName)" -Level Info
				$RemoveAllAppx = @{
					Path			    = $MountFolder
					PackageName		    = $($_.PackageName)
					ScratchDirectory    = $ScratchFolder
					LogPath			    = $DISMLog
					ErrorAction		    = "Stop"
				}
				[void](Remove-AppxProvisionedPackage @RemoveAllAppx)
			}
		}
		$MetroAppsComplete = $true
		Clear-Host
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to remove Provisioned App Packages." -Level Error
		Exit-Script
		Break
	}
	Finally
	{
		$Int = $null
	}
}

If ($SystemApps)
{
	$RemovedSystemApps = [System.Collections.ArrayList]@()
	Try
	{
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Removing System Applications."
		Write-Warning "Do NOT remove any System Application if you are unsure of its impact on a live installation."
		Start-Sleep 5
		Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SOFTWARE `"$MountFolder\Windows\System32\config\software`"") -WindowStyle Hidden -Wait
		$InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
		$InboxApps = (Get-ChildItem -Path $InboxAppsKey).Name.Split('\') | Where { $_ -like "*Microsoft.*" }
		$SelectSystemApps = $InboxApps | Select -Property `
												@{ Label = 'Name'; Expression = { ($_.Split('_')[0]) } },
												@{ Label = 'PackageName'; Expression = { ($_) } } |
		Out-GridView -Title "Remove System Applications." -PassThru
		$AppPackage = $SelectSystemApps.PackageName
		If ($SelectSystemApps)
		{
			Clear-Host
			$AppPackage | ForEach {
				$FullKeyPath = $InboxAppsKey + '\' + $($_)
				$AppKey = $FullKeyPath.Replace("HKLM:", "HKLM")
				Out-Log -Content "Removing System Application: $($_.Split('_')[0])" -Level Info
				[void](Invoke-Expression -Command ('REG DELETE $AppKey /F') -ErrorAction Stop)
				[void]$RemovedSystemApps.Add($($_.Split('_')[0]))
				Start-Sleep 2
			}
		}
		Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SOFTWARE") -WindowStyle Hidden -Wait
		$SystemAppsComplete = $true
		Clear-Host
	}
	Catch
	{
		Out-Log -Content "Failed to remove required registry subkeys." -Level Error
		Exit-Script
		Break
	}
}

If ($Packages)
{
	$RemovedWindowsPackages = [System.Collections.ArrayList]@()
	Try
	{
		Clear-Host
		$Host.UI.RawUI.WindowTitle = "Removing Windows Capability Packages"
		$CapabilityPackages = Get-WindowsCapability -Path $MountFolder | Where State -EQ Installed
		$Int = 1
		ForEach ($CapabilityPackage In $CapabilityPackages)
		{
			$CapabilityPackages = New-Object -TypeName PSObject
			$CapabilityPackages | Add-Member -MemberType NoteProperty -Name Num -Value $Int
			$CapabilityPackages | Add-Member -MemberType NoteProperty -Name Name -Value $CapabilityPackage.Name
			$CapabilityPackages | Add-Member -MemberType NoteProperty -Name State -Value $CapabilityPackage.State
			$Int++
			[void]$RemovedWindowsPackages.Add($CapabilityPackages)
		}
		$RemovePackages = $RemovedWindowsPackages | Out-GridView -Title "Remove Windows Capability Packages." -PassThru
		$PackageName = $RemovePackages.Name
		If ($RemovePackages)
		{
			$PackageName | ForEach {
				Out-Log -Content "Removing Windows Capability Package: $($_.Split('~')[0])" -Level Info
				$CapabilityPackage = @{
					Path    = $MountFolder
					Name    = $($_)
					ScratchDirectory = $ScratchFolder
					LogPath = $DISMLog
					ErrorAction = "Stop"
				}
				[void](Remove-WindowsCapability @CapabilityPackage)
			}
		}
		Clear-Host
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to remove Windows Capability Packages." -Level Error
		Exit-Script
		Break
	}
	Finally
	{
		$Int = $null
	}
}

If ($MetroAppsComplete.Equals($true))
{
	Try
	{
		If ((Get-AppxProvisionedPackage -Path $MountFolder `
				| Where DisplayName -Match "Microsoft.Wallet").Count.Equals(0) -or (Get-AppxProvisionedPackage -Path $MountFolder `
				| Where DisplayName -Match "Microsoft.WindowsMaps").Count.Equals(0))
		{
			$Host.UI.RawUI.WindowTitle = "Disabling Provisioned App Package Services."
			Out-Log -Content "Disabling Provisioned App Package services." -Level Info
			Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SYSTEM `"$MountFolder\Windows\System32\config\system`"") -WindowStyle Hidden -Wait
			If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService")
			{
				Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
			}
			If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker")
			{
				Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
			}
			Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SYSTEM") -WindowStyle Hidden -Wait
		}
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "An error occurred removing Provisoned App Package services." -Level Error
		Exit-Script
		Break
	}
	Try
	{
		$Host.UI.RawUI.WindowTitle = "Applying a custom Start Menu and Taskbar Layout."
		Write-Output ''
		Out-Log -Content "Applying a custom Start Menu and Taskbar Layout." -Level Info
		Start-Sleep 3
		@'
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
          <start:DesktopApplicationTile Size="1x1" Column="5" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\UWP File Explorer.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="5" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk" />
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
'@ | Out-File -FilePath "$MountFolder\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -ErrorAction Stop
		Write-Output ''
		Out-Log -Content "Creating Shortcut Links." -Level Info
		Start-Sleep 3
		$UWPShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
		$UWPShortcut = $UWPShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UWP File Explorer.lnk")
		$UWPShortcut.TargetPath = "%SystemRoot%\explorer.exe"
		$UWPShortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
		$UWPShortcut.IconLocation = "imageres.dll,-1023"
		$UWPShortcut.WorkingDirectory = "%SystemRoot%"
		$UWPShortcut.Description = "The UWP File Explorer Application."
		$UWPShortcut.Save()
		$UEFIShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
		$UEFIShortcut = $UEFIShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk")
		$UEFIShortcut.TargetPath = "%SystemRoot%\System32\shutdown.exe"
		$UEFIShortcut.Arguments = "/R /FW"
		$UEFIShortcut.IconLocation = "bootux.dll,-1016"
		$UEFIShortcut.WorkingDirectory = "%SystemRoot%\System32"
		$UEFIShortcut.Description = "Reboot directly into the system's UEFI firmware."
		$UEFIShortcut.Save()
		$Bytes = [System.IO.File]::ReadAllBytes("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk")
		$Bytes[0x15] = $Bytes[0x15] -bor 0x20
		[System.IO.File]::WriteAllBytes("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk", $Bytes)
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to apply a custom Start Menu and Taskbar Layout." -Level Error
		Exit-Script
		Break
	}
}

If ($RemovedSystemApps -contains "Microsoft.Windows.SecHealthUI")
{
	Try
	{
		$Host.UI.RawUI.WindowTitle = "Removing Windows Defender Remnants."
		Write-Output ''
		Out-Log -Content "Disabling Windows Defender services and drivers." -Level Info
		[void](Mount-OfflineHives)
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWord -ErrorAction Stop
		If ((Get-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run") -match "SecurityHealth")
		{
			Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction Stop
		}
		@("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach {
			If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_")
			{
				Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
			}
		}
		[void](Dismount-OfflineHives)
		Start-Sleep 3
		If ((Get-WindowsOptionalFeature -Path $MountFolder -FeatureName "Windows-Defender-Default-Definitions").State -eq "Enabled")
		{
			Write-Output ''
			Out-Log -Content "Disabling Windows Optional Feature: Windows-Defender-Default-Defintions" -Level Info
			$DisableDefenderFeature = @{
				Path			    = $MountFolder
				FeatureName		    = "Windows-Defender-Default-Definitions"
				ScratchDirectory    = $ScratchFolder
				LogPath			    = $DISMLog
				ErrorAction		    = "Stop"
			}
			[void](Disable-WindowsOptionalFeature @DisableDefenderFeature)
		}
		$DisableDefenderComplete = $true
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to disable remaining Windows Defender services and drivers." -Level Error
		Exit-Script
		Break
	}
}

If ($MetroApps -eq "All" -or $RemovedSystemApps -contains "Microsoft.XboxGameCallableUI" -or ((Get-AppxProvisionedPackage -Path $MountFolder | Where PackageName -Like "*Xbox*").Count -lt 5))
{
	Try
	{
		$Host.UI.RawUI.WindowTitle = "Removing Xbox Remnants."
		Write-Output ''
		Out-Log -Content "Disabling Xbox services and drivers." -Level Info
		[void](Mount-OfflineHives)
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord -ErrorAction Stop
		@("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach {
			If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_")
			{
				Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
			}
		}
		[void](Dismount-OfflineHives)
		Start-Sleep 3
		$DisableXboxComplete = $true
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to disable Xbox services and drivers." -Level Error
		Exit-Script
		Break
	}
}

#region Registry Optimizations
If ($Registry)
{
	Try
	{
		If (Test-Path -Path "$WorkFolder\Registry-Optimizations.log") { Remove-Item -Path "$WorkFolder\Registry-Optimizations.log" -Force }
		Write-Output ''
		$Host.UI.RawUI.WindowTitle = "Applying registry optimizations."
		Out-Log -Content "Applying registry optimizations." -Level Info
		[void](Mount-OfflineHives)
		#****************************************************************
		Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\InputPersonalization\TrainedDataStore" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Cortana Outgoing Network Traffic." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ErrorAction Stop
		$CortanaUriServer = @{
			Path	 = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name	 = "Block Cortana ActionUriServer.exe"
			Value    = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe|Name=Block Cortana ActionUriServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
			Type	 = "String"
		}
		Set-ItemProperty @CortanaUriServer
		$CortanaPlacesServer = @{
			Path	 = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name	 = "Block Cortana PlacesServer.exe"
			Value    = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe|Name=Block Cortana PlacesServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
			Type	 = "String"
		}
		Set-ItemProperty @CortanaPlacesServer
		$CortanaReminderServer = @{
			Path	 = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name	 = "Block Cortana RemindersServer.exe"
			Value    = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
			Type	 = "String"
		}
		Set-ItemProperty @CortanaReminderServer
		$CortanaReminderApp = @{
			Path	 = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name	 = "Block Cortana RemindersShareTargetApp.exe"
			Value    = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe|Name=Block Cortana RemindersShareTargetApp.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
			Type	 = "String"
		}
		Set-ItemProperty @CortanaReminderApp
		$CortanaSearchUI = @{
			Path	 = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name	 = "Block Cortana SearchUI.exe"
			Value    = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block Cortana SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
			Type	 = "String"
		}
		Set-ItemProperty @CortanaSearchUI
		$CortanaPackage = @{
			Path	 = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
			Name	 = "Block Cortana Package"
			Value    = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Cortana Package|Desc=Block Cortana Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|Platform=2:6:2|Platform2=GTEQ|"
			Type	 = "String"
		}
		Set-ItemProperty @CortanaPackage
		#****************************************************************
		Write-Output "Disabling System Telemetry and Data Collecting." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Office 2016 Telemetry and Logging." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling 'Find My Device'." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Enabling PIN requirement for pairing devices." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord
		#****************************************************************
		If ($Build -lt '17134')
		{
			#****************************************************************
			Write-Output "Disabling HomeGroup Services." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupListener" -Name "Start" -Value 4 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupProvider" -Name "Start" -Value 4 -Type DWord
		}
		#****************************************************************
		Write-Output "Disabling Text Suggestions and Screen Monitoring." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Steps Recorder." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Compatibility Assistant." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Windows Asking for Feedback." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling the Password Reveal button." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Windows Media Player Statistics Tracking." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Microsoft Windows Media Digital Rights Management." >> "$WorkFolder\Registry-Optimizations.log"
		#***************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord
		#***************************************************************
		Write-Output "Disabling Advertisement ID." >> "$WorkFolder\Registry-Optimizations.log"
		#***************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
		#***************************************************************
		Write-Output "Enabling the MeltDown (CVE-2017-5754) Compatibility Flag." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "CADCA5FE-87D3-4B96-B7FB-A231484277CC" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Explorer Tips, Sync Notifications and Document Tracking." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FolderContentsInfoTip" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableBalloonTips" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StartButtonBalloonTip" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentProgForNewUserInStartMenu" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling System Advertisements and Windows Spotlight." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "IncludeEnterpriseSpotlight" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Toast Notifications." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Feature Advertisement Notifications." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoBalloonFeatureAdvertisements" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling System Tray Promotion Notifications." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoSystraySystemPromotion" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Typing Data Telemetry." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Automatic Download of Content, Ads and Suggestions." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ErrorAction Stop
		@("ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RotatingLockScreenEnabled",
			"RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContent-202914Enabled",
			"SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled", "SubscribedContent-310091Enabled",
			"SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314381Enabled", "SubscribedContent-314559Enabled", "SubscribedContent-314563Enabled",
			"SubscribedContent-338380Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled",
			"SubscribedContent-353698Enabled") | ForEach {
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_ -Value 0 -Type DWord -ErrorAction Stop
		}
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceAppSuggestionsEnabled" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Explorer Ads and Tips." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Windows 'Getting to Know Me' and Tablet Mode Keylogging." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord
		#***************************************************************
		Write-Output "Disabling the Windows Insider Program and its Telemetry." >> "$WorkFolder\Registry-Optimizations.log"
		#***************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Notifications on Lock Screen." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Lock Screen Camera and Overlays." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Map Auto Downloads." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Speech Model Updates." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling First Log-on Animation." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Changing Search Bar Icon to Magnifying Glass Icon." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Moving Drive Letter Before Drive Label." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord
		#****************************************************************
		If ($Build -lt '17686')
		{
			#****************************************************************	
			Write-Output "Enabling Dark Theme for Settings and Modern Apps." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
		}
		#****************************************************************
		Write-Output "Enabling Dark Inactive Window Borders." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\DWM" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\DWM" -Name "AccentColor" -Value 4282927692 -Type DWord
		#****************************************************************
		Write-Output "Increasing Taskbar and Theme Transparency." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord
		#****************************************************************
		Write-Output "Disabling 'Shortcut' text for Shortcuts." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value 00000000 -Type Binary
		#****************************************************************
		Write-Output "Enabling Explorer opens to This PC." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord
		#****************************************************************
		If ($Build -ge '17134')
		{
			#****************************************************************	
			Write-Output "Removing Microsoft Edge Desktop Shortcut Creation." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord
		}
		#****************************************************************
		Write-Output "Removing Windows Store Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Removing Windows Mail Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord
		#****************************************************************
		Write-Output "Disabling the Windows Mail Application." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord
		#****************************************************************
		If ($Build -ge '16273')
		{
			#****************************************************************	
			Write-Output "Removing People Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type DWord
		}
		#****************************************************************
		Write-Output "Disabling 'How do you want to open this file?' prompt." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Switching to Smaller Control Panel Icons." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Adding This PC Icon to Desktop." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ErrorAction Stop
		$NewStartPanel = @{
			Path	 = "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
			Name	 = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
			Value    = 0
			Type	 = "DWord"
		}
		Set-ItemProperty @NewStartPanel
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ErrorAction Stop
		$ClassicStartMenu = @{
			Path	 = "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
			Name	 = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
			Value    = 0
			Type	 = "DWord"
		}
		Set-ItemProperty @ClassicStartMenu
		#****************************************************************
		Write-Output "Adding 'Reboot to Recovery' to My PC." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-RegistryOwner -SubKey "WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" -Name "Icon" -Value "%SystemRoot%\System32\imageres.dll,-110" -Type ExpandString
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" -Name "(default)" -Value "SHUTDOWN.EXE -R -O -F -T 00" -Type String
		#****************************************************************
		Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Disabling Live Tiles." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Connected Drive Autoplay and Autorun." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord
		#****************************************************************
		If ($Build -ge '16273')
		{
			#****************************************************************	
			Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			@("HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.glb\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit") | ForEach {
				Remove-Item -Path $_ -Recurse -Force -ErrorAction Stop
			}
		}
		ElseIf ($Build -lt '16273')
		{
			#****************************************************************	
			Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			@("HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit") | ForEach {
				Remove-Item -Path $_ -Recurse -Force -ErrorAction Stop
			}
		}
		If ($Build -ge "15063")
		{
			#****************************************************************	
			Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			@("HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3ds\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Print",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dae\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dxf\Shell\3D Print",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Print",
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.wrl\Shell\3D Print") | ForEach {
				Remove-Item -Path $_ -Recurse -Force -ErrorAction Stop
			}
		}
		#****************************************************************
		Write-Output "Restoring Windows Photo Viewer." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		@(".bmp", ".gif", ".jfif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".wdp") | ForEach {
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value (New-Object Byte[] 0) -Type Binary
		}
		#****************************************************************
		Write-Output "Removing 'Restore Previous Versions' from the Property Tab and Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		@("HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}") | ForEach {
			Remove-Item -Path $_ -Recurse -Force -ErrorAction Stop
		}
		#****************************************************************
		Write-Output "Removing 'Share' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -Value "" -Type String
		#****************************************************************
		Write-Output "Removing 'Give Access To' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" -Value "" -Type String
		#****************************************************************
		Write-Output "Removing 'Cast To Device' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "" -Type String
		#****************************************************************
		Write-Output "Removing Recently and Frequently Used Items in Explorer." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord
		#****************************************************************
		Write-Output "Removing all User Folders from This PC." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		If ($Build -ge '16273')
		{
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		}
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String
		#****************************************************************
		Write-Output "Removing Drives from the Navigation Pane." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" -ErrorAction Stop
		Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" -ErrorAction Stop
		#****************************************************************
		Write-Output "Cleaning-up Windows Control Panel Links." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowCpl" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "1" -Value "Microsoft.OfflineFiles" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "2" -Value "Microsoft.EaseOfAccessCenter" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "3" -Value "Microsoft.PhoneAndModem" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "4" -Value "Microsoft.RegionAndLanguage" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "5" -Value "Microsoft.ScannersAndCameras" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "6" -Value "Microsoft.SpeechRecognition" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "7" -Value "Microsoft.SyncCenter" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "8" -Value "Microsoft.Infrared" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "9" -Value "Microsoft.ColorManagement" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "10" -Value "Microsoft.Fonts" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "11" -Value "Microsoft.Troubleshooting" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "12" -Value "Microsoft.InternetOptions" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "13" -Value "Microsoft.HomeGroup" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "14" -Value "Microsoft.DateAndTime" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "15" -Value "Microsoft.AutoPlay" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "16" -Value "Microsoft.DeviceManager" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "17" -Value "Microsoft.FolderOptions" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "18" -Value "Microsoft.RegionAndLanguage" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "19" -Value "Microsoft.TaskbarAndStartMenu" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "20" -Value "Microsoft.PenAndTouch" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "21" -Value "Microsoft.BackupAndRestore" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "22" -Value "Microsoft.DevicesAndPrinters" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "23" -Value "Microsoft.WindowsDefender" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "24" -Value "Microsoft.WorkFolders" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "25" -Value "Microsoft.WindowsAnytimeUpgrade" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "26" -Value "Microsoft.Language" -Type String
		#****************************************************************
		If ($Build -ge '16273')
		{
			#****************************************************************	
			Write-Output "Cleaning-up Immersive Control Panel Settings Links." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
			If ($SystemAppsComplete -eq $true -and $RemovedSystemApps -contains "Microsoft.Windows.SecHealthUI")
			{
				$ImmersiveLinks = @{
					Path	 = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
					Name	 = "SettingsPageVisibility"
					Value    = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsinsider;windowsdefender"
					Type	 = "String"
				}
				Set-ItemProperty @ImmersiveLinks
			}
			Else
			{
				$ImmersiveLinks = @{
					Path	 = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
					Name	 = "SettingsPageVisibility"
					Value    = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsinsider"
					Type	 = "String"
				}
				Set-ItemProperty @ImmersiveLinks
			}
		}
		ElseIf ($Build -lt '16273')
		{
			#****************************************************************	
			Write-Output "Cleaning-up Immersive Control Panel Settings Links." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
			If ($SystemAppsComplete -eq $true -and $RemovedSystemApps -contains "Microsoft.Windows.SecHealthUI")
			{
				$ImmersiveLinks = @{
					Path	 = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
					Name	 = "SettingsPageVisibility"
					Value    = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsinsider;windowsdefender"
					Type	 = "String"
				}
				Set-ItemProperty @ImmersiveLinks
			}
			Else
			{
				$ImmersiveLinks = @{
					Path	 = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
					Name	 = "SettingsPageVisibility"
					Value    = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsinsider"
					Type	 = "String"
				}
				Set-ItemProperty @ImmersiveLinks
			}
		}
		#****************************************************************
		Write-Output "Disabling Recent Document History." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Automatic Sound Reduction." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord
		#****************************************************************
		Write-Output "Enabling Windows to use latest .NET Framework." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Enabling the Fraunhofer IIS MPEG Layer-3 (MP3) Codec." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc")
		{
			Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction Stop
			Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction Stop
		}
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type ExpandString
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type ExpandString
		#****************************************************************
		Write-Output "Enabling the auto-removal of the DefaultUser0 account." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-RegistryOwner -SubKey "WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" -Name "AutoElevationAllowed" -Value 1 -Type DWord
		#****************************************************************
		Write-Output "Disabling Sticky Keys." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value 122 -Type DWord
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value 58 -Type DWord
		#****************************************************************
		Write-Output "Increasing Icon Cache Size." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 4096 -Type DWord
		#****************************************************************
		Write-Output "Adding 'Open with Notepad' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" /v "Icon" /t REG_SZ /d "Notepad.exe,-2" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" /ve /t REG_SZ /d "Notepad.exe %1" /f)
		#****************************************************************
		Write-Output "Adding 'Copy-Move' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB630-2971-11D1-A18C-00C04FD75D13}" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB631-2971-11D1-A18C-00C04FD75D13}" -ErrorAction Stop
		#****************************************************************
		Write-Output "Adding 'Elevated Command-Prompt' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Icon" -Value "CMD.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "SeparatorAfter" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Icon" -Value "CMD.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "SeparatorAfter" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString
		#****************************************************************
		Write-Output "Adding 'Elevated PowerShell' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell\command" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell\command" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
		#****************************************************************
		Write-Output "Adding 'Install CAB' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs\Command" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -Name "(default)" -Value "Install" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -Name "HasLUAShield" -Value "" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs\Command" -Name "(default)" -Value "CMD /K DISM /ONLINE /ADD-PACKAGE /PACKAGEPATH:`"%1`"" -Type ExpandString
		#****************************************************************
		Write-Output "Adding 'Restart Explorer' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
		#****************************************************************
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -ErrorAction Stop
		New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Icon" -Value "Explorer.exe" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Position" -Value "Bottom" -Type String
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Get-Process -Name explorer | Stop-Process`"" -Type String
		#****************************************************************
		$SetRegistryComplete = $true
		If ($Registry -eq "Hardened")
		{
			#****************************************************************
			Write-Output "Disabling System and Settings Syncronization." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			@("Accessibility", "AppSync", "BrowserSettings", "Credentials", "DesktopTheme", "Language", "PackageState", "Personalization", "StartLayout", "Windows") |
			ForEach {
				New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -ErrorAction Stop
				Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -Name "Enabled" -Value 0 -Type DWord
			}
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Value 5 -Type DWord
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSyncUserOverride" -Value 1 -Type DWord
			#****************************************************************
			Write-Output "Disabling Location Sensors, App Syncronization and Non-Explicit App Access." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Value "Deny" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Value "Deny" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Name "Value" -Value "Deny" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Type" -Value "LooselyCoupled" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Value "Deny" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "InitialAppValue" -Value "Unspecified" -Type String
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Value 2 -Type DWord
			#****************************************************************
			Write-Output "Disabling System Tracking and Location Sensors." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc" -Name "Start" -Value 4 -Type DWord
			#****************************************************************	
			Write-Output "Disabling Shared Experiences." >> "$WorkFolder\Registry-Optimizations.log"
			#***************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Value 0 -Type DWord
			#****************************************************************
			Write-Output "Disabling SmartScreen." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord
			#****************************************************************
			Write-Output "Disabling Windows Auto-Update and Auto-Reboot." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Type DWord
			#****************************************************************
			Write-Output "Disabling the Link-Local Multicast Name Resolution (LLMNR) Protocol." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
			#****************************************************************
			Write-Output "Disabling Error Reporting." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WerSvc" -Name "Start" -Value 4 -Type DWord
			#****************************************************************	
			Write-Output "Disabling WiFi Sense." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord
			#***************************************************************	
			Write-Output "Disabling System and Settings Syncronization." >> "$WorkFolder\Registry-Optimizations.log"
			#****************************************************************
			@("Accessibility", "AppSync", "BrowserSettings", "Credentials", "DesktopTheme", "Language", "PackageState", "Personalization", "StartLayout", "Windows") | ForEach {
				New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -ErrorAction Stop
				Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -Name "Enabled" -Value 0 -Type DWord
			}
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Value 5 -Type DWord
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Value 2 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -Value 2 -Type DWord
			#****************************************************************
			Write-Output "Disabling System Tracking and Location Sensors." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc" -Name "Start" -Value 4 -Type DWord
			#****************************************************************	
			Write-Output "Disabling Web Access to Language List." >> "$WorkFolder\Registry-Optimizations.log"
			#***************************************************************
			New-Container -Path "HKLM:\WIM_HKCU\Control Panel\International\User Profile" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord
			#****************************************************************
			$HardenRegistryComplete = $true
		}
		[void](Dismount-OfflineHives)
	}
	Catch
	{
		Write-Error "Failed to apply all Registry Optimizations."
		Exit-Script
		Break
	}
}
#endregion Registry Optimizations

If ((Get-AppxProvisionedPackage -Path $MountFolder | Where PackageName -Like "*Calculator*").Count.Equals(0))
{
	If ((Test-Path -LiteralPath "$Win32CalcPath\win32calc.exe" -PathType Leaf) -and (Test-Path -LiteralPath "$Win32CalcPath\win32calc.exe.mui" -PathType Leaf))
	{
		Try
		{
			$Host.UI.RawUI.WindowTitle = "Applying the Win32 Calculator."
			Write-Output ''
			Out-Log -Content "Applying the Win32 Calculator." -Level Info
			Copy-Item -Path "$Win32CalcPath\win32calc.exe" -Destination "$MountFolder\Windows\System32\win32calc.exe" -Force -ErrorAction Stop
			Copy-Item -Path "$Win32CalcPath\win32calc.exe.mui" -Destination "$MountFolder\Windows\System32\en-US\win32calc.exe.mui" -Force -ErrorAction Stop
			[void](Mount-OfflineHives)
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -ErrorAction Stop
			New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -Name "(default)" -Value "C:\Windows\System32\win32calc.exe,0" -Type String -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\win32calc.exe" -Type String -ErrorAction Stop
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -Name "ShellExecute" -Value "C:\Windows\System32\win32calc.exe" -Type String -ErrorAction Stop
			[void](Dismount-OfflineHives)
			$CalcShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
			$CalcShortcut = $CalcShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk")
			$CalcShortcut.TargetPath = "%SystemRoot%\System32\win32calc.exe"
			$CalcShortcut.IconLocation = "%SystemRoot%\System32\win32calc.exe,0"
			$CalcShortcut.Description = "Performs basic arithmetic tasks with an on-screen calculator."
			$CalcShortcut.Save()
			$IniFile = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini"
			$CalcLink = "Calculator.lnk=@%SystemRoot%\System32\shell32.dll,-22019"
			Start-Process -FilePath ATTRIB -ArgumentList ("-S -H `"$IniFile`"") -NoNewWindow -Wait
			If (!(Select-String -Path $IniFile -Pattern $CalcLink -SimpleMatch -Quiet))
			{
				Add-Content -Path $IniFile -Value $CalcLink -Encoding Unicode -ErrorAction Stop
			}
			Else
			{
				(Get-Content -Path $IniFile) | Where { $_ -ne $CalcLink } | Set-Content -Path $IniFile -ErrorAction Stop
				Add-Content -Path $IniFile -Value $CalcLink -Encoding Unicode -ErrorAction Stop
			}
			Start-Process -FilePath ATTRIB -ArgumentList ("+S +H `"$IniFile`"") -NoNewWindow -Wait
		}
		Catch
		{
			Write-Output ''
			Out-Log -Content "Failed to apply the Win32 Calculator." -Level Error
			Exit-Script
			Break
		}
	}
}

If ($DaRT)
{
	If ((Test-Path -LiteralPath $DaRTPath -Filter "MSDaRT10.wim") -and (Get-ChildItem -LiteralPath $DaRTPath -Filter "DebuggingTools_*.wim"))
	{
		$CheckBuild = (Get-WindowsImage -ImagePath $InstallWim -Index $Index).Build
		If ($CheckBuild -eq '15063') { $CodeName = "RS2" }
		ElseIf ($CheckBuild -eq '16299') { $CodeName = "RS3" }
		ElseIf ($CheckBuild -eq '17134') { $CodeName = "RS4" }
		ElseIf ($CheckBuild -ge '17730') { $CodeName = "RS5" }
		If ($BootIsPresent.Equals($true))
		{
			Clear-Host
			$Host.UI.RawUI.WindowTitle = "Applying Microsoft DaRT 10."
			Out-Log -Content "Applying Microsoft DaRT 10 $($CodeName) to Windows Setup and Windows Recovery." -Level Info
			Start-Sleep 3
		}
		Else
		{
			Clear-Host
			$Host.UI.RawUI.WindowTitle = "Applying Microsoft DaRT 10."
			Out-Log -Content "Applying Microsoft DaRT 10 $($CodeName) to Windows Recovery." -Level Info
			Start-Sleep 3
		}
		Try
		{
			If ($BootIsPresent.Equals($true))
			{
				$BootWim = Get-Item -Path "$ImageFolder\boot.wim" -Force
				$NewBootMount = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "BootMount_$(Get-Random)"))
				If ($NewBootMount) { $BootMount = Get-Item -LiteralPath "$ScriptDirectory\$NewBootMount" }
				$MountBootImage = @{
					Path			    = $BootMount
					ImagePath		    = $BootWim
					Index			    = 2
					ScratchDirectory    = $ScratchFolder
					LogPath			    = $DISMLog
					ErrorAction		    = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Mounting the Boot Image." -Level Info
				[void](Mount-WindowsImage @MountBootImage)
				$MSDaRT10Boot = @{
					ImagePath    = "$DaRTPath\MSDaRT10.wim"
					Index	     = 1
					ApplyPath    = $BootMount
					CheckIntegrity = $true
					Verify	     = $true
					ScratchDirectory = $ScratchFolder
					LogPath	     = $DISMLog
					ErrorAction  = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Applying the Microsoft DaRT $($CodeName) Base Package to the Boot Image." -Level Info
				[void](Expand-WindowsImage @MSDaRT10Boot)
				Start-Sleep 3
				$DeguggingToolsBoot = @{
					ImagePath    = "$DaRTPath\DebuggingTools_$($CodeName).wim"
					Index	     = 1
					ApplyPath    = $BootMount
					CheckIntegrity = $true
					Verify	     = $true
					ScratchDirectory = $ScratchFolder
					LogPath	     = $DISMLog
					ErrorAction  = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Applying Windows 10 $($CodeName) Debugging Tools to the Boot Image." -Level Info
				[void](Expand-WindowsImage @DeguggingToolsBoot)
				Start-Sleep 3
				If (!(Test-Path -Path "$BootMount\Windows\System32\fmapi.dll"))
				{
					Copy-Item -Path "$MountFolder\Windows\System32\fmapi.dll" -Destination "$BootMount\Windows\System32" -ErrorAction Stop
				}
				@'
[LaunchApps]
%WINDIR%\system32\wpeinit.exe
%WINDIR%\system32\netstart.exe
%SYSTEMDRIVE%\setup.exe
'@ | Out-File -FilePath "$BootMount\Windows\System32\winpeshl.ini" -ErrorAction Stop
				$DismountBootImage = @{
					Path			    = $BootMount
					Save			    = $true
					CheckIntegrity	    = $true
					ScratchDirectory    = $ScratchFolder
					LogPath			    = $DISMLog
					ErrorAction		    = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Saving and Dismounting the Boot Image." -Level Info
				[void](Dismount-WindowsImage @DismountBootImage)
				Write-Output ''
				Out-Log -Content "Rebuilding the Boot Image." -Level Info
				$ExportBoot = "/English /Export-Image /SourceImageFile:`"${ImageFolder}\boot.wim`" /All /DestinationImageFile:`"${WorkFolder}\boot.wim`" /Compress:Max /CheckIntegrity /Quiet"
				Start-Process -FilePath DISM -ArgumentList $ExportBoot -WindowStyle Hidden -Wait
				Remove-Item -Path $BootWim -Force -ErrorAction SilentlyContinue
				Remove-Item -Path $BootMount -Recurse -Force -ErrorAction SilentlyContinue
			}
			If (Test-Path -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -PathType Leaf)
			{
				Start-Process -FilePath ATTRIB -ArgumentList ("-S -H -I `"$MountFolder\Windows\System32\Recovery\winre.wim`"") -NoNewWindow -Wait
				Copy-Item -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -Destination $ImageFolder -ErrorAction Stop
				$RecoveryWim = Get-Item -Path "$ImageFolder\winre.wim" -Force -ErrorAction Stop
				$NewRecoveryMount = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "RecoveryMount_$(Get-Random)" -ErrorAction Stop))
				If ($NewRecoveryMount) { $RecoveryMount = Get-Item -LiteralPath "$ScriptDirectory\$NewRecoveryMount" }
				$MountRecoveryImage = @{
					Path			    = $RecoveryMount
					ImagePath		    = $RecoveryWim
					Index			    = 1
					ScratchDirectory    = $ScratchFolder
					LogPath			    = $DISMLog
					ErrorAction		    = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Mounting the Recovery Image." -Level Info
				[void](Mount-WindowsImage @MountRecoveryImage)
				$MSDaRT10Recovery = @{
					ImagePath    = "$DaRTPath\MSDaRT10.wim"
					Index	     = 1
					ApplyPath    = $RecoveryMount
					CheckIntegrity = $true
					Verify	     = $true
					ScratchDirectory = $ScratchFolder
					LogPath	     = $DISMLog
					ErrorAction  = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Applying the Microsoft DaRT $($CodeName) Base Package to the Recovery Image." -Level Info
				[void](Expand-WindowsImage @MSDaRT10Recovery)
				Start-Sleep 3
				$DeguggingToolsRecovery = @{
					ImagePath    = "$DaRTPath\DebuggingTools_$($CodeName).wim"
					Index	     = 1
					ApplyPath    = $RecoveryMount
					CheckIntegrity = $true
					Verify	     = $true
					ScratchDirectory = $ScratchFolder
					LogPath	     = $DISMLog
					ErrorAction  = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Applying Windows 10 $($CodeName) Debugging Tools to the Recovery Image." -Level Info
				[void](Expand-WindowsImage @DeguggingToolsRecovery)
				Start-Sleep 3
				If (!(Test-Path -Path "$RecoveryMount\Windows\System32\fmapi.dll"))
				{
					Copy-Item -Path "$MountFolder\Windows\System32\fmapi.dll" -Destination "$RecoveryMount\Windows\System32" -ErrorAction Stop
				}
				@'
[LaunchApps]
%WINDIR%\system32\wpeinit.exe
%WINDIR%\system32\netstart.exe
%SYSTEMDRIVE%\sources\recovery\recenv.exe
'@ | Out-File -FilePath "$RecoveryMount\Windows\System32\winpeshl.ini" -ErrorAction Stop
				$DismountRecoveryImage = @{
					Path			    = $RecoveryMount
					Save			    = $true
					CheckIntegrity	    = $true
					ScratchDirectory    = $ScratchFolder
					LogPath			    = $DISMLog
					ErrorAction		    = "Stop"
				}
				Write-Output ''
				Out-Log -Content "Saving and Dismounting the Recovery Image." -Level Info
				[void](Dismount-WindowsImage @DismountRecoveryImage)
				Write-Output ''
				Out-Log -Content "Rebuilding the Recovery Image." -Level Info
				$ExportRecovery = "/English /Export-Image /SourceImageFile:`"${ImageFolder}\winre.wim`" /All /DestinationImageFile:`"${WorkFolder}\winre.wim`" /Compress:Max /CheckIntegrity /Quiet"
				Start-Process -FilePath DISM -ArgumentList $ExportRecovery -WindowStyle Hidden -Wait
				Move-Item -Path "$WorkFolder\winre.wim" -Destination "$MountFolder\Windows\System32\Recovery" -Force -ErrorAction Stop
				Start-Process -FilePath ATTRIB -ArgumentList ("+S +H +I `"$MountFolder\Windows\System32\Recovery\winre.wim`"") -NoNewWindow -Wait
				Remove-Item -Path $RecoveryWim -Force -ErrorAction SilentlyContinue
				Remove-Item -Path $RecoveryMount -Recurse -Force -ErrorAction SilentlyContinue
			}
			$DaRTApplied = $true
			Clear-Host
		}
		Catch
		{
			Write-Output ''
			Out-Log -Content "Failed to apply Microsoft DaRT 10 to the Recovery Image." -Level Error
			If ((Get-WindowsImage -Mounted).ImagePath -match "boot.wim")
			{
				Write-Output ''
				Write-Host "Dismounting and Discarding the Recovery Image." -ForegroundColor Cyan
				[void](Dismount-WindowsImage -Path $BootMount -Discard)
			}
			If ((Get-WindowsImage -Mounted).ImagePath -match "winre.wim")
			{
				Write-Output ''
				Write-Host "Dismounting and Discarding the Recovery Image." -ForegroundColor Cyan
				[void](Dismount-WindowsImage -Path $RecoveryMount -Discard)
			}
			If (Test-Path -Path $BootWim -ErrorAction SilentlyContinue) { Remove-Item -Path $BootWim -Force -ErrorAction SilentlyContinue }
			If (Test-Path -Path $BootMount -ErrorAction SilentlyContinue) { Remove-Item -Path $BootMount -Recurse -Force -ErrorAction SilentlyContinue }
			If (Test-Path -Path $RecoveryWim -ErrorAction SilentlyContinue) { Remove-Item -Path $RecoveryWim -Force -ErrorAction SilentlyContinue }
			If (Test-Path -Path $RecoveryMount -ErrorAction SilentlyContinue) { Remove-Item -Path $RecoveryMount -Recurse -Force -ErrorAction SilentlyContinue }
		}
	}
}

If ($Drivers -and (Get-ChildItem -Path $DriverPath -Recurse -Filter "*.inf"))
{
	Try
	{
		If ($DaRTApplied.Equals($true)) { Clear-Host }
		Else { Write-Output '' }
		$Host.UI.RawUI.WindowTitle = "Injecting Driver Packages."
		Out-Log -Content "Injecting Driver Packages" -Level Info
		$InjectDriverPackages = @{
			Path				 = $MountFolder
			Driver			     = $DriverPath
			Recurse			     = $true
			ForceUnsigned	     = $true
			ScratchDirectory	 = $ScratchFolder
			LogPath			     = $DISMLog
			ErrorAction		     = "Stop"
		}
		[void](Add-WindowsDriver @InjectDriverPackages)
		Get-WindowsDriver -Path $MountFolder -ScratchDirectory $ScratchFolder -LogPath $DISMLog | Format-List | Out-File -FilePath $WorkFolder\InjectedDriverList.txt
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to inject driver packages into the image." -Level Error
		Exit-Script
		Break
	}
}

If ((Get-ChildItem -Path $NetFx3Path -Recurse -Filter "*NetFx3*.cab") -and (Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -EQ NetFx3).State -eq "DisabledWithPayloadRemoved")
{
	Try
	{
		Write-Output ''
		Out-Log -Content "Applying Payload and Enabling NetFx3" -Level Info
		$EnableNetFx3 = @{
			Path			   = $MountFolder
			ScratchDirectory   = $ScratchFolder
			LogPath		       = $DISMLog
			FeatureName	       = "NetFx3"
			Source			   = $NetFx3Path
			All			       = $true
			ErrorAction	       = "Stop"
		}
		[void](Enable-WindowsOptionalFeature @EnableNetFx3)
	}
	Catch
	{
		Write-Output ''
		Out-Log -Content "Failed to apply payload and enable NetFx3." -Level Error
		Exit-Script
		Break
	}
}

If ($SetRegistryComplete.Equals($true))
{
	New-Container -Path "$MountFolder\Windows\Setup\Scripts"
	$SetupScript = "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd"
	@'
SET DEFAULTUSER0="defaultuser0"

FOR /F "TOKENS=*" %%A IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"^|FIND /I "S-1-5-21"') DO CALL :QUERY_REGISTRY "%%A"
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
SCHTASKS /QUERY | FINDSTR /B /I "AitAgent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BthSQM" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /DISABLE >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CreateObjectTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\CloudExperienceHost\" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft Compatibility Appraiser" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "ProgramDataUpdater" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "StartupAppTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
'@ | Out-File -FilePath $SetupScript -Encoding ASCII
	$XboxTasks = @'
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
'@
	$DefenderTasks = @'
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
'@
	$SetupEnd = @'
POWERCFG -H OFF >NUL
DEL /F /Q "%WINDIR%\Panther\unattend.xml" >NUL 2>&1
DEL /F /Q "%WINDIR%\System32\Sysprep\unattend.xml" >NUL 2>&1
DEL "%~f0"
'@
	If ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -eq $true) { Out-File -FilePath $SetupScript -InputObject $DefenderTasks, $XboxTasks, $SetupEnd -Append -Encoding ASCII }
	ElseIf ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -ne $true) { Out-File -FilePath $SetupScript -InputObject $DefenderTasks, $SetupEnd -Append -Encoding ASCII }
	ElseIf ($DisableDefenderComplete -ne $true -and $DisableXboxComplete -eq $true) { Out-File -FilePath $SetupScript -InputObject $XboxTasks, $SetupEnd -Append -Encoding ASCII }
	Else { Out-File -FilePath $SetupScript -InputObject $SetupEnd -Append -Encoding ASCII }
}

If ((Test-Connection -ComputerName $Env:COMPUTERNAME -Quiet).Equals($true))
{
	Rename-Item -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -NewName hosts.bak -Force
	[void]((Invoke-WebRequest -Uri "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -OutFile "$MountFolder\Windows\System32\drivers\etc\hosts").RawContent)
	(Get-Content -Path "$MountFolder\Windows\System32\drivers\etc\hosts") | Set-Content -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -Encoding UTF8 -Force
}

Clear-Host
$EndHealthCheck = (Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState
If ($EndHealthCheck -eq "Healthy")
{
	Out-Log -Content "The image health state has returned as [Healthy]" -Level Info
	Start-Sleep 3
}
Else
{
	Write-Output ''
	Out-Log -Content "The image has been flagged for corruption. Discarding optimizations." -Level Error
	Exit-Script
	Break
}

Try
{
	$Host.UI.RawUI.WindowTitle = "Saving and Dismounting."
	Write-Output ''
	Out-Log -Content "Saving and Dismounting." -Level Info
	$RecycleBin = "$MountFolder\" + '$Recycle.Bin'
	If (Test-Path -Path $RecycleBin) { Remove-Item -Path $RecycleBin -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
	If (Test-Path -Path "$MountFolder\PerfLogs") { Remove-Item -Path "$MountFolder\PerfLogs" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
	$DismountWindowsImage = @{
		Path			    = $MountFolder
		Save			    = $true
		CheckIntegrity	    = $true
		ScratchDirectory    = $ScratchFolder
		LogPath			    = $DISMLog
		ErrorAction		    = "Stop"
	}
	[void](Dismount-WindowsImage @DismountWindowsImage)
}
Catch
{
	Write-Output ''
	Out-Log -Content "Failed to save and dismount the image." -Level Error
	Exit-Script
	Break
}

Try
{
	$Host.UI.RawUI.WindowTitle = "Rebuilding Image."
	Write-Output ''
	Out-Log -Content "Rebuilding Image." -Level Info
	$ExportInstall = "/English /Export-Image /SourceImageFile:`"${InstallWim}`" /All /DestinationImageFile:`"${WorkFolder}\install.wim`" /Compress:Max /CheckIntegrity /Quiet"
	Start-Process -FilePath DISM -ArgumentList $ExportInstall -WindowStyle Hidden -Wait -ErrorAction Stop
}
Catch
{
	Write-Output ''
	Out-Log -Content "Failed to rebuild image." -Level Error
	Exit-Script
	Break
}

Try
{
	$Host.UI.RawUI.WindowTitle = "Finalizing Script."
	Write-Output ''
	Out-Log -Content "Finalizing Script." -Level Info
	[void]($SaveFolder = New-SaveDirectory)
	Move-Item -Path "$WorkFolder\*.txt" -Destination $SaveFolder -Force
	Move-Item -Path "$WorkFolder\*.log" -Destination $SaveFolder -Force
	Move-Item -Path "$WorkFolder\install.wim" -Destination $SaveFolder -Force
	If (Test-Path -Path "$WorkFolder\boot.wim") { Move-Item -Path "$WorkFolder\boot.wim" -Destination $SaveFolder -Force }
	Start-Sleep 3
	If ($Error.Count.Equals(0))
	{
		Write-Output ''
		Write-Host "$OScript completed with [$($Error.Count)] errors." -ForegroundColor White
		Write-Output ''
		Start-Sleep 3
	}
	Else
	{
		$SaveErrorLog = Join-Path -Path $Env:TEMP -ChildPath ErrorLog.log
		Set-Content -Path $SaveErrorLog -Value $Error.ToArray() -Force
		Move-Item -Path $Env:TEMP\ErrorLog.log -Destination $SaveFolder -Force
		Write-Output ''
		Write-Warning "$OScript completed with [$($Error.Count)] errors."
		Write-Output ''
		Start-Sleep 3
	}
}
Finally
{
	Remove-Item -Path $ScriptDirectory -Recurse -Force
	Remove-Item -Path $DISMLog -Force
	If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force }
	$Host.UI.RawUI.WindowTitle = "Optimization Complete."
	[void](Clear-WindowsCorruptMountPoint)
	@"

***************************************************************************************************
			$($OScript) completed at [$($TimeStamp)]
***************************************************************************************************
"@ | Out-File -FilePath $LogFile -Append -Encoding ASCII
	Move-Item -Path $LogFile -Destination $SaveFolder -Force
}
# SIG # Begin signature block
# MIIMIAYJKoZIhvcNAQcCoIIMETCCDA0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7g7nFoFdu956fSWVM4Uam6y4
# YSygggj8MIIDfTCCAmWgAwIBAgIQfY66zkudTZ9EnV2nSZm8oDANBgkqhkiG9w0B
# AQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9N
# TklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTE4MDMxMzIxNTY1OFoXDTIz
# MDMxMzIyMDY1OFowRTEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/Is
# ZAEZFgVPTU5JQzEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAO6V7MmlK+QuOqWIzrLbmhv9acRXB46vi4RV2xla
# MTDUimrSyGtpoDQTYK2QZ3idDq1nxrnfAR2XytTwVCcCFoWLpFFRack5k/q3QFFV
# WP2DbSqoWfNG/EFd0qx8p81X5mH09t1mnN/K+BX1jiBS60rQYTsSGMkSSn/IUxDs
# sLvatjToctZnCDiqG8SgPdWtVfHRLLMmT0l8paOamO0bpaSSsTpBaan+qiYidnxa
# eIR23Yvv26Px1kMFYNp5YrWfWJEw5udB4W8DASO8TriypXXpca2jCEkVswNwNW/n
# Ng7QQqECDVwVm3BVSClNcf1J52uU+Nvx36gKRl5xcogW4h0CAwEAAaNpMGcwEwYJ
# KwYBBAGCNxQCBAYeBABDAEEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFH/3cqyAb+6RpNGa2+j3ldMI8axTMBAGCSsGAQQBgjcVAQQD
# AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBYMivmEQPQpT1OfiPLVFaGFbnKmWo0dTWo
# vkCQMq54NdUqvnCkOIC9O3nrsBqdQhTPAtDow1C1qWQipGf/JyMCTh9ZIEoz3u4z
# RsiKMjIlPJkar1OsTsvKcAaya+a10LTcBMfF4DyOFaGqvKNrTaD3MmFQIBblQ8TS
# QOzQPOXUwY/2IgI9w1AA8VO0N2coYzvj4i79RSQ77eg1iefjBRqs347o4/b7pWtS
# 95+FBGr7JhhV3i9EI95172O4jmEkmoJQgr2mzvThjp9WiyeyjpnBAikV14YmEIyu
# DmKue5ZuxG+D3W3ZwFyGytUCHYWwMshTRwI0z236dZG9OhYDSfibMIIFdzCCBF+g
# AwIBAgITIQAAAAV87PzZFzK4xAAAAAAABTANBgkqhkiG9w0BAQsFADBFMRQwEgYK
# CZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9NTklDMRYwFAYDVQQD
# Ew1PTU5JQy5URUNILUNBMB4XDTE4MDQxODEyMjAzNloXDTE5MDQxODEyMjAzNlow
# UzEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/IsZAEZFgVPTU5JQzEO
# MAwGA1UEAxMFVXNlcnMxFDASBgNVBAMTC0JlblRoZUdyZWF0MIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9xWMMTEOCpdnZu3eDTVbytEzoTnHQYeS/2jg
# wGLYU3+43C3viMoNVj+nLANJydTIRW5Dca+6JfO8UH25kf0XQ+AiXirQfjb9ec9u
# I+au+krmlL1fSR076lPgYzqnqPMQzOER8U2J2+uF18UtxEVO3rq7Cnxlich4jXzy
# gTy8XiNSAfUGR1nfq7HjahJ/CKopwl/7NcfmV5ZDzogRob1eErOPJXGAkewJuKqp
# /qItYzGH+9XADCyO0GYVIOsXNIE0Ho0bdBPZ3eDdamL1vocTlEkTe0/drs3o2AkS
# qcgg2I0uBco/p8CxCR7Tfq2zX1DFW9B7+KGNobxq+l+V15rTMwIDAQABo4ICUDCC
# AkwwJQYJKwYBBAGCNxQCBBgeFgBDAG8AZABlAFMAaQBnAG4AaQBuAGcwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBSIikO7ZjAP
# GlMAUcP2kulHiqpJnDAfBgNVHSMEGDAWgBR/93KsgG/ukaTRmtvo95XTCPGsUzCB
# yQYDVR0fBIHBMIG+MIG7oIG4oIG1hoGybGRhcDovLy9DTj1PTU5JQy5URUNILUNB
# LENOPURPUkFETyxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
# U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1PTU5JQyxEQz1URUNIP2NlcnRp
# ZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmli
# dXRpb25Qb2ludDCBvgYIKwYBBQUHAQEEgbEwga4wgasGCCsGAQUFBzAChoGebGRh
# cDovLy9DTj1PTU5JQy5URUNILUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPU9NTklDLERD
# PVRFQ0g/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRp
# b25BdXRob3JpdHkwMQYDVR0RBCowKKAmBgorBgEEAYI3FAIDoBgMFkJlblRoZUdy
# ZWF0QE9NTklDLlRFQ0gwDQYJKoZIhvcNAQELBQADggEBAD1ZkdqIaFcqxTK1YcVi
# QENxxkixwVHJW8ZATwpQa8zQBh3B1cMromiR6gFvPmphMI1ObRtuTohvuZ+4tK7/
# IohAt6TwzyDFqY+/HzoNCat07Vb7DrA2fa+QMOl421kVUnZyYLI+gEod/zJqyuk8
# ULBmUxCXxxH26XVC016AuoOedKwzBgAFyIDlIAivZcSOtaSyALJSZ2Pk29R69dp5
# ICb+zCXCWPQJkbsU6eTlZAwaMmR2Vx4TQeDl49YIIwoDXDT4zBTcJ6n2k6vHQDWR
# K9zaF4qAD9pwlQICbLgTeZBz5Bz2sXzhkPsmY6LNKTAOnuk0QbjsKXSKoB/QRAip
# FiUxggKOMIICigIBATBcMEUxFDASBgoJkiaJk/IsZAEZFgRURUNIMRUwEwYKCZIm
# iZPyLGQBGRYFT01OSUMxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0ECEyEAAAAFfOz8
# 2RcyuMQAAAAAAAUwCQYFKw4DAhoFAKCCAQcwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFCfXSgDwQ3WO7KuqV8+eNKlvCRuQMIGmBgorBgEEAYI3AgEMMYGXMIGUoIGR
# gIGOAEEAIABmAHUAbABsAHkAIABhAHUAdABvAG0AYQB0AGUAZAAgAFcAaQBuAGQA
# bwB3AHMAIAAxADAAIABSAFMAMwAtAFIAUwA1ACAAbwBmAGYAbABpAG4AZQAgAGkA
# bQBhAGcAZQAgAG8AcAB0AGkAbQBpAHoAYQB0AGkAbwBuACAAcwBjAHIAaQBwAHQA
# LjANBgkqhkiG9w0BAQEFAASCAQA+TfCe3VmaiHdJ8y9FGURyp4z7jpMQZDaU3TuL
# U0T412J7eBRUtYJbjM/Pp/nKQuhBoZ3cgozXMXVbdQYQitLVHfDszxvTEP85bZYv
# Pqh6V47bvlHdBmbSlNsnjAgeY3H3a7XJhlfIU9VL3XhkNW8pZjbi+T0EOzh+JfM5
# IdovTS77BKf0oC00eQy/8lYI5EkEHpK5wp4Vcdup5ngQZXsvUShVdTzIZNxKgeLU
# W2b7iacf44osr8dOhh/Kn45KGzJfp/4I+3aTdItWzBGN8B80o4SBAHGrAtfWCQ4/
# vgKQg+lm7meI5fEKBTNZGuWXkn1uTmjZzGuvWSJX5Ee99Ifx
# SIG # End signature block
