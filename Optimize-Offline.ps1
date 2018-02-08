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
		Prompts the user for approval before a Provisioning Application Package is removed by outputting its Display Name.
	
	.PARAMETER AllApps
		Automatically removes all Provisioning Application Packages.
	
	.PARAMETER UseWhiteList
		Automatically removes all Provisioning Application Packages not WhiteListed.
	
	.PARAMETER SystemApps
		Automatically removes the provisioning and installation of System Applications.
	
	.PARAMETER OptimizeRegistry
		Automatically adds, removes or modifies multiple registry keys and values.
	
	.PARAMETER DisableFeatures
		Automatically disables all Windows Optional Features included in the FeatureDisableList.
	
	.PARAMETER RemovePackages
		Automatically removes all Windows Packages included in the PackageRemovalList.
	
	.PARAMETER AddDrivers
		A resolvable path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.PARAMETER Local
		This will set the mount and save locations to the root path of the script allowing the end-user to use an alternate drive as the location for all processing, which is SSD optimal.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -AllApps -SystemApps -OptimizeRegistry -DisableFeatures -RemovePackages -AddDrivers "E:\DriverFolder"
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\Win10Pro.iso" -Build 16299 -SelectApps -SystemApps -OptimizeRegistry -DisableFeatures -RemovePackages -AddDrivers "E:\DriverFolder" -Local
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ISO "D:\Win Images\Win10Pro.iso" -Index 2 -Build 16299 -UseWhiteList -SysApps -RegEdit -Features -Packages -Drivers "E:\DriverFolder"
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -WIM "D:\WIM Files\Win10Pro\install.wim" -Index 3 -Build 15063 -Select -SysApps -RegEdit -Features -Packages -Drivers "E:\DriverFolder\OEM12.inf" -Local
	
	.NOTES
		===========================================================================
		Created on:   	11/30/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        3.0.7
		Last updated:	02/08/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')][ValidateScript({
			If ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
			ElseIf ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
			Else { Throw "$_ is an invalid image path." }
		})][Alias('ISO', 'WIM')][string]$ImagePath,
	[Parameter(HelpMessage = 'If using a multi-index image, specify the index of the image.')][ValidateRange(1, 16)][int]$Index = 1,
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The build number of the image.')][ValidateRange(15063, 16299)][int]$Build,
	[Parameter(HelpMessage = 'Prompts the user for approval before a Provisioning Application Package is removed by outputting its Display Name.')][Alias('Select')][switch]$SelectApps,
	[Parameter(HelpMessage = 'Automatically removes all Provisioning Application Packages.')][switch]$AllApps,
	[Parameter(HelpMessage = 'Automatically removes all Provisioning Application Packages not WhiteListed.')][Alias('WhiteList')][switch]$UseWhiteList,
	[Parameter(HelpMessage = 'Automatically removes the provisioning and installation of System Applications.')][Alias('SysApps')][switch]$SystemApps,
	[Parameter(HelpMessage = 'Automatically adds, removes or modifies multiple registry keys and values.')][Alias('RegEdit')][switch]$OptimizeRegistry,
	[Parameter(HelpMessage = 'Automatically disables all Windows Optional Features included in the FeatureDisableList.')][Alias('Features')][switch]$DisableFeatures,
	[Parameter(HelpMessage = 'Automatically removes all Windows Packages included in the PackageRemovalList.')][Alias('Packages')][switch]$RemovePackages,
	[Parameter(Mandatory = $false,
			   HelpMessage = 'The path to a collection of driver packages, or a driver .inf file, to be injected into the image.')][ValidateScript({ Test-Path $(Resolve-Path $_) })][Alias('Drivers')][string]$AddDrivers,
	[Parameter(HelpMessage = 'Sets the mount and save locations to the root path of the script')][switch]$Local
)

## *************************************************************************************************
## *          THE FIELDS BELOW CAN BE EDITED TO FURTHER ACCOMMODATE REMOVAL REQUIREMENTS.          *
## *                      ITEMS CAN SIMPLY BE COMMENTED OUT WITH THE # KEY.                        *
## *************************************************************************************************

# The provisioning name of System Applications to remove if using the -SystemApps switch. 
# NOTE: Adding the ImmersiveControlPanel or ShellExperienceHost to this list will result in a NON-FUNCTIONAL final image.
# NOTE: Removing Cortana will render the search bar non-functional, but will not affect the final image.
$SystemAppsList = @(
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

# Display names of Provisioning Application Packages to WhiteList if using the -UseWhiteList switch.
$AppWhiteList = @(
	"Microsoft.DesktopAppInstaller"
	"Microsoft.Windows.Photos"
	#"Microsoft.WindowsCalculator"
	"Microsoft.Xbox.TCUI"
	"Microsoft.StorePurchaseApp"
	"Microsoft.WindowsStore"
)

# Wildcard names of Optional Features to disable if using the -DisableFeatures switch.
$FeatureDisableList = @(
	"*WorkFolders-Client*"
	"*WindowsMediaPlayer*"
	"*Internet-Explorer*"
)

# Wildcard names of OnDemand packages to be removed if using the -RemovePackages switch.
$PackageRemovalList = @(
	"*ContactSupport*"
	"*QuickAssist*"
	#"*InternetExplorer*"
	#"*MediaPlayer*"
)
## *************************************************************************************************
## *                                      END EDITABLE FIELDS.                                     *
## *************************************************************************************************

#region Helper Primary Functions
Function Verify-Admin # Verifies that the script is being run in an elevated shell by an Administrator.
{
	[CmdletBinding()]
	Param ()
	
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	$IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	Write-Verbose "IsUserAdmin? $IsAdmin" -Verbose
	Return $IsAdmin
	Write-Output ''
	Start-Sleep 3
}

Function Process-Log # Logs each process, any encountered errors and results to a .log file.
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias('LogContent')][string]$Output,
		[Parameter(Mandatory = $false)][string]$LogPath = "$env:SystemDrive\PowerShellLog.log",
		[Parameter(Mandatory = $false)][ValidateSet('Info', 'Warning', 'Error')][string]$Level = "Info",
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
}

#region C# Coded Token Privilege Method
$AdjustTokenPrivileges = @"
using System;
using System.Runtime.InteropServices;

public class AdjustAccessToken
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(
        IntPtr htok,
        bool disall,
        ref TokPriv1Luid newst,
        int len,
        IntPtr prev,
        IntPtr relen
        );
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(
        IntPtr h,
        int acc,
        ref IntPtr
        phtok
        );
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(
        string host,
        string name,
        ref long pluid
        );
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid
    {
        public int Count;
        public long Luid;
        public int Attr;
    }
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool GrantPrivilege(string privilege)
    {
        try
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(
                hproc,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ref htok
                );
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(
                null,
                privilege,
                ref tp.Luid
                );
            retVal = AdjustTokenPrivileges(
                htok,
                false,
                ref tp,
                0,
                IntPtr.Zero,
                IntPtr.Zero
                );
            return retVal;
        }
        catch(Exception ex)
        {
            throw ex;
        }
    }
    public static bool RevokePrivilege(string privilege)
    {
        try
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(
                hproc,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ref htok
                );
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = LookupPrivilegeValue(
                null,
                privilege,
                ref tp.Luid
                );
            retVal = AdjustTokenPrivileges(
                htok,
                false,
                ref tp,
                0,
                IntPtr.Zero,
                IntPtr.Zero
                );
            return retVal;
        }
        catch(Exception ex)
        {
            throw ex;
        }
    }
}
"@
#endregion C# Coded Token Privilege Method
Add-Type $AdjustTokenPrivileges -PassThru # Adds the Token Privilege Method as a .NET Framework class so it can be used within a function.

Function Set-RegistryOwner # Changes the ownership and access control of protected registry keys and subkeys (those owned by TrustedInstaller) in order to add or remove values.
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][string]$Hive,
		[Parameter(Mandatory = $true)][string]$SubKey
	)
	
	Begin # Grants the Access Token Privileges required to set full acesss and ownership on a protected registry hive/key.
	{
		[void][AdjustAccessToken]::GrantPrivilege("SeTakeOwnershipPrivilege") # Required to override access control permissions and take ownership of objects.
		[void][AdjustAccessToken]::GrantPrivilege("SeRestorePrivilege") # Required to restore files and directories.
		[void][AdjustAccessToken]::GrantPrivilege("SeBackupPrivilege") # Required to back-up files and directories.
	}
	Process # Begins processing and applying registry hive and subkey access now that the proper Access Token Privileges have been granted.
	{
		Switch ($Hive.ToString().ToLower())
		{
			"HKCR" {
				$Key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
			}
			"HKCU" {
				$Key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
			}
			"HKLM" {
				$Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
			}
		}
		$ACL = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None) # Assigns access control of the Key to a blank access control input-object.
		$AdminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # Assigns the SID of the built-in Administrator to a new object.
		$Account = $AdminSID.Translate([System.Security.Principal.NTAccount]) # Translates the build-in Administrator SID to its Windows Account Name (NTAccount).
		$ACL.SetOwner($Account) # Sets the ownership to the built-in Administrator.
		$Key.SetAccessControl($ACL) # Sets the access control permissions to the built-in Administrator.
		$ACL = $Key.GetAccessControl() # Retrieves the access control information for the registry key/subkey.
		$Rights = [System.Security.AccessControl.RegistryRights]"FullControl" # Designates the registry Key and SubKey rights.
		$Inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit" # Designates the flags that control object access control inheritance.
		$Propagation = [System.Security.AccessControl.PropagationFlags]"None" # Designates the flags that control object access control propogation.
		$Control = [System.Security.AccessControl.AccessControlType]"Allow" # Designates whether access is Allowed or Denied on the object.
		$Rule = New-Object System.Security.AccessControl.RegistryAccessRule($Account, $Rights, $Inheritance, $Propagation, $Control) # Assigns the access control rule to a new object.
		$ACL.SetAccessRule($Rule) # Sets the new access control rule.
		$Key.SetAccessControl($ACL) # Sets the access control permissions to the object rule.
		$Key.Close() # Closes the key/subkey.
		Switch ($Hive.ToString().ToLower())
		{
			"HKLM" {
				$Key = "HKLM:\$SubKey"
			}
			"HKCU" {
				$Key = "HKCU:\$SubKey"
			}
			"HKCR" {
				$Key = "HKLM:\SOFTWARE\Classes\$SubKey"
			}
		}
		# Reverts the ownership and access control permissions back to the TrustedInstaller after the changes to the key/subkey have been made.
		$TrustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
		$ACL = Get-Acl $Key
		$ACL.SetOwner($TrustedInstaller)
		$ACL | Set-Acl -Path $Key
	}
	End # Revokes the Access Token Privileges since system-level access is no longer required.
	{
		[void][AdjustAccessToken]::RevokePrivilege("SeTakeOwnershipPrivilege") # Revokes the Take Ownership Privilege.
		[void][AdjustAccessToken]::RevokePrivilege("SeRestorePrivilege") # Revokes the Restore Privilege.
		[void][AdjustAccessToken]::RevokePrivilege("SeBackupPrivilege") # Revokes the Backup Privilege.
	}
}

Function Create-WorkDirectory
{
	If ($Local)
	{
		$WorkDir = [System.IO.Directory]::GetCurrentDirectory()
		$WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($WorkDir)
		$WorkDir
	}
	Else
	{
		$WorkDir = [System.IO.Path]::GetTempPath()
		$WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($WorkDir)
		$WorkDir
	}
}

Function Create-TempDirectory
{
	If ($Local)
	{
		$TempDir = [System.IO.Directory]::GetCurrentDirectory()
		$TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($TempDir)
		$TempDir
	}
	Else
	{
		$TempDir = [System.IO.Path]::GetTempPath()
		$TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($TempDir)
		$TempDir
	}
}

Function Create-ImageDirectory
{
	If ($Local)
	{
		$ImageDir = [System.IO.Directory]::GetCurrentDirectory()
		$ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($ImageDir)
		$ImageDir
	}
	Else
	{
		$ImageDir = [System.IO.Path]::GetTempPath()
		$ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($ImageDir)
		$ImageDir
	}
}

Function Create-MountDirectory
{
	If ($Local)
	{
		$MountDir = [System.IO.Directory]::GetCurrentDirectory()
		$MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($MountDir)
		$MountDir
	}
	Else
	{
		$MountDir = [System.IO.Path]::GetTempPath()
		$MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
		[void][System.IO.Directory]::CreateDirectory($MountDir)
		$MountDir
	}
}

Function Create-SaveDirectory
{
	If ($Local)
	{
		New-Item -ItemType Directory -Path $PSScriptRoot\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
	Else
	{
		New-Item -ItemType Directory -Path $HOME\Desktop\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
}

Function Load-OfflineHives # Loads the offline registry hives.
{
	[void](REG LOAD HKLM\WIM_HKLM_COMPONENTS "$MountFolder\Windows\system32\config\COMPONENTS")
	[void](REG LOAD HKLM\WIM_HKLM_DRIVERS "$MountFolder\Windows\system32\config\DRIVERS")
	[void](REG LOAD HKLM\WIM_HKLM_SCHEMA "$MountFolder\Windows\system32\SMI\Store\Machine\SCHEMA.DAT")
	[void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\windows\system32\config\software")
	[void](REG LOAD HKLM\WIM_HKLM_SYSTEM "$MountFolder\windows\system32\config\system")
	[void](REG LOAD HKLM\WIM_HKCU "$MountFolder\Users\Default\NTUSER.DAT")
	[void](REG LOAD HKLM\WIM_HKU_DEFAULT "$MountFolder\Windows\System32\config\default")
}

Function Unload-OfflineHives # Unloads the offline registry hives.
{
	Start-Sleep 3
	[System.GC]::Collect()
	[void](REG UNLOAD HKLM\WIM_HKLM_COMPONENTS)
	[void](REG UNLOAD HKLM\WIM_HKLM_DRIVERS)
	[void](REG UNLOAD HKLM\WIM_HKLM_SCHEMA)
	[void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
	[void](REG UNLOAD HKLM\WIM_HKLM_SYSTEM)
	[void](REG UNLOAD HKLM\WIM_HKCU)
	[void](REG UNLOAD HKLM\WIM_HKU_DEFAULT)
}

Function Verify-OfflineHives # Verifies whether any offline registry hives are loaded.
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

Function Terminate-Script # Performs a roll-back and clean-up if a terminating error is encountered.
{
	[CmdletBinding()]
	Param ()
	
	Start-Sleep 3
	Write-Output ''
	Write-Verbose "Cleaning-up and terminating script." -Verbose
	If (Verify-OfflineHives)
	{
		[void](Unload-OfflineHives)
	}
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
	[void](Remove-Item -Path $WorkFolder -Recurse -Force)
	[void](Remove-Item -Path $TempFolder -Recurse -Force)
	[void](Remove-Item -Path $ImageFolder -Recurse -Force)
	[void](Remove-Item -Path $MountFolder -Recurse -Force)
	If ($Local)
	{
		[void](Move-Item -Path $LogFile -Destination $PSScriptRoot\Optimize-Offline.log -Force)
	}
	Else
	{
		[void](Move-Item -Path $LogFile -Destination $Desktop\Optimize-Offline.log -Force)
	}
}

Function Clean-CurrentMount # Attempts to dismount and clean-up the locations of a currently mounted image.
{
	Param ()
	
	Begin
	{
		$ErrorMessage = $_.Exception.Message
	}
	Process
	{
		Try
		{
			Write-Output ''
			Write-Verbose "Current mount location detected. Performing clean-up." -Verbose
			$ImageIsMounted = Get-WindowsImage -Mounted
			$MountedImagePath = Split-Path -Path $ImageIsMounted.ImagePath -Parent
			$QueryWIM = REG QUERY HKLM | FINDSTR WIM
			$QueryAppData = REG QUERY HKLM | FINDSTR AppData
			$QueryOptimize = REG QUERY HKLM | FINDSTR Optimize
			If ($QueryWIM)
			{
				[void]($QueryWIM.ForEach{ REG UNLOAD "$_" })
			}
			ElseIf ($QueryAppData)
			{
				[void]($QueryAppData.ForEach{ REG UNLOAD "$_" })
			}
			ElseIf ($QueryOptimize)
			{
				[void]($QueryOptimize.ForEach{ REG UNLOAD "$_" })
			}
			[void](Dismount-WindowsImage -Path $ImageIsMounted.MountPath -Discard)
			[void](Clear-WindowsCorruptMountPoint)
			[void](Remove-Item -Path $ImageIsMounted.MountPath -Recurse -Force)
			[void](Remove-Item -Path $MountedImagePath -Recurse -Force)
			Write-Output ''
			Write-Output "Clean-up complete."
		}
		Catch [System.Exception]
		{
			Write-Output ''
			Write-Warning "Clean-up failed with error message: $ErrorMessage"
		}
	}
}

Function Force-MKDIR($Path)
{
	If (!(Test-Path $Path))
	{
		[void](New-Item -Path $Path -ItemType Directory -Force)
	}
}
#endregion Helper Primary Functions

#region Script Variables
$Host.UI.RawUI.WindowTitle = "Optimizing image."
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = "SilentlyContinue"
$Script = "Optimize-Offline"
$ErrorMessage = "$_.Exception.Message"
$TimeStamp = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
$LogFile = "$env:TEMP\Optimize-Offline.log"
$Desktop = [Environment]::GetFolderPath("Desktop")
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
	Clean-CurrentMount
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
		If ($Local)
		{
			[void]($MountFolder = Create-MountDirectory)
			[void]($ImageFolder = Create-ImageDirectory)
			Copy-Item -Path $InstallWIM -Destination $ImageFolder -Force
			Dismount-DiskImage -ImagePath $ISOPath -StorageType ISO
			If (([IO.FileInfo]"$ImageFolder\install.wim").IsReadOnly) { ATTRIB -R $ImageFolder\install.wim }
		}
		Else
		{
			[void]($MountFolder = Create-MountDirectory)
			[void]($ImageFolder = Create-ImageDirectory)
			Copy-Item -Path $InstallWIM -Destination $ImageFolder -Force
			Dismount-DiskImage -ImagePath $ISOPath -StorageType ISO
			If (([IO.FileInfo]"$ImageFolder\install.wim").IsReadOnly) { ATTRIB -R $ImageFolder\install.wim }
		}
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
		If ($Local)
		{
			[void]($MountFolder = Create-MountDirectory)
			[void]($ImageFolder = Create-ImageDirectory)
			Copy-Item -Path $ImagePath -Destination $ImageFolder\install.wim -Force
			If (([IO.FileInfo]"$ImageFolder\install.wim").IsReadOnly) { ATTRIB -R $ImageFolder\install.wim }
		}
		Else
		{
			[void]($MountFolder = Create-MountDirectory)
			[void]($ImageFolder = Create-ImageDirectory)
			Copy-Item -Path $ImagePath -Destination $ImageFolder\install.wim -Force
			If (([IO.FileInfo]"$ImageFolder\install.wim").IsReadOnly) { ATTRIB -R $ImageFolder\install.wim }
		}
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
	Process-Log -Output "$Script Starting." -LogPath $LogFile -Level Info
	[void]($WorkFolder = Create-WorkDirectory)
	[void]($TempFolder = Create-TempDirectory)
	$ImageFile = "$ImageFolder\install.wim"
}
Finally
{
	$Error.Clear()
	Start-Sleep 3
}

Try
{
	Write-Output ''
	Process-Log -Output "Mounting Image." -LogPath $LogFile -Level Info
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder -Optimize)
	$ImageIsMounted = $true
}
Catch [System.Exception]
{
	Write-Output ''
	Process-Log -Output "Failed to mount the Windows Image." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}

If ($ImageIsMounted -eq $true)
{
	[void](Load-OfflineHives)
	$WIMProperties = Get-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	If ($WIMProperties.CurrentBuildNumber -eq "15063")
	{
		Write-Output ''
		Write-Output "The image build [$($WIMProperties.CurrentBuildNumber)] is supported."
		Start-Sleep 3
		Write-Output ''
	}
	ElseIf ($WIMProperties.CurrentBuildNumber -eq "16299")
	{
		Write-Output ''
		Write-Output "The image build [$($WIMProperties.CurrentBuildNumber)] is supported."
		Start-Sleep 3
		Write-Output ''
	}
	Else
	{
		Write-Output ''
		Process-Log -Output "The image build [$($WIMProperties.CurrentBuildNumber)] is not supported." -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
}

If (Verify-OfflineHives)
{
	[void](Unload-OfflineHives)
}

If ($ImageIsMounted -eq $true)
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
		Process-Log -Output "The image has been flagged for corruption. Further servicing is required before the image can be optimized." -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
}

If ($UseWhiteList)
{
	Process-Log -Output "Removing all Provisioning Application Packages not WhiteListed." -LogPath $LogFile -Level Info
	Start-Sleep 3; "`n"
	$AppWhiteList.ForEach{ Write-Output "WhiteListed:`t$_"; Write-Output "$TimeStamp INFO: Skipping Provisioning Application Package: $($_)" >> $LogFile }; "`n";
	Write-Verbose "Please wait." -Verbose
	[void](Get-AppxProvisionedPackage -Path $MountFolder | ? { $_.DisplayName -notin $AppWhiteList } | Remove-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder)
}

If ($SelectApps -or $AllApps)
{
	Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
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

#region Registry Settings
If ($OptimizeRegistry)
{
	$SECURITY_AND_PRIVACY = {
		#****************************************************************
		Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Telemetry and Data Collecting." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Windows Update Peer-to-Peer Distribution." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Windows Auto-Update and Auto-Reboot." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Windows' Peer-to-Peer Networking Service." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Peernet"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling 'Find My Device'." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling PIN requirement for pairing devices." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Home Group Services." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupListener" -Name "Start" -Value 4
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupProvider" -Name "Start" -Value 4
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Text Suggestions and Screen Monitoring." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Steps Recorder." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling App Location Services and Sensors." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Value "Deny"
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" -Name "Value" -Value "Deny"
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Value 2
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling System Location Services and Sensors." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling User Location Services and Sensors." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Error Reporting." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling WiFi Sense." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Windows Asking for Feedback." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling the Password Reveal button." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Non-Explicit App Synchronization." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Value "Deny"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Value 2
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Apps Accessing Phone, SMS/Text Messaging and Call History." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Value "Deny"
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Value "Deny"
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Name "Value" -Value "Deny"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Value 2
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Cross-Device Experiences." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Windows Media Player Statistics Tracking." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Value 0
	}
	$DEVICE_EXPERIENCE = {
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling the MeltDown (CVE-2017-5754) Compatibility Flag." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Explorer Tips, Sync Notifications and Document Tracking." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FolderContentsInfoTip" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableBalloonTips" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StartButtonBalloonTip" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentProgForNewUserInStartMenu" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling System Advertisements and Windows Spotlight." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "IncludeEnterpriseSpotlight" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Toast Notifications." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Feature Advertisement Notifications." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoBalloonFeatureAdvertisements" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling System Tray Promotion Notifications." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoSystraySystemPromotion" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling System and Settings Syncronization." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		$Groups = @(
			"Accessibility"
			"AppSync"
			"BrowserSettings"
			"Credentials"
			"DesktopTheme"
			"Language"
			"PackageState"
			"Personalization"
			"StartLayout"
			"Windows"
		)
		ForEach ($Group in $Groups)
		{
			Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$Group"
			Set-ItemProperty "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$Group" -Name "Enabled" -Value 0
		}
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Value 5
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSyncUserOverride" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Automatic Download of Bloatware Apps and Suggestions." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		$BloatwareApps = @(
			"ContentDeliveryAllowed"
			"FeatureManagementEnabled"
			"OemPreInstalledAppsEnabled"
			"PreInstalledAppsEnabled"
			"PreInstalledAppsEverEnabled"
			"RotatingLockScreenEnabled"
			"RotatingLockScreenOverlayEnabled"
			"SilentInstalledAppsEnabled"
			"SoftLandingEnabled"
			"SystemPaneSuggestionsEnabled"
			"SubscribedContent-310093Enabled"
			"SubscribedContent-338388Enabled"
			"SubscribedContent-338389Enabled"
			"SubscribedContent-338393Enabled"
		) | % { Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "$_" -Value 0 }
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Windows 'Getting to Know Me.'" >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Notifications on Lock Screen." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Lock Screen Camera and Overlays." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Preview Build Telemetry." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Map Auto Downloads." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Speech Model Updates." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0
	}
	$PERFORMANCE_AND_AESTHETICS = {
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling First Log-on Animation." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Changing Search Bar to Magnifying Glass Icon." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Moving Drive Letter Before Drive Label." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling Dark Theme for Settings and Modern Apps." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Increasing Taskbar Transparency." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling 'Shortcut' text for Shortcuts." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value "00000000"
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling Explorer opens to This PC." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Removing Windows Store Icon from Taskbar." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Removing Windows Mail Icon from Taskbar." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling the Windows Mail Application." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0
		#****************************************************************
		If ($Build -ge "16299")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing People Icon from Taskbar" >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0
			Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
			Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1
		}
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling 'How do you want to open this file?' prompt." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Switching to Smaller Control Panel Icons." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Adding This PC Icon to Desktop." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Adding 'Reboot to Recovery' to My PC." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-RegistryOwner -Hive "HKLM" -SubKey "WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell"
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" -Name "Icon" -Value "%SystemRoot%\System32\imageres.dll,-110"
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" -Name '(default)' -Value "shutdown.exe -r -o -f -t 00"
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Live Tiles." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Connected Drive Autoplay and Autorun." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value "255"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\Control Panel\Desktop"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value "100"
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling Photo-Viewer for .BMP, .GIF, .JPG, .PNG and .TIF" >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		ForEach ($ImageType in @("Paint.Picture", "giffile", "jpegfile", "pngfile"))
		{
			Force-MKDIR $("HKLM:\WIM_HKLM_SOFTWARE\Classes\$ImageType\shell\open")
			Force-MKDIR $("HKLM:\WIM_HKLM_SOFTWARE\Classes\$ImageType\shell\open\command")
			Set-ItemProperty -Path $("HKLM:\WIM_HKLM_SOFTWARE\Classes\$ImageType\shell\open") -Name "MuiVerb" -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
			Set-ItemProperty -Path $("HKLM:\WIM_HKLM_SOFTWARE\Classes\$ImageType\shell\open\command") -Name '(Default)' -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
		}
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling 'Open with Photo Viewer.'" >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command"
		Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -Name '(Default)' -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling Developer Mode and Application Sideloading." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Appx"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowDevelopmentWithoutDevLicense" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Appx"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Appx" -Name "AllowDevelopmentWithoutDevLicense" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -Value 1
	}
	$USABILITY_AND_CLEANUP = {
		If ($Build -ge "16299")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			$RemovePaint3D = @(
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.glb\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit"
			) | % { Remove-Item "$_" -Recurse -Force }
		}
		ElseIf ($Build -le "15063")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			$RemovePaint3D = @(
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit"
			) | % { Remove-Item "$_" -Recurse -Force }
		}
		If ($Build -ge "15063")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			$Remove3DPrint = @(
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3ds\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dae\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dxf\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.wrl\Shell\3D Print"
			) | % { Remove-Item "$_" -Recurse -Force }
		}
		ElseIf ($Build -lt "15063")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			$Remove3DPrint = @(
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\T3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\T3D Print"
				"HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.png\Shell\T3D Print"
			) | % { Remove-Item "$_" -Recurse -Force }
		}
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Removing 'Restore Previous Versions' Property Tab and Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		$RemoveRestore = @(
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
			"HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
		) | % { Remove-Item "$_" -Recurse -Force }
		#****************************************************************
		If ($Build -ge "16299")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing 'Share' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" -Value ""
		}
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Removing 'Give Access To' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" -Value ""
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Removing 'Cast To Device' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value ""
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Hiding Recently and Frequently Used Items in Explorer." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0
		#****************************************************************
		If ($Build -ge "16299")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing all User Folders from This PC." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
		}
		ElseIf ($Build -le "15063")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Removing all User Folders from This PC." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide"
		}
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Removing Drives from the Navigation Pane." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}"
		Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}"
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Cleaning up Control Panel CPL links." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowCpl" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "1" -Value "Microsoft.OfflineFiles"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "2" -Value "Microsoft.EaseOfAccessCenter"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "3" -Value "Microsoft.PhoneAndModem"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "4" -Value "Microsoft.RegionAndLanguage"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "5" -Value "Microsoft.ScannersAndCameras"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "6" -Value "Microsoft.SpeechRecognition"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "7" -Value "Microsoft.SyncCenter"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "8" -Value "Microsoft.Infrared"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "9" -Value "Microsoft.ColorManagement"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "10" -Value "Microsoft.Fonts"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "11" -Value "Microsoft.Troubleshooting"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "12" -Value "Microsoft.InternetOptions"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "13" -Value "Microsoft.HomeGroup"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "14" -Value "Microsoft.DateAndTime"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "15" -Value "Microsoft.AutoPlay"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "16" -Value "Microsoft.DeviceManager"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "17" -Value "Microsoft.FolderOptions"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "18" -Value "Microsoft.RegionAndLanguage"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "19" -Value "Microsoft.TaskbarAndStartMenu"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "20" -Value "Microsoft.PenAndTouch"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "21" -Value "Microsoft.BackupAndRestore"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "22" -Value "Microsoft.DevicesAndPrinters"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "23" -Value "Microsoft.WindowsDefender"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "24" -Value "Microsoft.WindowsFirewall"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "25" -Value "Microsoft.WorkFolders"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "26" -Value "Microsoft.WindowsAnytimeUpgrade"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "27" -Value "Microsoft.Language"
		If ($Build -ge "16299")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps"
		}
		ElseIf ($Build -eq "15063")
		{
			#****************************************************************
			Write-Output '' >> $WorkFolder\Registry-Optimizations.log
			Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
			#****************************************************************
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers"
		}
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Recent Document History." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Automatic Sound Reduction." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Enabling Component Clean-up with Reset Base." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" -Name "DisableResetbase" -Value 0
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Setting elevation allowing the removal of the 'DefaultUser0' ghost account." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Set-RegistryOwner -Hive "HKLM" -SubKey "WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" -Name "AutoElevationAllowed" -Value 1
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Disabling Sticky Keys." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"
		Force-MKDIR "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122"
		Force-MKDIR "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58"
	}
	Write-Output ''
	Process-Log -Output "Enhancing system security, usability and performance with registry optimizations." -LogPath $LogFile -Level Info
	[void](Load-OfflineHives)
	& $SECURITY_AND_PRIVACY
	& $DEVICE_EXPERIENCE
	& $PERFORMANCE_AND_AESTHETICS
	& $USABILITY_AND_CLEANUP
	[void](Unload-OfflineHives)
	$RegistryComplete = $true
}
#endregion Registry Settings

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
			$FullKeyPath = "$($InboxAppsKey)\" + $InboxApp
			$AppKey = $FullKeyPath.Replace("HKLM:", "HKLM")
			[void](REG DELETE $AppKey /F)
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
		Process-Log -Output "Disabling remaining Windows Defender services and drivers." -LogPath $LogFile -Level Info
		[void](Load-OfflineHives)
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1
		If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
		{
			Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"
		}
		If ($Build -ge "16299" -and $RegistryComplete -eq $true)
		{
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsdefender"
		}
		ElseIf ($Build -eq "15063" -and $RegistryComplete -eq $true)
		{
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;windowsdefender"
		}
		$DEFENDER_SVCS = @(
			"SecurityHealthService"
			"WinDefend"
			"WdNisSvc"
			"WdNisDrv"
			"Sense"
		) | % { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 }
		$DisableDefenderComplete = $true
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "Failed to disable remaining SecHealthUI services and drivers." -LogPath $LogFile -Level Error
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

If ($SystemAppsComplete -eq $true -and $SystemAppsList -contains "XboxGameCallableUI")
{
	Try
	{
		Write-Output ''
		Process-Log -Output "Disabling remaining Xbox services and drivers." -LogPath $LogFile -Level Info
		[void](Load-OfflineHives)
		Force-MKDIR "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0
		Force-MKDIR "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0
		Force-MKDIR -Path "HKLM:\WIM_HKCU\Software\Microsoft\GameBar"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0
		Force-MKDIR -Path "HKLM:\WIM_HKCU\System\GameConfigStore"
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Force
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2
		Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2
		If ($Build -ge "16299" -and $DisableDefenderComplete -eq $true)
		{
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsdefender"
		}
		ElseIf ($Build -eq "15063" -and $DisableDefenderComplete -eq $true)
		{
			Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsdefender"
		}
		$XBOX_SVCS = @(
			"xbgm"
			"XblAuthManager"
			"XblGameSave"
			"xboxgip"
			"XboxGipSvc"
			"XboxNetApiSvc"
		) | % { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 }
		$DisableXboxComplete = $true
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "Failed to disable remaining Xbox services and drivers." -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
	Finally
	{
		[void](Unload-OfflineHives)
	}
}

If ($RegistryComplete -eq $true)
{
	Try
	{
		Write-Output ''
		Process-Log -Output "Disabling Telemetry, Location, Compatibility Assistance and Delivery Optimization services and drivers." -LogPath $LogFile -Level Info
		[void](Load-OfflineHives)
		$SPYWARE_SVCS = @(
			"DiagTrack"
			"dmwappushservice"
			"diagnosticshub.standardcollector.service"
			"lfsvc"
			"PcaSvc"
			"DoSvc"
		) | % { Force-MKDIR "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_"; Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 }
		Force-MKDIR "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0
		Force-MKDIR "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\Remote Assistance"
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
		Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\Remote Assistance" -Name "fAllowFullControl" -Value 0
	}
	Catch [System.Exception]
	{
		Write-Output ''
		Process-Log -Output "Failed to disable Telemetry, Location, Compatibility Assistance and Delivery Optimization services and drivers." -LogPath $LogFile -Level Error
		Terminate-Script
		Break
	}
	Finally
	{
		[void](Unload-OfflineHives)
	}
}

If ($DisableFeatures)
{
	Write-Output ''
	Process-Log -Output "Disabling all Windows Features included in the Feature Disable List." -LogPath $LogFile -Level Info
	$WindowsFeatures = Get-WindowsOptionalFeature -Path $MountFolder
	ForEach ($Feature in $FeatureDisableList)
	{
		[void]($WindowsFeatures.Where{ $_.FeatureName -like $Feature } | Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $TempFolder)
	}
}

If ($RemovePackages)
{
	Write-Output ''
	Process-Log -Output "Removing all Windows Packages included in the Package Removal List." -LogPath $LogFile -Level Info
	$WindowsPackages = Get-WindowsPackage -Path $MountFolder
	ForEach ($Package in $PackageRemovalList)
	{
		[void]($WindowsPackages.Where{ $_.PackageName -like $Package } | Remove-WindowsPackage -Path $MountFolder -ScratchDirectory $TempFolder)
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

If ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -eq $true)
{
	$SETUPCOMPLETE1 = {
		$SetupCompleteStr1 = @"
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
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL  
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL "%~f0"
"@
		If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
		{
			[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
			$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
			Set-Content -Path $SetupCompleteScript -Value $SetupCompleteStr1 -Encoding ASCII -Force
		}
	}
	& $SETUPCOMPLETE1
}
ElseIf ($DisableDefenderComplete -ne $true -and $DisableXboxComplete -eq $true)
{
	$SETUPCOMPLETE2 = {
		$SetupCompleteStr2 = @"
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
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL  
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL "%~f0"
"@
		If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
		{
			[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
			$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
			Set-Content -Path $SetupCompleteScript -Value $SetupCompleteStr2 -Encoding ASCII -Force
		}
	}
	& $SETUPCOMPLETE2
}
ElseIf ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -ne $true)
{
	$SETUPCOMPLETE3 = {
		$SetupCompleteStr3 = @"
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
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL  
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL "%~f0"
"@
		If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
		{
			[void](New-Item -ItemType Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
			$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
			Set-Content -Path $SetupCompleteScript -Value $SetupCompleteStr3 -Encoding ASCII -Force
		}
	}
	& $SETUPCOMPLETE3
}
Else
{
	$SETUPCOMPLETE4 = {
		$SetupCompleteStr4 = @"
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
			Set-Content -Path $SetupCompleteScript -Value $SetupCompleteStr4 -Encoding ASCII -Force
		}
	}
	& $SETUPCOMPLETE4
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
Catch [System.Exception]
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
	[void](Export-WindowsImage -CheckIntegrity -CompressionType Maximum -SourceImagePath $ImageFile -SourceIndex $Index -DestinationImagePath $WorkFolder\install.wim -ScratchDirectory $TempFolder)
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
	Process-Log -Output "Failed to locate all files." -LogPath $LogFile -Level Error
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
	$SaveErrorLog = Join-Path -Path $env:TEMP -ChildPath "ErrorLog.log"
	Set-Content -Path $SaveErrorLog -Value $Error.ToArray() -Force
	Move-Item -Path $env:TEMP\ErrorLog.log -Destination $SaveFolder -Force
	Write-Output ''
	Write-Output "Newly optimized image has been saved to $SaveFolder."
	Write-Output ''
	Process-Log -Output "$Script completed with [$($Error.Count)] errors." -LogPath $LogFile -Level Warning
	Move-Item -Path $LogFile -Destination $SaveFolder -Force
	Write-Output ''
}
# SIG # Begin signature block
# MIIJngYJKoZIhvcNAQcCoIIJjzCCCYsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYlttR6dZSnE5W1TdePdhAGgj
# t8agggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
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
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSTrP54MqIG9DS0uihrrAd3Wzhv2jCB
# rgYKKwYBBAGCNwIBDDGBnzCBnKCBmYCBlgBBACAAZgB1AGwAbAB5ACAAYQB1AHQA
# bwBtAGEAdABlAGQAIABXAGkAbgBkAG8AdwBzACAAMQAwACAAUgBTADIAIABhAG4A
# ZAAgAFIAUwAzACAAbwBmAGYAbABpAG4AZQAgAGkAbQBhAGcAZQAgAG8AcAB0AGkA
# bQBpAHoAYQB0AGkAbwBuACAAcwBjAHIAaQBwAHQALjANBgkqhkiG9w0BAQEFAASC
# AQCg8iekj6H62QaxP1uslUvmdQrqIeV6yuQxrD3Zdnek9plOX+mQRR6pykn4K1w2
# qYXmr43V7eGV8irdVqf7N4nRdS+dLbAHoB3P6oaPcPlkzklD6vWuXm8i95LcuJgl
# 7/uwMrOntZYXhnnfDyiAPd5lmusqz6gs07DqO87Yt+UkcPoK2Qkgf8YnWvfQZctf
# Lo08MwAnqlQphTmuLRiNzI2ocNdIRUBqZTnAlKTA2fNvUGZeA8a6EI/y9MZhYTPz
# hpB4ixbyI5GqZq+ryzLYX5qZJ74Cj+dokIDcMqzC+PU4zy8VXKeweTNRiKHM+LJK
# z5sTjgJwITfbRZZfbv7lJR+f
# SIG # End signature block
