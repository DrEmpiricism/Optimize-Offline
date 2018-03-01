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
	
	.PARAMETER AddDrivers
		A resolvable path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -AllApps -AddDrivers "E:\DriverFolder" -AdditionalFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\Win10Pro.iso" -Build 16299 -SelectApps -AddDrivers "E:\DriverFolder" -AdditionalFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ISO "D:\Win Images\Win10Pro.iso" -Index 2 -Build 16299 -UseWhiteList -Drivers "E:\DriverFolder" -AdditionalFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -WIM "D:\WIM Files\Win10Pro\install.wim" -Index 3 -Build 15063 -Select -Drivers "E:\DriverFolder\OEM12.inf" -AdditionalFeatures

	.NOTES
		The removal of System Applications, OnDemand Packages and Optional Features are determined by whether or not they are present in the editable array variables.
		In order to prevent them from running completely, you can comment out the variable with a # right before '[string[]]'.
		The only exception is the AppWhiteList, which is enabled by using its respective switch when calling the script.
	
	.NOTES
		===========================================================================
		Created on:   	11/30/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        3.0.7.4
		Last updated:	03/01/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')]
	[ValidateScript({
			If ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
			ElseIf ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
			Else { Throw "$_ is an invalid image path." }
		})]
	[Alias('ISO', 'WIM')]
	[string]$ImagePath,
	[Parameter(HelpMessage = 'If using a multi-index image, specify the index of the image.')]
	[ValidateRange(1, 16)]
	[int]$Index = 1,
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The build number of the image.')]
	[ValidateRange(15063, 16299)]
	[int]$Build,
	[Parameter(HelpMessage = 'Prompts the user for approval before a Provisioning Application Package is removed by outputting its Display Name.')]
	[Alias('Select')]
	[switch]$SelectApps,
	[Parameter(HelpMessage = 'Automatically removes all Provisioning Application Packages.')]
	[switch]$AllApps,
	[Parameter(HelpMessage = 'Automatically removes all Provisioning Application Packages not WhiteListed.')]
	[Alias('WhiteList')]
	[switch]$UseWhiteList,
	[Parameter(Mandatory = $false,
			   HelpMessage = 'The path to a collection of driver packages, or a driver .inf file, to be injected into the image.')]
	[ValidateScript({ Test-Path $(Resolve-Path $_) })]
	[Alias('Drivers')]
	[string]$AddDrivers,
	[Parameter(HelpMessage = 'Sets the mount and save locations to the root path of the script')]
	[switch]$Local
)
## *************************************************************************************************
## *          THE FIELDS BELOW CAN BE EDITED TO FURTHER ACCOMMODATE REMOVAL REQUIREMENTS.          *
## *                      ITEMS CAN SIMPLY BE COMMENTED OUT WITH THE # KEY.                        *
## *************************************************************************************************

##*=============================================
##* SYSTEM APPS TO BE REMOVED
##*=============================================
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

##*=============================================
##* APPX PACKAGES TO KEEP. NO WILDCARDS
##*=============================================
[string[]]$AppWhiteList = @(
	"Microsoft.DesktopAppInstaller"
	"Microsoft.Windows.Photos"
	#"Microsoft.WindowsCalculator"
	"Microsoft.Xbox.TCUI"
	#"Microsoft.XboxIdentityProvider"
	"Microsoft.WindowsCamera"
	"Microsoft.StorePurchaseApp"
	"Microsoft.WindowsStore"
)

##*=============================================
##* OPTIONAL FEATURES TO DISABLE.
##*=============================================
[string[]]$FeatureDisableList = @(
	"WorkFolders-Client"
	"*WindowsMediaPlayer*"
	"*Internet-Explorer*"
	"*MediaPlayback*"
	"*MediaPlayer*"
)

##*=============================================
##* PACKAGES TO REMOVE.
##*=============================================
[string[]]$PackageRemovalList = @(
	"*ContactSupport*"
	"*QuickAssist*"
	#"*InternetExplorer*"
	#"*MediaPlayer*"
	#"*Hello-Face*"
)
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
$TimeStamp = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
$Desktop = [Environment]::GetFolderPath("Desktop")
$RootPath = [Environment]::CurrentDirectory
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
	Write-Output ''
	Start-Sleep 3
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

#region C# Coded Token Privilege Method
Add-Type @"
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

Function Set-RegistryOwner # Changes the ownership and access control of protected registry keys and subkeys (those owned by TrustedInstaller) in order to add or remove values.
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)]
		[string]$Hive,
		[Parameter(Mandatory = $true)]
		[string]$SubKey
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
		$WorkDir = [System.IO.Path]::Combine($RootPath, [System.Guid]::NewGuid())
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
		$TempDir = [System.IO.Path]::Combine($RootPath, [System.Guid]::NewGuid())
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
		$ImageDir = [System.IO.Path]::Combine($RootPath, [System.Guid]::NewGuid())
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
		$MountDir = [System.IO.Path]::Combine($RootPath, [System.Guid]::NewGuid())
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
		New-Item -ItemType Directory -Path $RootPath\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
	Else
	{
		New-Item -ItemType Directory -Path $Desktop\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
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
	
	Try
	{
		$CurrentMount = Get-WindowsImage -Mounted
		Write-Output ''
		Write-Verbose "Current mount location detected. Performing clean-up." -Verbose
		$CurrentMount = Get-WindowsImage -Mounted
		$MountPath = $CurrentMount.MountPath
		$ImagePath = $CurrentMount.ImagePath
		$ImageParentPath = Split-Path -Path $ImagePath -Parent
		$HivesToUnload = REG QUERY HKLM | FINDSTR /V "\BCD00000000 \DRIVERS \HARDWARE \SAM \SECURITY \SOFTWARE \SYSTEM"
		If ($HivesToUnload -ne $null)
		{
			[void]($HivesToUnload.ForEach{ REG UNLOAD $_ })
		}
		[void](Dismount-WindowsImage -Path $MountPath -Discard)
		[void](Clear-WindowsCorruptMountPoint)
		[void](Remove-Item -Path $MountPath -Recurse -Force)
		If ($ImageParentPath.Contains("Temp"))
		{
			[void](Remove-Item -Path $ImageParentPath -Recurse -Force)
		}
		Else
		{
			[void](Remove-Item -Path $ImagePath -Force)
		}
		Write-Output ''
		Write-Output "Clean-up complete."
	}
	Catch
	{
		Continue
	}
}

Function Force-MKDIR
{
	Param
	(
		[Parameter(Mandatory = $true)]
		$Path
	)
	
	If (!(Test-Path -Path $Path))
	{
		[void](New-Item -Path $Path -ItemType Directory -Force)
	}
}
#endregion Helper Primary Functions

If (!(Verify-Admin))
{
	Write-Warning -Message "Administrative access is required. Please re-launch PowerShell with elevation."
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
		Write-Verbose "Copying the WIM from $(Split-Path $ISOPath -Leaf) to a temporary directory." -Verbose
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
		Write-Verbose "Copying the WIM to a temporary directory." -Verbose
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
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
	$ImageIsMounted = $true
}
Catch
{
	Write-Output ''
	Process-Log -Output "Failed to mount the Windows Image." -LogPath $LogFile -Level Error
	Terminate-Script
	Break
}

If ($ImageIsMounted -eq $true)
{
	[void](Load-OfflineHives)
	$WIMVersion = Get-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	If ($WIMVersion.CurrentBuildNumber -eq "15063")
	{
		Write-Output ''
		Write-Output "The image build [$($WIMVersion.CurrentBuildNumber)] is supported."
		Start-Sleep 3
		Write-Output ''
	}
	ElseIf ($WIMVersion.CurrentBuildNumber -ge "16273")
	{
		Write-Output ''
		Write-Output "The image build [$($WIMVersion.CurrentBuildNumber)] is supported."
		Start-Sleep 3
		Write-Output ''
	}
	Else
	{
		Write-Output ''
		Process-Log -Output "The image build [$($WIMVersion.CurrentBuildNumber)] is not supported." -LogPath $LogFile -Level Error
		Terminate-Script
		Throw
	}
}

If (Verify-OfflineHives)
{
	[void](Unload-OfflineHives)
}

If ($ImageIsMounted -eq $true)
{
	Process-Log -Output "Verifying image health." -LogPath $LogFile -Level Info
	$StartHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth
	If ($StartHealthCheck.ImageHealthState -eq "Healthy")
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
		Throw
	}
}

If ($UseWhiteList)
{
	Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
		If ($_.DisplayName -notin $AppWhiteList)
		{
			Process-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
			[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
		}
	}
}

If ($SelectApps)
{
	Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
		$AppSelect = Read-Host "Remove Provisioned App Package:" $_.DisplayName "(Y/N)"
		If ($AppSelect -eq "y")
		{
			Process-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
			[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
			$AppSelect = ''
		}
		Else
		{
			Write-Output "Skipping Provisioned App Package: $($_.DisplayName)"
			$AppSelect = ''
		}
	}
}

If ($AllApps)
{
	Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
		Process-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
		[void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder)
	}
}

#region Registry Optimizations
Try
{
	Clear-Host
	Process-Log -Output "Enhancing system security, usability and performance with registry optimizations." -LogPath $LogFile -Level Info
	[void](Load-OfflineHives)
	$Software = "HKLM:\WIM_HKLM_SOFTWARE"
	$System = "HKLM:\WIM_HKLM_SYSTEM"
	$CUSoftware = "HKLM:\WIM_HKCU\Software"
	$CUSystem = "HKLM:\WIM_HKCU\System"
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
	[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f)
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
	[void](REG ADD "HKLM\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f)
	[void](REG ADD "HKLM\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f)
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
	Write-Output "Disabling Windows Media Player Statistics Tracking." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	[void](REG ADD "HKLM\WIM_HKCU\Software\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f)
	#****************************************************************
	Write-Output '' >> $WorkFolder\Registry-Optimizations.log
	Write-Output "Enabling the MeltDown (CVE-2017-5754) Compatibility Flag." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" /v "cadca5fe-87d3-4b96-b7fb-a231484277cc" /t REG_DWORD /d "0" /f)
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
	) | % {
		Force-MKDIR "$CUSoftware\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" |
		Set-ItemProperty "$CUSoftware\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -Name "Enabled" -Value 0 }
	[void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f)
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
	Write-Output "Disabling Automatic Download of Content and Suggestions." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	$ContentDelivery = @(
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
	) | % {
		Force-MKDIR -Path "$CUSoftware\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" |
		Set-ItemProperty -Path "$CUSoftware\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "$_" -Value 0 }
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
	Write-Output '' >> $WorkFolder\Registry-Optimizations.log
	Write-Output "Disabling First Log-on Animation." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f)
	#****************************************************************
	Write-Output '' >> $WorkFolder\Registry-Optimizations.log
	Write-Output "Changing Search Bar to Icon." >> $WorkFolder\Registry-Optimizations.log
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
	If ($Build -ge "16273")
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
	Write-Output "Adding 'Reboot to Recovery' to My PC." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	Set-RegistryOwner -Hive "HKLM" -SubKey "WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell"
	[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d "%SystemRoot%\System32\imageres.dll,-110" /f)
	[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f)
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
	Write-Output "Enabling Photo-Viewer for .BMP, .GIF, .JPG, .PNG and .TIF" >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	ForEach ($ImageType in @("Paint.Picture", "giffile", "jpegfile", "pngfile"))
	{
		Force-MKDIR -Path $("$Software\Classes\$ImageType\shell\open")
		Force-MKDIR -Path $("$Software\Classes\$ImageType\shell\open\command")
		Set-ItemProperty -Path $("$Software\Classes\$ImageType\shell\open") -Name "MuiVerb" `
						 -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("$Software\Classes\$ImageType\shell\open\command") -Name '(Default)' `
						 -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
	#****************************************************************
	Write-Output '' >> $WorkFolder\Registry-Optimizations.log
	Write-Output "Enabling 'Open with Photo Viewer.'" >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	Force-MKDIR -Path "$Software\Classes\Applications\photoviewer.dll\shell\open\command"
	Force-MKDIR -Path "$Software\Classes\Applications\photoviewer.dll\shell\open\DropTarget"
	Set-ItemProperty -Path "$Software\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" `
					 -Value "@photoviewer.dll,-3043"
	Set-ItemProperty -Path "$Software\Classes\Applications\photoviewer.dll\shell\open\command" -Name '(Default)' `
					 -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	Set-ItemProperty -Path "$Software\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" `
					 -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
	If ($Build -ge "16273")
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
	ElseIf ($Build -eq "15063")
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
	If ($Build -ge "16273")
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
	If ($Build -ge "16273")
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
	ElseIf ($Build -eq "15063")
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
	If ($Build -ge "16273")
	{
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
		If ($SystemAppsList -contains "SecHealthUI")
		{
			Set-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
							 -Name "SettingsPageVisibility" `
							 -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsdefender"
		}
		Else
		{
			Set-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
							 -Name "SettingsPageVisibility" `
							 -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps"
		}
	}
	ElseIf ($Build -eq "15063")
	{
		#****************************************************************
		Write-Output '' >> $WorkFolder\Registry-Optimizations.log
		Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************
		Force-MKDIR -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
		If ($SystemAppsList -contains "SecHealthUI")
		{
			Set-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
							 -Name "SettingsPageVisibility" `
							 -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsdefender"
		}
		Else
		{
			Set-ItemProperty -Path "$Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
							 -Name "SettingsPageVisibility" `
							 -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;windowsinsider;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking"
		}
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
	#****************************************************************
	Write-Output '' >> $WorkFolder\Registry-Optimizations.log
	Write-Output "Setting elevation allowing the removal of the 'DefaultUser0' ghost account." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	Set-RegistryOwner -Hive "HKLM" -SubKey "WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}"
	[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f)
	#****************************************************************
	Write-Output '' >> $WorkFolder\Registry-Optimizations.log
	Write-Output "Disabling Sticky Keys." >> $WorkFolder\Registry-Optimizations.log
	#****************************************************************
	[void](REG ADD "HKLM\WIM_HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "506" /f)
	[void](REG ADD "HKLM\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "122" /f)
	[void](REG ADD "HKLM\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "58" /f)
	#****************************************************************
	[void](Unload-OfflineHives)
	$RegistryComplete = $true
}
Catch
{
	Write-Output ''
	Process-Log -Output "Unable to apply registry optimizations." -LogPath $LogFile -Level Error
	Terminate-Script
	Throw
}
#endregion Registry Optimizations

If ($RegistryComplete -eq $true)
{
	Write-Output ''
	Process-Log -Output "Applying a custom Start Menu and Taskbar Layout." -LogPath $LogFile -Level Info
	Start-Sleep 3
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
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UWP File Explorer.lnk")
	$Shortcut.TargetPath = "C:\Windows\explorer.exe"
	$Shortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
	$Shortcut.IconLocation = "imageres.dll,-1023"
	$Shortcut.WorkingDirectory = "C:\Windows"
	$Shortcut.Description = "The UWP File Explorer Application."
	$Shortcut.Save()
}

If ($SystemAppsList.Count -gt "0")
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

If ($SystemAppsList -contains "SecHealthUI")
{
	Write-Output ''
	Process-Log -Output "Disabling remaining Windows Defender services and drivers." -LogPath $LogFile -Level Info
	[void](Load-OfflineHives)
	Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender"
	Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
	Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
	Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
	Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT"
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1
	If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
	{
		[void](Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth")
	}
	$DEFENDER_SVCS = @(
		"SecurityHealthService"
		"WinDefend"
		"WdNisSvc"
		"WdNisDrv"
		"Sense"
	) | % { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 }
	[void](Unload-OfflineHives)
	$DisableDefenderComplete = $true
}

If ($DisableDefenderComplete -eq $true -and $Build -ge "16273")
{
	Write-Output ''
	Process-Log -Output "Disabling Windows-Defender-Default-Defintions." -LogPath $LogFile -Level Info
	[void](Disable-WindowsOptionalFeature -Path $MountFolder -FeatureName "Windows-Defender-Default-Definitions" -ScratchDirectory $TempFolder)
}

If ($SystemAppsList -contains "XboxGameCallableUI")
{
	Write-Output ''
	Process-Log -Output "Disabling remaining Xbox services and drivers." -LogPath $LogFile -Level Info
	[void](Load-OfflineHives)
	Force-MKDIR -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR"
	Force-MKDIR -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR"
	Force-MKDIR -Path "HKLM:\WIM_HKCU\Software\Microsoft\GameBar"
	Force-MKDIR -Path "HKLM:\WIM_HKCU\System\GameConfigStore"
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2
	$XBOX_SVCS = @(
		"xbgm"
		"XblAuthManager"
		"XblGameSave"
		"xboxgip"
		"XboxGipSvc"
		"XboxNetApiSvc"
	) | % { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 }
	[void](Unload-OfflineHives)
	$DisableXboxComplete = $true
}

If ($FeatureDisableList.Count -gt "0")
{
	Write-Output ''
	Process-Log -Output "Disabling Windows Features." -LogPath $LogFile -Level Info
	$WindowsFeatures = Get-WindowsOptionalFeature -Path $MountFolder
	ForEach ($Feature in $FeatureDisableList)
	{
		[void]($WindowsFeatures.Where{ $_.FeatureName -like $Feature } | Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $TempFolder)
	}
}

If ($PackageRemovalList.Count -gt "0")
{
	Write-Output ''
	Process-Log -Output "Removing Windows Packages." -LogPath $LogFile -Level Info
	$WindowsPackages = Get-WindowsPackage -Path $MountFolder
	ForEach ($Package in $PackageRemovalList)
	{
		[void]($WindowsPackages.Where{ $_.PackageName -like $Package } | Remove-WindowsPackage -Path $MountFolder -ScratchDirectory $TempFolder)
	}
}

If ($AddDrivers)
{
	If ((Test-Path -Path $AddDrivers -PathType Container) -and (Get-ChildItem -Path $AddDrivers -Recurse -Include "*.inf"))
	{
		Write-Output ''
		Process-Log -Output "Injecting driver packages into the image." -LogPath $LogFile -Level Info
		[void](Add-WindowsDriver -Path $MountFolder -Driver $AddDrivers -Recurse -ForceUnsigned)
		Get-WindowsDriver -Path $MountFolder | Format-List | Out-File $WorkFolder\DriverPackageList.txt -Force
	}
	ElseIf ((Test-Path -Path $AddDrivers -PathType Leaf) -and ([IO.FileInfo]$AddDrivers).Extension -like ".inf")
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
	$EndHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth
	If ($EndHealthCheck.ImageHealthState -eq "Healthy")
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
Catch
{
	Write-Output ''
	Process-Log -Output "Failed to verify the image health." -LogPath $LogFile -Level Error
	Terminate-Script
	Throw
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
Catch
{
	Write-Output ''
	Process-Log -Output "An I/O error occured while trying to save and dismount the Windows Image." -LogPath $LogFile -Level Error
	Terminate-Script
	Throw
}

Try
{
	Write-Output ''
	Process-Log -Output "Rebuilding and compressing the new image." -LogPath $LogFile -Level Info
	[void](Export-WindowsImage -CheckIntegrity -CompressionType maximum -SourceImagePath $ImageFile -SourceIndex $Index -DestinationImagePath $WorkFolder\install.wim -ScratchDirectory $TempFolder)
}
Catch
{
	Write-Output ''
	Process-Log -Output "An I/O error occured while trying to rebuild and compress the the new image." -LogPath $LogFile -Level Error
	Terminate-Script
	Throw
}


If (Test-Path -Path $WorkFolder\install.wim)
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUC7fhn1mfet/nr0hnbomMhRQ/
# PVigggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
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
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQAc+QWGZe0fBETLVpnRbFuFycfFDCB
# rgYKKwYBBAGCNwIBDDGBnzCBnKCBmYCBlgBBACAAZgB1AGwAbAB5ACAAYQB1AHQA
# bwBtAGEAdABlAGQAIABXAGkAbgBkAG8AdwBzACAAMQAwACAAUgBTADIAIABhAG4A
# ZAAgAFIAUwAzACAAbwBmAGYAbABpAG4AZQAgAGkAbQBhAGcAZQAgAG8AcAB0AGkA
# bQBpAHoAYQB0AGkAbwBuACAAcwBjAHIAaQBwAHQALjANBgkqhkiG9w0BAQEFAASC
# AQA01C/1hWtD2PGE/tEU9PzNRWl+A0uUx9Fv/TjlzaRYsn+lkO4sEsNIds70ku/N
# Z0T8yDow/QqHAu7puH1dlekySk3lSCrRVtkU2Ct24DncO/bEEtCK2+jJVOAq8k3v
# 0AxTBe1VdkHODMRONHay2SFaeaaJXnG2GrKRdvBylm1KmEp1duFrIhkccBsfpTAP
# QWZQMGXoJSIIfJc3D69il6NaVNlBJUeXbZMAjbVvQGAFfsZOukDxpjJVSHJGIOaO
# 2zaawJC2q3quxxRL7HZk3UEQaq56a+R7ZWGjmw7ik8oh9kURow2U1hM6D1JZsAFG
# 0QX5xTIPnunJGg47FUEpU6ma
# SIG # End signature block
