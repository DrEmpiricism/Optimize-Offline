#Requires -RunAsAdministrator
#Requires -Version 5
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 Creator's Update builds RS2, RS3 and RS4 64-bit.
	
	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, privacy and security enhancements, cleaner aesthetics, increased performance and a significantly better user experience.
		Does not perform any changes to an installed or live system nor can it optimize a live system.
		Makes multiple changes to both the offline system and registry hives to enhance security, usability and privacy while also improving performance.
		Generates installation scripts to accommodate offline changes.
		Checks the health of the image both before and after the script runs to ensure the image retains a healthy status.
		Detects what System Applications were removed, and further removes any associated drivers or services associated with them.
		Adds removed System Applications' scheduled tasks to the SetupComplete script to be automatically disabled during Windows installation.
		Optional Features and Windows Packages can be removed and/or disabled by editing their respective arrays.
		It is up to the end-user to be aware of all changes made prior to running this script.
	
	.PARAMETER ImagePath
		The path to a Windows Installation ISO or an Install.WIM.
	
	.PARAMETER Index
		If using a multi-index image, specify the index of the image.
	
	.PARAMETER Build
		The build number of the image.
	
	.PARAMETER SelectApps
		Prompts the user for approval before a Provisioning Application Package is removed.
	
	.PARAMETER AllApps
		Automatically removes all Provisioning Application Packages.
	
	.PARAMETER WhiteListApps
		Automatically removes all Provisioning Application Packages not WhiteListed.
	
	.PARAMETER SetRegistry
        	Sets optimized registry values into the offline registry hives.
        
    	.PARAMETER Hardened
		Increases device security and further restricts more access to such things as system and app sensors. Moreover, the SetupComplete script is quite a bit more substantive.
	
	.PARAMETER Drivers
		A resolvable path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.PARAMETER AdditionalFeatures
		Invokes the Additional-Features function to apply additional customizations and tweaks included in its parameter hashtable.
	
	.PARAMETER Local
		Sets the mount and save locations to the root path of the script
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -AllApps -Drivers "E:\DriverFolder" -SetRegistry -AdditionalFeatures
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\Win10Pro.iso" -Build 15063 -SelectApps -Hardened -AdditionalFeatures -Local
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ISO "D:\Win Images\Win10Pro.iso" -Index 2 -Build 16299 -WhiteListApps -Drivers "E:\DriverFolder" -Local
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -WIM "D:\WIM Files\Win10Pro\install.wim" -Index 3 -Build 15063 -Select -SetRegistry -Drivers "E:\DriverFolder\OEM12.inf"
	
	.NOTES
        	The removal of System Applications, OnDemand Packages and Optional Features are determined by whether or not they are present in the editable arrays.
        	You do not need to run the -SetRegistry and -Hardened switch simultaneously.  If you run the -Hardened switch, the registry optimizations will apply regardless.
	
	.NOTES
        	===========================================================================
        	Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.150
		Created on:   	11/30/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        3.0.8.8
		Last updated:	04/12/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $true,
        HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')]
    [ValidateScript( {
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
    [switch]$WhiteListApps,
    [Parameter(HelpMessage = 'Sets optimized registry values into the offline registry hives.')]
    [switch]$SetRegistry,
    [Parameter(HelpMessage = 'Sets more restrictive registry values into the offline registry hives.')]
    [switch]$Hardened,
    [Parameter(Mandatory = $false,
        HelpMessage = 'The path to a collection of driver packages, or a driver .inf file, to be injected into the image.')]
    [ValidateScript( { Test-Path $(Resolve-Path $_) })]
    [string]$Drivers,
    [Parameter(HelpMessage = 'Calls the Additional-Features function script to apply additional customizations and tweaks included in its parameter hashtable.')]
    [switch]$AdditionalFeatures,
    [Parameter(HelpMessage = 'Sets the mount and save locations to the root path of the script')]
    [switch]$Local
)

. .\Additional-Features.ps1
## *************************************************************************************************
## *          THE FIELDS BELOW CAN BE EDITED TO FURTHER ACCOMMODATE REMOVAL REQUIREMENTS.          *
## *                      ITEMS CAN SIMPLY BE COMMENTED OUT WITH THE # KEY.                        *
## *************************************************************************************************

##*=============================================
##* SYSTEM APPS TO BE REMOVED
##*=============================================
$SystemAppsList = @(
    #"contactsupport" # It's recommended to remove this using its OnDemand Package instead by adding it to the $PackageRemovalList.
    "ContentDeliveryManager"
    #"Cortana" # Removing Cortana will completely disable all default functions of Windows Search.
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
    #"XboxGameCallableUI" # Removing XboxGameCallableUI will prevent Microsoft's App Troubleshooter from functioning properly.
)
##*=============================================
##* APP PACKAGES TO KEEP BY DISPLAY NAME.
##*=============================================
$AppWhiteList = @(
    "Microsoft.DesktopAppInstaller"
    "Microsoft.Windows.Photos"
    #"Microsoft.WindowsCalculator"
    "Microsoft.Xbox.TCUI" # Removing Microsoft.Xbox.TCUI will prevent Microsoft's App Troubleshooter from functioning properly.
    "Microsoft.XboxIdentityProvider"
    #"Microsoft.WindowsCamera"
    #"Microsoft.WebMediaExtensions" 
    "Microsoft.StorePurchaseApp"
    "Microsoft.WindowsStore"
)
##*=============================================
##* OPTIONAL FEATURES TO DISABLE. USE WILDCARDS.
##*=============================================
$FeatureDisableList = @(
    "WorkFolders-Client"
    "*WindowsMediaPlayer*"
    "*Internet-Explorer*"
    #"*MediaPlayback*"
)
##*=============================================
##* ON-DEMAND PACKAGES TO REMOVE. USE WILDCARDS.
##*=============================================
$PackageRemovalList = @(
    "*ContactSupport*"
    "*QuickAssist*"
    #"*InternetExplorer*"
    #"*MediaPlayer*"
    #"*Hello-Face*"
)
##*=============================================
##* ADDITIONAL-FEATURES FUNCTION SCRIPT PARAMS.
##*=============================================
$AddFeatures = @{
    ContextMenu      = $true
    NetFx3           = $null
    SystemImages     = $null
    OfflineServicing = $null
    Unattend         = $null
    GenuineTicket    = $null
    HostsFile        = $true
    Win32Calc        = $true
    SysPrep          = $null
}
## *************************************************************************************************
## *                                      END EDITABLE FIELDS.                                     *
## *************************************************************************************************

#region Script Variables
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$Host.UI.RawUI.WindowTitle = "Optimizing image."
$ProgressPreference = 'SilentlyContinue'
$TimeStamp = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
$Script = "Optimize-Offline"
$LogFile = "$env:TEMP\Optimize-Offline.log"
$DISMLog = "$env:TEMP\DISM.log"
$Desktop = [Environment]::GetFolderPath("Desktop")
#endregion Script Variables

#region Helper Functions
Function Test-Admin {
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Write-Verbose "IsUserAdmin? $IsAdmin"
    Return $IsAdmin
}

Function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output,
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "$Env:SystemDrive\PowerShellLog.log",
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = "Info"
    )
	
    Begin {
        $VerbosePreference = "Continue"
    }
    Process {
        If (!(Test-Path -Path $LogPath)) {
            Write-Verbose "Logging has started."
            Write-Output ''
            Start-Sleep 2
            $CreateLogFile = New-Item $LogPath -ItemType File -Force
        }
        $DateFormat = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
        Switch ($Level) {
            'Info' {
                Write-Verbose $Output
                $LogLevel = "INFO:"
            }
            'Warning' {
                Write-Warning $Output
                $LogLevel = "WARNING:"
            }
            'Error' {
                Write-Error $Output
                $LogLevel = "ERROR:"
            }
        }
        "$DateFormat $LogLevel $Output" | Out-File -FilePath $LogPath -Append
    }
}

Function Set-RegistryOwner {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Hive,
        [Parameter(Mandatory = $true)]
        [string]$SubKey
    )
	
    Begin {
        #region C# Process Privilege Method
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;
namespace ProcessPrivileges
{
    public sealed class AccessTokens
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
            ref IntPtr phtok
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
        public static void GrantPrivilege(string privilege)
        {
            try
            {
                bool retVal;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(
                    hproc,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    ref htok
                    );
                TokPriv1Luid tp;
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
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static void RevokePrivilege(string privilege)
        {
            try
            {
                bool retVal;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(
                    hproc,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    ref htok
                    );
                TokPriv1Luid tp;
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
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
'@
        #endregion C# Process Privilege Method
        [ProcessPrivileges.AccessTokens]::GrantPrivilege("SeTakeOwnershipPrivilege") # Grants the privilege to override access control permissions.
        [ProcessPrivileges.AccessTokens]::GrantPrivilege("SeRestorePrivilege") # Grants the privilege to restore ownership permissions.
    }
    Process {
        Switch ($Hive.ToString().ToLower()) {
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
        $ACL = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None) # Assigns access control to a blank access control object.
        $SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # Assigns the SID of the built-in Administrator to a new object.
        $Admin = $SID.Translate([System.Security.Principal.NTAccount]) # Translates the build-in Administrator SID to its NTAccount.
        $ACL.SetOwner($Admin) # Sets the ownership to the built-in Administrator.
        $Key.SetAccessControl($ACL) # Sets the access control permissions to the built-in Administrator.
        $ACL = $Key.GetAccessControl() # Retrieves the access control information for the registry subkey.
        $Rights = [System.Security.AccessControl.RegistryRights]"FullControl" # Designates the registry object access control rights.
        $Inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit" # Designates the object access control inheritance flags.
        $Propagation = [System.Security.AccessControl.PropagationFlags]"None" # Designates the object access control propogation flags.
        $Control = [System.Security.AccessControl.AccessControlType]"Allow" # Designates whether access is Allowed or Denied on the object.
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule($Admin, $Rights, $Inheritance, $Propagation, $Control) # Assigns the access control rule to a new object.
        $ACL.SetAccessRule($Rule) # Sets the new access control rule.
        $Key.SetAccessControl($ACL) # Sets the access control permissions to the object rule.
        $Key.Close() # Closes the subkey.
        Switch ($Hive.ToString().ToLower()) {
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
        $ACL = Get-Acl $Key
        $TrustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
        $ACL.SetOwner($TrustedInstaller)
        $ACL | Set-Acl $Key # Restores the ownership and access control permissions after the changes to the subkey have been made.
    }
    End {
        [ProcessPrivileges.AccessTokens]::RevokePrivilege("SeTakeOwnershipPrivilege") # The privilege is revoked upon completion of the process block.
        [ProcessPrivileges.AccessTokens]::RevokePrivilege("SeRestorePrivilege") # The privilege is revoked upon completion of the process block.
    }
}

Function New-WorkDirectory {
    If ($Local) {
        $WorkDir = [System.IO.Path]::Combine($PSScriptRoot, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($WorkDir)
        $WorkDir
    }
    Else {
        $WorkDir = [System.IO.Path]::GetTempPath()
        $WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($WorkDir)
        $WorkDir
    }
}

Function New-TempDirectory {
    If ($Local) {
        $TempDir = [System.IO.Path]::Combine($PSScriptRoot, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($TempDir)
        $TempDir
    }
    Else {
        $TempDir = [System.IO.Path]::GetTempPath()
        $TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($TempDir)
        $TempDir
    }
}

Function New-ImageDirectory {
    If ($Local) {
        $ImageDir = [System.IO.Path]::Combine($PSScriptRoot, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($ImageDir)
        $ImageDir
    }
    Else {
        $ImageDir = [System.IO.Path]::GetTempPath()
        $ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($ImageDir)
        $ImageDir
    }
}

Function New-MountDirectory {
    If ($Local) {
        $MountDir = [System.IO.Path]::Combine($PSScriptRoot, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($MountDir)
        $MountDir
    }
    Else {
        $MountDir = [System.IO.Path]::GetTempPath()
        $MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($MountDir)
        $MountDir
    }
}

Function New-SaveDirectory {
    If ($Local) {
        New-Item -ItemType Directory -Path $PSScriptRoot\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
    }
    Else {
        New-Item -ItemType Directory -Path $Desktop\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
    }
}

Function Mount-OfflineHives {
    [void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\Windows\System32\config\software")
    [void](REG LOAD HKLM\WIM_HKLM_SYSTEM "$MountFolder\Windows\System32\config\system")
    [void](REG LOAD HKLM\WIM_HKCU "$MountFolder\Users\Default\NTUSER.DAT")
    [void](REG LOAD HKLM\WIM_HKU_DEFAULT "$MountFolder\Windows\System32\config\default")
}

Function Dismount-OfflineHives {
    Start-Sleep 3
    [System.GC]::Collect()
    [void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
    [void](REG UNLOAD HKLM\WIM_HKLM_SYSTEM)
    [void](REG UNLOAD HKLM\WIM_HKCU)
    [void](REG UNLOAD HKLM\WIM_HKU_DEFAULT)
}

Function Test-OfflineHives {
    Param ()
	
    $HivePaths = @(
        "HKLM:\WIM_HKLM_SOFTWARE"
        "HKLM:\WIM_HKLM_SYSTEM"
        "HKLM:\WIM_HKCU"
        "HKLM:\WIM_HKU_DEFAULT"
    ) | % { $HivesLoaded = ((Test-Path -Path $_) -eq $true) }; Return $HivesLoaded
}

Function Exit-Script {
    Start-Sleep 3
    Write-Output ''
    Write-Verbose "Cleaning-up and terminating script." -Verbose
    If (Test-OfflineHives) {
        [void](Dismount-OfflineHives)
    }
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder -LogPath $DISMLog)
    [void](Clear-WindowsCorruptMountPoint -LogPath $DISMLog)
    If ($Local) {
        [void](Move-Item -Path $LogFile -Destination $PSScriptRoot -Force)
        [void](Move-Item -Path $DISMLog -Destination $PSScriptRoot -Force)
        [void](Move-Item -Path $WorkFolder\Registry-Optimizations.log -Destination $PSScriptRoot -Force)
    }
    Else {
        [void](Move-Item -Path $LogFile -Destination $Desktop -Force)
        [void](Move-Item -Path $DISMLog -Destination $Desktop -Force)
        [void](Move-Item -Path $WorkFolder\Registry-Optimizations.log -Destination $Desktop -Force)
    }
    [void](Remove-Item -Path $WorkFolder -Recurse -Force)
    [void](Remove-Item -Path $TempFolder -Recurse -Force)
    [void](Remove-Item -Path $ImageFolder -Recurse -Force)
    [void](Remove-Item -Path $MountFolder -Recurse -Force)
}

Function New-Container($Path) {
    If (!(Test-Path -Path $Path)) {
        [void](New-Item -Path $Path -ItemType Directory -Force)
    }
}
#endregion Helper Primary Functions

If (!(Test-Admin)) {
    Write-Warning "Administrative access is required. Please re-launch PowerShell with elevation."
    Break
}

If ($SelectApps -and $AllApps) {
    Write-Warning "The SelectApps switch and AllApps switch cannot be enabled at the same time."
    Break
}

If ($SelectApps -and $WhiteListApps) {
    Write-Warning "The SelectApps switch and UseWhiteList switch cannot be enabled at the same time."
    Break
}

If ($AllApps -and $WhiteListApps) {
    Write-Warning "The AllApps switch and UseWhiteList switch cannot be enabled at the same time."
    Break
}

If ($SetRegistry -and $Hardened) {
    Write-Warning "The SetRegistry switch and Hardened switch cannot be enabled at the same time."
    Break
}

If (([IO.FileInfo]$ImagePath).Extension -eq ".ISO") {
    $ImagePath = (Resolve-Path -Path $ImagePath).Path
    $MountImage = Mount-DiskImage -ImagePath $ImagePath -StorageType ISO -PassThru
    $DriveLetter = ($MountImage | Get-Volume).DriveLetter
    $WimFile = "$($DriveLetter):\sources\install.wim"
    If (Test-Path -Path $WimFile -PathType Leaf) {
        Write-Verbose "Copying the WIM from $(Split-Path -Path $ImagePath -Leaf)" -Verbose
        [void]($MountFolder = New-MountDirectory)
        [void]($ImageFolder = New-ImageDirectory)
        [void]($WorkFolder = New-WorkDirectory)
        [void]($TempFolder = New-TempDirectory)
        Copy-Item -Path $WimFile -Destination $ImageFolder -Force
        $ImageFile = "$ImageFolder\install.wim"
        Dismount-DiskImage -ImagePath $ImagePath -StorageType ISO
        $ImageFile = Get-Item -Path $ImageFile -Force
        If ($ImageFile.IsReadOnly) {
            Set-ItemProperty -Path $ImageFile -Name IsReadOnly -Value $false
        }
    }
    Else {
        Write-Warning "$(Split-Path -Path $ImagePath -Leaf) does not contain valid Windows Installation media."
        Break
    }
}
ElseIf (([IO.FileInfo]$ImagePath).Extension -eq ".WIM") {
    $ImagePath = (Resolve-Path -Path $ImagePath).Path
    Write-Verbose "Copying the WIM from $(Split-Path -Path $ImagePath -Parent)" -Verbose
    [void]($MountFolder = New-MountDirectory)
    [void]($ImageFolder = New-ImageDirectory)
    [void]($WorkFolder = New-WorkDirectory)
    [void]($TempFolder = New-TempDirectory)
    Copy-Item -Path $ImagePath -Destination $ImageFolder -Force
    $ImageFile = "$ImageFolder\install.wim"
    $ImageFile = Get-Item -Path $ImageFile -Force
    If ($ImageFile.IsReadOnly) {
        Set-ItemProperty -Path $ImageFile -Name IsReadOnly -Value $false
    }
}

If (Test-Path -Path $DISMLog) {
    Remove-Item -Path $DISMLog -Force
}

If (Test-Path -Path $LogFile) {
    Remove-Item -Path $LogFile -Force
}

Try {
    $CheckBuild = (Get-WindowsImage -ImagePath $ImageFile -Index $Index -LogPath $DISMLog)
    If ($CheckBuild.Build -lt '15063') {
        Write-Output ''
        Write-Error "The image build [$($CheckBuild.Build.ToString())] is not supported." -ErrorAction Stop
    }
    Else {
        Write-Output ''
        Write-Output "The image build [$($CheckBuild.Build.ToString())] is supported."
        Start-Sleep 3
        Clear-Host
        $Error.Clear()
        Write-Log -Output "Mounting Image." -LogPath $LogFile -Level Info
        $MountWindowsImage = @{
            ImagePath        = $ImageFile
            Index            = $Index
            Path             = $MountFolder
            ScratchDirectory = $TempFolder
            LogPath          = $DISMLog
            ErrorAction      = "Stop"
        }
        [void](Mount-WindowsImage @MountWindowsImage)
        $ImageIsMounted = $true
    }
}
Catch {
    Remove-Item -Path $MountFolder -Recurse -Force
    Remove-Item -Path $ImageFolder -Recurse -Force
    Remove-Item -Path $WorkFolder -Recurse -Force
    Remove-Item -Path $TempFolder -Recurse -Force
    Remove-Item -Path $LogFile -Force
    Remove-Item -Path $DISMLog -Force
    Break
}

If ($ImageIsMounted.Equals($true)) {
    Write-Output ''
    Write-Log -Output "Verifying image health." -LogPath $LogFile -Level Info
    $StartHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth -LogPath $DISMLog
    If ($StartHealthCheck.ImageHealthState -eq "Healthy") {
        Write-Output ''
        Write-Output "The image is healthy."
        Start-Sleep 3
        Clear-Host
    }
    Else {
        Write-Output ''
        Write-Log -Output "The image has been flagged for corruption. Further servicing is required before the image can be optimized." -LogPath $LogFile -Level Error
        Exit-Script
        Break
    }
}

If ($WhiteListApps) {
    Get-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder -LogPath $DISMLog | ForEach {
        If ($_.DisplayName -notin $AppWhiteList) {
            Write-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
            [void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder -LogPath $DISMLog)
        }
    }
}

If ($SelectApps) {
    Get-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder -LogPath $DISMLog | ForEach {
        If ($SelectApps) {
            $AppSelect = Read-Host "Remove Provisioned App Package:" $_.DisplayName "(y/N)"
            If ($AppSelect.Equals("y")) {
                Write-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
                [void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder -LogPath $DISMLog)
                $AppSelect = ''
            }
            Else {
                Write-Host "Skipping Provisioned App Package: $($_.DisplayName)" -ForegroundColor Cyan
                $AppSelect = ''
            }
        }
    }
}

If ($AllApps) {
    Get-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder -LogPath $DISMLog | ForEach {
        Write-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -LogPath $LogFile -Level Info
        [void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $_.PackageName -ScratchDirectory $TempFolder -LogPath $DISMLog)
    }
}

If ($SetRegistry -or $Hardened) {
    #region Default Registry Optimizations
    If (Test-Path -Path $WorkFolder\Registry-Optimizations.log) {
        Remove-Item -Path $WorkFolder\Registry-Optimizations.log -Force
    }
    Clear-Host
    Write-Log -Output "Enhancing system security, usability and performance with registry optimizations." -LogPath $LogFile -Level Info
    [void](Mount-OfflineHives)
    #****************************************************************
    Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\InputPersonalization\TrainedDataStore"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings"
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
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Cortana Outgoing Network Traffic." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    $CortanaUriServer = @{
        Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name  = "Block Cortana ActionUriServer.exe"
        Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe|Name=Block Cortana ActionUriServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type  = "String"
    }
    Set-ItemProperty @CortanaUriServer
    $CortanaPlacesServer = @{
        Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name  = "Block Cortana PlacesServer.exe"
        Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe|Name=Block Cortana PlacesServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type  = "String"
    }
    Set-ItemProperty @CortanaPlacesServer
    $CortanaReminderServer = @{
        Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name  = "Block Cortana RemindersServer.exe"
        Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type  = "String"
    }
    Set-ItemProperty @CortanaReminderServer
    $CortanaReminderApp = @{
        Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name  = "Block Cortana RemindersShareTargetApp.exe"
        Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe|Name=Block Cortana RemindersShareTargetApp.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type  = "String"
    }
    Set-ItemProperty @CortanaReminderApp
    $CortanaSearchUI = @{
        Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name  = "Block Cortana SearchUI.exe"
        Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block Cortana SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type  = "String"
    }
    Set-ItemProperty @CortanaSearchUI
    $CortanaPackage = @{
        Path  = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name  = "Block Cortana Package"
        Value = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Cortana Package|Desc=Block Cortana Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|Platform=2:6:2|Platform2=GTEQ|"
        Type  = "String"
    }
    Set-ItemProperty @CortanaPackage
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling System Telemetry and Data Collecting." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation"
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
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Office 2016 Telemetry and Logging." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling 'Find My Device'." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Enabling PIN requirement for pairing devices." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling HomeGroup Services." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupListener" -Name "Start" -Value 4 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupProvider" -Name "Start" -Value 4 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Text Suggestions and Screen Monitoring." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Steps Recorder." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Compatibility Assistant." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Error Reporting." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WerSvc" -Name "Start" -Value 4 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling WiFi Sense." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Windows Asking for Feedback." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling the Password Reveal button." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Windows Media Player Statistics Tracking." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Microsoft Windows Media Digital Rights Management." >> $WorkFolder\Registry-Optimizations.log
    #***************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Enabling the MeltDown (CVE-2017-5754) Compatibility Flag." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "CADCA5FE-87D3-4B96-B7FB-A231484277CC" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Explorer Tips, Sync Notifications and Document Tracking." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
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
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling System Advertisements and Windows Spotlight." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
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
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Toast Notifications." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" `
        -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" `
        -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Feature Advertisement Notifications." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoBalloonFeatureAdvertisements" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling System Tray Promotion Notifications." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoSystraySystemPromotion" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Typing Data Telemetry." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Automatic Download of Content and Suggestions." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
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
    ) | % { Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_ -Value 0 -Type DWord }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Windows 'Getting to Know Me' and Keylogging" >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Notifications on Lock Screen." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" `
        -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" `
        -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Lock Screen Camera and Overlays." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Map Auto Downloads." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Speech Model Updates." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling First Log-on Animation." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling the Windows Insider Program." >> $WorkFolder\Registry-Optimizations.log
    #***************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Changing Search Bar to Magnifying Glass Icon." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Moving Drive Letter Before Drive Label." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Enabling Dark Theme for Settings and Modern Apps." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Increasing Taskbar and Theme Transparency." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling 'Shortcut' text for Shortcuts." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value 00000000 -Type Binary
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Enabling Explorer opens to This PC." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing Windows Store Icon from Taskbar." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing Windows Mail Icon from Taskbar." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling the Windows Mail Application." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord
    #****************************************************************
    If ($Build -ge '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Removing People Icon from Taskbar" >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type DWord
    }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling 'How do you want to open this file?' prompt." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Switching to Smaller Control Panel Icons." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Adding This PC Icon to Desktop." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    $NewStart = @{
        Path  = "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
        Name  = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
        Value = 0
        Type  = "DWord"
    }
    Set-ItemProperty @NewStart
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
    $ClassicStart = @{
        Path  = "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
        Name  = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
        Value = 0
        Type  = "DWord"
    }
    Set-ItemProperty @ClassicStart
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Adding 'Reboot to Recovery' to My PC." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-RegistryOwner -Hive HKLM -SubKey "WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery"
    $RecoveryIcon = @{
        Path  = "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery"
        Name  = "Icon"
        Value = "%SystemRoot%\System32\imageres.dll,-110"
        Type  = "ExpandString"
    }
    Set-ItemProperty @RecoveryIcon
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command"
    $RecoveryCommand = @{
        Path  = "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command"
        Name  = "(default)"
        Value = "shutdown.exe -r -o -f -t 00"
        Type  = "String"
    }
    Set-ItemProperty @RecoveryCommand
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Live Tiles." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" `
        -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Connected Drive Autoplay and Autorun." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord
    #****************************************************************
    If ($Build -ge '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        $P3D = @(
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
        ) | % { Remove-Item -Path $_ -Recurse -Force }
    }
    ElseIf ($Build -lt '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Removing 'Edit with Paint 3D' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        $P3D = @(
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
        ) | % { Remove-Item -Path $_ -Recurse -Force }
    }
    If ($Build -ge "15063") {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        $3DP = @(
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3ds\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dae\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dxf\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Print"
            "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.wrl\Shell\3D Print"
        ) | % { Remove-Item -Path $_ -Recurse -Force }
    }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Restoring Windows Photo Viewer." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    $Type = @(
        ".bmp"
        ".gif"
        ".jfif"
        ".jpeg"
        ".jpg"
        ".png"
        ".tif"
        ".tiff"
        ".wdp"
    ) | % {
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_";
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids";
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String;
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" `
            -Value (New-Object Byte[] 0) -Type Binary
    }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing 'Restore Previous Versions' from the Property Tab and Context Menu." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    $Restore = @(
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    ) | % { Remove-Item -Path $_ -Recurse -Force }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing 'Share' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" `
        -Value "" -Type String
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing 'Give Access To' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" `
        -Value "" -Type String
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing 'Cast To Device' from the Context Menu." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" `
        -Value "" -Type String
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Hiding Recently and Frequently Used Items in Explorer." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord
    #****************************************************************
    If ($Build -ge '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Hiding all User Folders from This PC." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
    }
    ElseIf ($Build -lt '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Hiding all User Folders from This PC." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" `
            -Name "ThisPCPolicy" -Value "Hide" -Type String
    }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Removing 3D Objects from This PC." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
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
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowCpl" -Value 1
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
    If ($Build -ge '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        If ($SystemAppsList -contains "SecHealthUI") {
            $ImmersiveLinks1 = @{
                Path  = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                Name  = "SettingsPageVisibility"
                Value = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsinsider;windowsdefender"
                Type  = "String"
            }
            Set-ItemProperty @ImmersiveLinks1
        }
        Else {
            $ImmersiveLinks2 = @{
                Path  = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                Name  = "SettingsPageVisibility"
                Value = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsinsider"
                Type  = "String"
            }
            Set-ItemProperty @ImmersiveLinks2
        }
    }
    ElseIf ($Build -lt '16273') {
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Cleaning up Immersive Control Panel Settings Links." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        If ($SystemAppsList -contains "SecHealthUI") {
            $ImmersiveLinks3 = @{
                Path  = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                Name  = "SettingsPageVisibility"
                Value = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsinsider;windowsdefender"
                Type  = "String"
            }
            Set-ItemProperty @ImmersiveLinks3
        }
        Else {
            $ImmersiveLinks4 = @{
                Path  = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                Name  = "SettingsPageVisibility"
                Value = "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsinsider"
                Type  = "String"
            }
            Set-ItemProperty @ImmersiveLinks4
        }
    }
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Recent Document History." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Automatic Sound Reduction." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Enabling Component Clean-up with Reset Base." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" -Name "DisableResetbase" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Enabling the removal of the 'DefaultUser0' ghost account." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-RegistryOwner -Hive HKLM -SubKey "WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}"
    $DefaultUser0 = @{
        Path  = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}"
        Name  = "AutoElevationAllowed"
        Value = 1
        Type  = "DWord"
    }
    Set-ItemProperty @DefaultUser0
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Sticky Keys." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys"
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response"
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value 122 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value 58 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Increasing Icon Cache Size." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 4096 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Hibernation." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Session Manager\Power" -Name "HibernteEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Value 0 -Type DWord
    #****************************************************************
    [void](Dismount-OfflineHives)
    $RegistryComplete = $true
    #endregion Default Registry Optimizations
}

If ($Hardened) {
    #region Hardened Registry Optimizations
    [void](Mount-OfflineHives)
    Write-Output ''
    Write-Log -Output "Adding Hardened Registry Values." -LogPath $LogFile -Level Info
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
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_";
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -Name "Enabled" -Value 0 -Type DWord
    }
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Value 5 -Type DWord
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync"
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
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Location Sensors, App Syncronization and Non-Explicit App Access." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    [void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f)
    [void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f)
    [void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v "Value" /t REG_SZ /d "Deny" /f)
    [void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Type" /t REG_SZ /d "LooselyCoupled" /f)
    [void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f)
    [void](REG ADD "HKLM\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "InitialAppValue" /t REG_SZ /d "Unspecified" /f)
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Value 2 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling System Tracking and Location Sensors." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" `
        -Name "SensorPermissionState" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" `
        -Name "SensorPermissionState" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc" -Name "Start" -Value 4 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Shared Experiences." >> $WorkFolder\Registry-Optimizations.log
    #***************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling SmartScreen." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord
    #****************************************************************
    Write-Output '' >> $WorkFolder\Registry-Optimizations.log
    Write-Output "Disabling Windows Auto-Update and Auto-Reboot." >> $WorkFolder\Registry-Optimizations.log
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Type DWord
    #****************************************************************
    [void](Dismount-OfflineHives)
    #endregion Default Hardened Registry Optimizations
}

If ($RegistryComplete.Equals($true)) {
    Write-Output ''
    Write-Log -Output "Editing the Start Menu Desktop.ini to remove any broken links." -LogPath $LogFile -Level Info
    $LnkINI = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini"
    $MathInput = "Math Input Panel.lnk=@%CommonProgramFiles%\Microsoft Shared\Ink\mip.exe,-291"
    $SnippingTool = "Snipping Tool.lnk=@%SystemRoot%\system32\SnippingTool.exe,-15051"
    $StepsRecorder = "Steps Recorder.lnk=@%SystemRoot%\system32\psr.exe,-1701"
    $FaxScan = "Windows Fax and Scan.lnk=@%SystemRoot%\system32\FXSRESM.dll,-114"
    $LnkContent = (Get-Content -Path $LnkINI)
    If ((Select-String -InputObject $LnkContent -Pattern $MathInput -SimpleMatch -Quiet) -eq $true -and `
        (Select-String -InputObject $LnkContent -Pattern $SnippingTool -SimpleMatch -Quiet) -eq $true -and `
        (Select-String -InputObject $LnkContent -Pattern $StepsRecorder -SimpleMatch -Quiet) -eq $true -and `
        (Select-String -InputObject $LnkContent -Pattern $FaxScan -SimpleMatch -Quiet) -eq $true) {
        ATTRIB -S -H $LnkINI
        $LnkContent.Where{ $_ -ne $MathInput -and $_ -ne $SnippingTool -and $_ -ne $StepsRecorder -and $_ -ne $FaxScan } | Set-Content -Path $LnkINI -Encoding Unicode -Force
        ATTRIB +S +H $LnkINI
        Remove-Item -Path "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Math Input Panel.lnk" -Force
        Remove-Item -Path "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk" -Force
        Remove-Item -Path "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Steps Recorder.lnk" -Force
        Remove-Item -Path "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows Fax and Scan.lnk" -Force
    }
    Start-Sleep 3
}

If ($SelectApps -or $AllApps -or $WhiteListApps -or $SetRegistry -or $Hardened) {
    Write-Output ''
    Write-Log -Output "Applying a custom Start Menu and Taskbar Layout." -LogPath $LogFile -Level Info
    $LayoutTemplate = @'
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
'@
    $LayoutModification = Join-Path -Path "$MountFolder\Users\Default\AppData\Local\Microsoft\Windows\Shell" -ChildPath "LayoutModification.xml"
    Set-Content -Path $LayoutModification -Value $LayoutTemplate -Encoding UTF8 -Force
    $CreateShortcuts = {
        # UWP Explorer App LayoutModification Link
        $UWPShell = New-Object -ComObject WScript.Shell
        $UWPShortcut = $UWPShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UWP File Explorer.lnk")
        $UWPShortcut.TargetPath = "%SystemRoot%\explorer.exe"
        $UWPShortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
        $UWPShortcut.IconLocation = "imageres.dll,-1023"
        $UWPShortcut.WorkingDirectory = "%SystemRoot%"
        $UWPShortcut.Description = "The UWP File Explorer Application."
        $UWPShortcut.Save()
        # Boot to Firmware LayoutModification Link
        $UEFIShell = New-Object -ComObject WScript.Shell
        $UEFIShortcut = $UEFIShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk")
        $UEFIShortcut.TargetPath = "%SystemRoot%\System32\shutdown.exe"
        $UEFIShortcut.Arguments = "/r /fw"
        $UEFIShortcut.IconLocation = "bootux.dll,-1016"
        $UEFIShortcut.WorkingDirectory = "%SystemRoot%\System32"
        $UEFIShortcut.Description = "Reboot directly into the system's UEFI firmware."
        $UEFIShortcut.Save()
        $Bytes = [System.IO.File]::ReadAllBytes("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk")
        $Bytes[0x15] = $Bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\UEFI Firmware.lnk", $Bytes)
    }
    Write-Output ''
    Write-Log -Output "Creating required Shortcuts." -LogPath $LogFile -Level Info
    & $CreateShortcuts
    Start-Sleep 3
}

If ($SystemAppsList.Count -gt 0) {
    Write-Output ''
    Write-Verbose "Removing System Applications." -Verbose
    [void](Mount-OfflineHives)
    $InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
    ForEach ($SystemApp in $SystemAppsList) {
        $InboxApps = (Get-ChildItem -Path $InboxAppsKey).Name.Split("\") | ? { $_ -like "*$SystemApp*" }
        ForEach ($InboxApp in $InboxApps) {
            Write-Output "$TimeStamp INFO: Removing System Application: $($InboxApp.Split("_")[0])" >> $LogFile
            $FullKeyPath = "$($InboxAppsKey)\" + $InboxApp
            $AppKey = $FullKeyPath.Replace("HKLM:", "HKLM")
            [void](REG DELETE $AppKey /F)
        }
    }
    [void](Dismount-OfflineHives)
}

Try {
    If ($SelectApps -or $AllApps -or $WhiteListApps) {
        Write-Output ''
        Write-Log -Output "Disabling removed Provisoned App Package services." -LogPath $LogFile -Level Info
        If ((Get-AppxProvisionedPackage -Path $MountFolder | ? { $_.DisplayName -Match "Microsoft.Wallet" }).Count.Equals(0)) {
            [void](Mount-OfflineHives)
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            [void](Dismount-OfflineHives)
        }
        If ((Get-AppxProvisionedPackage -Path $MountFolder | ? { $_.DisplayName -Match "Microsoft.WindowsMaps" }).Count.Equals(0)) {
            [void](Mount-OfflineHives)
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            [void](Dismount-OfflineHives)
        }
    }
}
Catch {
    Write-Output ''
    Write-Log -Output "An error occurred removing Provisoned App Package services." -LogPath $LogFile -Level Error
    Exit-Script
    Break
}

Try {
    If ($SystemAppsList -contains "SecHealthUI") {
        Write-Output ''
        Write-Log -Output "Disabling remaining Windows Defender services and drivers." -LogPath $LogFile -Level Info
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWord
        If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run") {
            [void](Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth")
        }
        $Services = @(
            "SecurityHealthService"
            "WinDefend"
            "WdNisSvc"
            "WdNisDrv"
            "WdBoot"
            "WdFilter"
            "Sense"
        ) | % { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop }
        $DisableDefenderComplete = $true
    }
}
Catch {
    Write-Output ''
    Write-Log -Output "An error occurred disabling remaining Windows Defender services and drivers." -LogPath $LogFile -Level Error
    Exit-Script
    Break
}
Finally {
    [void](Dismount-OfflineHives)
}

If ($DisableDefenderComplete.Equals($true) -and $Build -ge '16273') {
    Write-Output ''
    Write-Log -Output "Disabling Windows-Defender-Default-Defintions." -LogPath $LogFile -Level Info
    $DisableDefenderFeature = @{
        Path             = $MountFolder
        FeatureName      = "Windows-Defender-Default-Definitions"
        ScratchDirectory = $TempFolder
        LogPath          = $DISMLog
    }
    [void](Disable-WindowsOptionalFeature @DisableDefenderFeature)
}

Try {
    If ($SystemAppsList -contains "XboxGameCallableUI" -or ((Get-AppxProvisionedPackage -Path $MountFolder | ? { $_.PackageName -like "*Xbox*" }).Count -lt 5)) {
        Write-Output ''
        Write-Log -Output "Disabling remaining Xbox services and drivers." -LogPath $LogFile -Level Info
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar"
        New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord
        $Services = @(
            "xbgm"
            "XblAuthManager"
            "XblGameSave"
            "xboxgip"
            "XboxGipSvc"
            "XboxNetApiSvc"
        ) | % { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop }
        $DisableXboxComplete = $true
    }
}
Catch {
    Write-Output ''
    Write-Log -Output "An error occurred disabling remaining Xbox services and drivers." -LogPath $LogFile -Level Error
    Exit-Script
    Break
}
Finally {
    [void](Dismount-OfflineHives)
}

If ($FeatureDisableList.Count -gt 0) {
    Write-Output ''
    Write-Log -Output "Disabling Windows Optional Features." -LogPath $LogFile -Level Info
    $WindowsFeatures = Get-WindowsOptionalFeature -Path $MountFolder
    ForEach ($Feature in $FeatureDisableList) {
        $DisableFeature = @{
            Path             = $MountFolder
            ScratchDirectory = $TempFolder
            LogPath          = $DISMLog
        }
        [void]($WindowsFeatures.Where{ $_.FeatureName -like $Feature } | Disable-WindowsOptionalFeature @DisableFeature)
    }
}

If ($PackageRemovalList.Count -gt 0) {
    Write-Output ''
    Write-Log -Output "Removing Windows OnDemand Packages." -LogPath $LogFile -Level Info
    $WindowsPackages = Get-WindowsPackage -Path $MountFolder
    ForEach ($Package in $PackageRemovalList) {
        $RemovePackage = @{
            Path             = $MountFolder
            ScratchDirectory = $TempFolder
            LogPath          = $DISMLog
        }
        [void]($WindowsPackages.Where{ $_.PackageName -like $Package } | Remove-WindowsPackage @RemovePackage)
    }
}

If ($Drivers) {
    If ((Test-Path -Path $Drivers -PathType Container) -and (Get-ChildItem -Path $Drivers -Recurse -Filter "*.inf")) {
        Write-Output ''
        Write-Log -Output "Injecting driver packages into the image." -LogPath $LogFile -Level Info
        [void](Add-WindowsDriver -Path $MountFolder -Driver $Drivers -Recurse -ForceUnsigned -LogPath $DISMLog)
        Get-WindowsDriver -Path $MountFolder | Format-List | Out-File $WorkFolder\DriverPackageList.log -Force
    }
    ElseIf (Test-Path -Path $Drivers -PathType Leaf -Filter "*.inf") {
        Write-Output ''
        Write-Log -Output "Injecting driver package into the image." -LogPath $LogFile -Level Info
        [void](Add-WindowsDriver -Path $MountFolder -Driver $Drivers -ForceUnsigned -LogPath $DISMLog)
        Get-WindowsDriver -Path $MountFolder | Format-List | Out-File $WorkFolder\DriverPackageList.log -Force
    }
    Else {
        Write-Output ''
        Write-Log -Output "$Drivers is not a valid driver package path." -LogPath $LogFile -Level Warning
    }
}

Try {
    If (!$Hardened) {
        If ($RegistryComplete.Equals($true)) {
            $SetupComplete = @'
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


'@
            [void]($SB = [System.Text.StringBuilder]::New($SetupComplete))
            New-Container -Path "$MountFolder\Windows\Setup\Scripts"
            $SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
        }
        If ($DisableDefenderComplete.Equals($true) -and $DisableXboxComplete.Equals($true)) {
            $DefenderXbox = @'
:CONTINUE
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL  
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
DEL "%~f0"
'@
            [void]($SB.Append($DefenderXbox))
            Set-Content -Path $SetupCompleteScript -Value $SB.ToString() -Encoding ASCII
            $SetupScriptComplete = $true
        }
        ElseIf ($DisableDefenderComplete.Equals($true) -and $DisableXboxComplete -ne $true) {
            $Defender = @'
:CONTINUE
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL  
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
DEL "%~f0"
'@
            [void]($SB.Append($Defender))
            Set-Content -Path $SetupCompleteScript -Value $SB.ToString() -Encoding ASCII
            $SetupScriptComplete = $true
        }
        ElseIf ($DisableDefenderComplete -ne $true -and $DisableXboxComplete.Equals($true)) {
            $Xbox = @'
:CONTINUE
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL  
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
DEL "%~f0"
'@
            [void]($SB.Append($Xbox))
            Set-Content -Path $SetupCompleteScript -Value $SB.ToString() -Encoding ASCII
            $SetupScriptComplete = $true
        }
    }
    ElseIf ($Hardened) {
        $SetupComplete = @'
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


'@
        [void]($SB = [System.Text.StringBuilder]::New($SetupComplete))
        New-Container -Path "$MountFolder\Windows\Setup\Scripts"
        $SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
    }
    If ($DisableDefenderComplete.Equals($true) -and $DisableXboxComplete.Equals($true)) {
        $DefenderXbox = @'
:CONTINUE
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Diagnostics" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft Compatibility Appraiser" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "ProgramDataUpdater" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL  && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UpdateLibrary" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "WindowsActionDialog" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
DEL "%~f0"
'@
        [void]($SB.Append($DefenderXbox))
        Set-Content -Path $SetupCompleteScript -Value $SB.ToString() -Encoding ASCII
        $SetupScriptComplete = $true
    }
    ElseIf ($DisableDefenderComplete.Equals($true) -and $DisableXboxComplete -ne $true) {
        $Defender = @'
:CONTINUE
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Diagnostics" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft Compatibility Appraiser" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "ProgramDataUpdater" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL  && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UpdateLibrary" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "WindowsActionDialog" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
DEL "%~f0"
'@
        [void]($SB.Append($Defender))
        Set-Content -Path $SetupCompleteScript -Value $SB.ToString() -Encoding ASCII
        $SetupScriptComplete = $true
    }
    ElseIf ($DisableDefenderComplete -ne $true -and $DisableXboxComplete.Equals($true)) {
        $Xbox = @'
:CONTINUE
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Diagnostics" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefresh" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "File History (maintenance mode)" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft Compatibility Appraiser" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticResolver" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "ProgramDataUpdater" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL  && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UpdateLibrary" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "WindowsActionDialog" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL
DEL "%~f0"
'@
        [void]($SB.Append($Xbox))
        Set-Content -Path $SetupCompleteScript -Value $SB.ToString() -Encoding ASCII
        $SetupScriptComplete = $true
    }
}
Finally {
    If ($SetupScriptComplete.Equals($true)) {
        [void]($SB.Clear())
    }
}

Try {
    If ($AddFeatures.HostsFile -ne $true) {
        Write-Output ''
        Write-Log -Output "Blocking Microsoft spyware, Windows Update and telemetry domains." -LogPath $LogFile -Level Info
        Copy-Item -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -Destination "$MountFolder\Windows\System32\drivers\etc\hosts.bak" -Force
        Add-Content -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -Value "`r`n`n# Entries created by the Optimize-Offline PowerShell Script." -Encoding UTF8
        $Domains = @(
            "000202-1.l.windowsupdate.com"
            "0002c3-1.l.windowsupdate.com"
            "0002fd-1.l.windowsupdate.com"
            "00149f-1.l.windowsupdate.com"
            "001891-1.l.windowsupdate.com"
            "001f23-1.l.windowsupdate.com"
            "002062-1.l.windowsupdate.com"
            "0021d0-1.l.windowsupdate.com"
            "a-0001.a-msedge.net"
            "a-0001.dc-msedge.net"
            "a-0002.a-msedge.net"
            "a-0003.a-msedge.net"
            "a-0003.dc-msedge.net"
            "a-0004.a-msedge.net"
            "a-0005.a-msedge.net"
            "a-0006.a-msedge.net"
            "a-0007.a-msedge.net"
            "a-0008.a-msedge.net"
            "a-0009.a-msedge.net"
            "a-0010.a-msedge.net"
            "a-0011.a-msedge.net"
            "a-0012.a-msedge.net"
            "a-msedge.net"
            "a.ads1.msn.com"
            "a.ads2.msads.net"
            "a.ads2.msn.com"
            "a.rad.msn.com"
            "ac3.msn.com"
            "activity.windows.com"
            "adnexus.net"
            "adnxs.com"
            "ads.msn.com"
            "ads1.msads.net"
            "ads1.msn.com"
            "aidps.atdmt.com"
            "aka-cdn-ns.adtech.de"
            "answers.microsoft.com"
            "apps.skype.com"
            "array101-prod.do.dsp.mp.microsoft.com"
            "array102-prod.do.dsp.mp.microsoft.com"
            "array103-prod.do.dsp.mp.microsoft.com"
            "array104-prod.do.dsp.mp.microsoft.com"
            "array201-prod.do.dsp.mp.microsoft.com"
            "array202-prod.do.dsp.mp.microsoft.com"
            "array203-prod.do.dsp.mp.microsoft.com"
            "array204-prod.do.dsp.mp.microsoft.com"
            "array401-prod.do.dsp.mp.microsoft.com"
            "array402-prod.do.dsp.mp.microsoft.com"
            "array403-prod.do.dsp.mp.microsoft.com"
            "array404-prod.do.dsp.mp.microsoft.com"
            "array405-prod.do.dsp.mp.microsoft.com"
            "array406-prod.do.dsp.mp.microsoft.com"
            "array407-prod.do.dsp.mp.microsoft.com"
            "array408-prod.do.dsp.mp.microsoft.com"
            "ars.smartscreen.microsoft.com"
            "au.download.windowsupdate.com"
            "au.v4.download.windowsupdate.com"
            "az361816.vo.msecnd.net"
            "az512334.vo.msecnd.net"
            "b.ads1.msn.com"
            "b.ads2.msads.net"
            "b.rad.msn.com"
            "bingads.microsoft.com"
            "bl3301-a.1drv.com"
            "bl3301-c.1drv.com"
            "bl3301-g.1drv.com"
            "blob.weather.microsoft.com"
            "bn1304-e.1drv.com"
            "bn1306-a.1drv.com"
            "bn1306-e.1drv.com"
            "bn1306-g.1drv.com"
            "bn2b-cor001.api.p001.1drv.com"
            "bn2b-cor002.api.p001.1drv.com"
            "bn2b-cor003.api.p001.1drv.com"
            "bn2b-cor004.api.p001.1drv.com"
            "bn2wns1.wns.windows.com"
            "bn3p-cor001.api.p001.1drv.com"
            "bn3sch020010560.wns.windows.com"
            "bn3sch020010618.wns.windows.com"
            "bn3sch020010629.wns.windows.com"
            "bn3sch020010631.wns.windows.com"
            "bn3sch020010635.wns.windows.com"
            "bn3sch020010636.wns.windows.com"
            "bn3sch020010650.wns.windows.com"
            "bn3sch020011727.wns.windows.com"
            "bn3sch020012850.wns.windows.com"
            "bn3sch020020322.wns.windows.com"
            "bn3sch020020749.wns.windows.com"
            "bn3sch020022328.wns.windows.com"
            "bn3sch020022335.wns.windows.com"
            "bn3sch020022361.wns.windows.com"
            "bn4sch101120814.wns.windows.com"
            "bn4sch101120818.wns.windows.com"
            "bn4sch101120913.wns.windows.com"
            "bn4sch101121019.wns.windows.com"
            "bn4sch101121109.wns.windows.com"
            "bn4sch101121118.wns.windows.com"
            "bn4sch101121223.wns.windows.com"
            "bn4sch101121407.wns.windows.com"
            "bn4sch101121618.wns.windows.com"
            "bn4sch101121704.wns.windows.com"
            "bn4sch101121709.wns.windows.com"
            "bn4sch101121714.wns.windows.com"
            "bn4sch101121908.wns.windows.com"
            "bn4sch101122117.wns.windows.com"
            "bn4sch101122310.wns.windows.com"
            "bn4sch101122312.wns.windows.com"
            "bn4sch101122421.wns.windows.com"
            "bn4sch101123108.wns.windows.com"
            "bn4sch101123110.wns.windows.com"
            "bn4sch101123202.wns.windows.com"
            "bn4sch102110124.wns.windows.com"
            "bs.serving-sys.com"
            "by3301-a.1drv.com"
            "by3301-c.1drv.com"
            "by3301-e.1drv.com"
            "c-0001.dc-msedge.net"
            "c.atdmt.com"
            "c.msn.com"
            "ca.telemetry.microsoft.com"
            "cache.datamart.windows.com"
            "candycrushsoda.king.com"
            "cdn.atdmt.com"
            "cdn.content.prod.cms.msn.com"
            "cdn.onenote.net"
            "cds1204.lon.llnw.net"
            "cds1289.lon.llnw.net"
            "cds1293.lon.llnw.net"
            "cds1327.lon.llnw.net"
            "cds20417.lcy.llnw.net"
            "cds20431.lcy.llnw.net"
            "cds20450.lcy.llnw.net"
            "cds20457.lcy.llnw.net"
            "cds20475.lcy.llnw.net"
            "cds21244.lon.llnw.net"
            "cds26.ams9.msecn.net"
            "cds299.lcy.llnw.net"
            "cds405.lcy.llnw.net"
            "cds425.lcy.llnw.net"
            "cds459.lcy.llnw.net"
            "cds494.lcy.llnw.net"
            "cds965.lon.llnw.net"
            "ch1-cor001.api.p001.1drv.com"
            "ch1-cor002.api.p001.1drv.com"
            "ch3301-c.1drv.com"
            "ch3301-e.1drv.com"
            "ch3301-g.1drv.com"
            "ch3302-c.1drv.com"
            "ch3302-e.1drv.com"
            "choice.microsoft.com"
            "choice.microsoft.com.nsatc.net"
            "client-s.gateway.messenger.live.com"
            "client.wns.windows.com"
            "clientconfig.passport.net"
            "compatexchange.cloudapp.net"
            "compatexchange1.trafficmanager.net"
            "continuum.dds.microsoft.com"
            "corp.sts.microsoft.com"
            "corpext.msitadfs.glbdns2.microsoft.com"
            "cp101-prod.do.dsp.mp.microsoft.com"
            "cp201-prod.do.dsp.mp.microsoft.com"
            "cp401-prod.do.dsp.mp.microsoft.com"
            "cs1.wpc.v0cdn.net"
            "ctldl.windowsupdate.com"
            "db3aqu.atdmt.com"
            "db3wns2011111.wns.windows.com"
            "db5.wns.windows.com"
            "db5sch101100122.wns.windows.com"
            "db5sch101100127.wns.windows.com"
            "db5sch101100831.wns.windows.com"
            "db5sch101100835.wns.windows.com"
            "db5sch101100917.wns.windows.com"
            "db5sch101100925.wns.windows.com"
            "db5sch101100928.wns.windows.com"
            "db5sch101100938.wns.windows.com"
            "db5sch101101001.wns.windows.com"
            "db5sch101101022.wns.windows.com"
            "db5sch101101024.wns.windows.com"
            "db5sch101101031.wns.windows.com"
            "db5sch101101034.wns.windows.com"
            "db5sch101101042.wns.windows.com"
            "db5sch101101044.wns.windows.com"
            "db5sch101101122.wns.windows.com"
            "db5sch101101123.wns.windows.com"
            "db5sch101101125.wns.windows.com"
            "db5sch101101128.wns.windows.com"
            "db5sch101101129.wns.windows.com"
            "db5sch101101133.wns.windows.com"
            "db5sch101101145.wns.windows.com"
            "db5sch101101209.wns.windows.com"
            "db5sch101101221.wns.windows.com"
            "db5sch101101228.wns.windows.com"
            "db5sch101101231.wns.windows.com"
            "db5sch101101237.wns.windows.com"
            "db5sch101101317.wns.windows.com"
            "db5sch101101324.wns.windows.com"
            "db5sch101101329.wns.windows.com"
            "db5sch101101333.wns.windows.com"
            "db5sch101101334.wns.windows.com"
            "db5sch101101338.wns.windows.com"
            "db5sch101101419.wns.windows.com"
            "db5sch101101424.wns.windows.com"
            "db5sch101101426.wns.windows.com"
            "db5sch101101427.wns.windows.com"
            "db5sch101101430.wns.windows.com"
            "db5sch101101445.wns.windows.com"
            "db5sch101101511.wns.windows.com"
            "db5sch101101519.wns.windows.com"
            "db5sch101101529.wns.windows.com"
            "db5sch101101535.wns.windows.com"
            "db5sch101101541.wns.windows.com"
            "db5sch101101543.wns.windows.com"
            "db5sch101101608.wns.windows.com"
            "db5sch101101618.wns.windows.com"
            "db5sch101101629.wns.windows.com"
            "db5sch101101631.wns.windows.com"
            "db5sch101101633.wns.windows.com"
            "db5sch101101640.wns.windows.com"
            "db5sch101101711.wns.windows.com"
            "db5sch101101722.wns.windows.com"
            "db5sch101101739.wns.windows.com"
            "db5sch101101745.wns.windows.com"
            "db5sch101101813.wns.windows.com"
            "db5sch101101820.wns.windows.com"
            "db5sch101101826.wns.windows.com"
            "db5sch101101828.wns.windows.com"
            "db5sch101101835.wns.windows.com"
            "db5sch101101837.wns.windows.com"
            "db5sch101101844.wns.windows.com"
            "db5sch101101902.wns.windows.com"
            "db5sch101101907.wns.windows.com"
            "db5sch101101914.wns.windows.com"
            "db5sch101101929.wns.windows.com"
            "db5sch101101939.wns.windows.com"
            "db5sch101101941.wns.windows.com"
            "db5sch101102015.wns.windows.com"
            "db5sch101102017.wns.windows.com"
            "db5sch101102019.wns.windows.com"
            "db5sch101102023.wns.windows.com"
            "db5sch101102025.wns.windows.com"
            "db5sch101102032.wns.windows.com"
            "db5sch101102033.wns.windows.com"
            "db5sch101110108.wns.windows.com"
            "db5sch101110109.wns.windows.com"
            "db5sch101110114.wns.windows.com"
            "db5sch101110135.wns.windows.com"
            "db5sch101110142.wns.windows.com"
            "db5sch101110204.wns.windows.com"
            "db5sch101110206.wns.windows.com"
            "db5sch101110214.wns.windows.com"
            "db5sch101110225.wns.windows.com"
            "db5sch101110232.wns.windows.com"
            "db5sch101110245.wns.windows.com"
            "db5sch101110315.wns.windows.com"
            "db5sch101110323.wns.windows.com"
            "db5sch101110325.wns.windows.com"
            "db5sch101110328.wns.windows.com"
            "db5sch101110331.wns.windows.com"
            "db5sch101110341.wns.windows.com"
            "db5sch101110343.wns.windows.com"
            "db5sch101110345.wns.windows.com"
            "db5sch101110403.wns.windows.com"
            "db5sch101110419.wns.windows.com"
            "db5sch101110428.wns.windows.com"
            "db5sch101110435.wns.windows.com"
            "db5sch101110438.wns.windows.com"
            "db5sch101110442.wns.windows.com"
            "db5sch101110501.wns.windows.com"
            "db5sch101110527.wns.windows.com"
            "db5sch101110533.wns.windows.com"
            "db5sch101110618.wns.windows.com"
            "db5sch101110621.wns.windows.com"
            "db5sch101110622.wns.windows.com"
            "db5sch101110624.wns.windows.com"
            "db5sch101110626.wns.windows.com"
            "db5sch101110634.wns.windows.com"
            "db5sch101110705.wns.windows.com"
            "db5sch101110713.wns.windows.com"
            "db5sch101110724.wns.windows.com"
            "db5sch101110740.wns.windows.com"
            "db5sch101110810.wns.windows.com"
            "db5sch101110816.wns.windows.com"
            "db5sch101110821.wns.windows.com"
            "db5sch101110822.wns.windows.com"
            "db5sch101110825.wns.windows.com"
            "db5sch101110828.wns.windows.com"
            "db5sch101110829.wns.windows.com"
            "db5sch101110831.wns.windows.com"
            "db5sch101110835.wns.windows.com"
            "db5sch101110919.wns.windows.com"
            "db5sch101110921.wns.windows.com"
            "db5sch101110923.wns.windows.com"
            "db5sch101110929.wns.windows.com"
            "db5sch103081814.wns.windows.com"
            "db5sch103081913.wns.windows.com"
            "db5sch103082011.wns.windows.com"
            "db5sch103082111.wns.windows.com"
            "db5sch103082308.wns.windows.com"
            "db5sch103082406.wns.windows.com"
            "db5sch103082409.wns.windows.com"
            "db5sch103082609.wns.windows.com"
            "db5sch103082611.wns.windows.com"
            "db5sch103082709.wns.windows.com"
            "db5sch103082712.wns.windows.com"
            "db5sch103082806.wns.windows.com"
            "db5sch103090115.wns.windows.com"
            "db5sch103090414.wns.windows.com"
            "db5sch103090415.wns.windows.com"
            "db5sch103090513.wns.windows.com"
            "db5sch103090515.wns.windows.com"
            "db5sch103090608.wns.windows.com"
            "db5sch103090806.wns.windows.com"
            "db5sch103090814.wns.windows.com"
            "db5sch103090906.wns.windows.com"
            "db5sch103091011.wns.windows.com"
            "db5sch103091012.wns.windows.com"
            "db5sch103091106.wns.windows.com"
            "db5sch103091108.wns.windows.com"
            "db5sch103091212.wns.windows.com"
            "db5sch103091311.wns.windows.com"
            "db5sch103091414.wns.windows.com"
            "db5sch103091511.wns.windows.com"
            "db5sch103091609.wns.windows.com"
            "db5sch103091617.wns.windows.com"
            "db5sch103091715.wns.windows.com"
            "db5sch103091817.wns.windows.com"
            "db5sch103091908.wns.windows.com"
            "db5sch103091911.wns.windows.com"
            "db5sch103092010.wns.windows.com"
            "db5sch103092108.wns.windows.com"
            "db5sch103092109.wns.windows.com"
            "db5sch103092209.wns.windows.com"
            "db5sch103092210.wns.windows.com"
            "db5sch103092509.wns.windows.com"
            "db5sch103100117.wns.windows.com"
            "db5sch103100121.wns.windows.com"
            "db5sch103100221.wns.windows.com"
            "db5sch103100313.wns.windows.com"
            "db5sch103100314.wns.windows.com"
            "db5sch103100412.wns.windows.com"
            "db5sch103100510.wns.windows.com"
            "db5sch103100511.wns.windows.com"
            "db5sch103100611.wns.windows.com"
            "db5sch103100712.wns.windows.com"
            "db5sch103101105.wns.windows.com"
            "db5sch103101208.wns.windows.com"
            "db5sch103101212.wns.windows.com"
            "db5sch103101314.wns.windows.com"
            "db5sch103101411.wns.windows.com"
            "db5sch103101413.wns.windows.com"
            "db5sch103101513.wns.windows.com"
            "db5sch103101610.wns.windows.com"
            "db5sch103101611.wns.windows.com"
            "db5sch103101705.wns.windows.com"
            "db5sch103101711.wns.windows.com"
            "db5sch103101909.wns.windows.com"
            "db5sch103101914.wns.windows.com"
            "db5sch103102009.wns.windows.com"
            "db5sch103102112.wns.windows.com"
            "db5sch103102203.wns.windows.com"
            "db5sch103102209.wns.windows.com"
            "db5sch103102310.wns.windows.com"
            "db5sch103102404.wns.windows.com"
            "db5sch103102410.wns.windows.com"
            "db5sch103102609.wns.windows.com"
            "db5sch103102610.wns.windows.com"
            "db5sch103102711.wns.windows.com"
            "db5sch103102805.wns.windows.com"
            "db5wns1d.wns.windows.com"
            "db6sch102090104.wns.windows.com"
            "db6sch102090109.wns.windows.com"
            "db6sch102090112.wns.windows.com"
            "db6sch102090116.wns.windows.com"
            "db6sch102090122.wns.windows.com"
            "db6sch102090203.wns.windows.com"
            "db6sch102090206.wns.windows.com"
            "db6sch102090208.wns.windows.com"
            "db6sch102090209.wns.windows.com"
            "db6sch102090211.wns.windows.com"
            "db6sch102090212.wns.windows.com"
            "db6sch102090305.wns.windows.com"
            "db6sch102090306.wns.windows.com"
            "db6sch102090308.wns.windows.com"
            "db6sch102090311.wns.windows.com"
            "db6sch102090313.wns.windows.com"
            "db6sch102090410.wns.windows.com"
            "db6sch102090412.wns.windows.com"
            "db6sch102090504.wns.windows.com"
            "db6sch102090510.wns.windows.com"
            "db6sch102090512.wns.windows.com"
            "db6sch102090513.wns.windows.com"
            "db6sch102090514.wns.windows.com"
            "db6sch102090519.wns.windows.com"
            "db6sch102090613.wns.windows.com"
            "db6sch102090619.wns.windows.com"
            "db6sch102090810.wns.windows.com"
            "db6sch102090811.wns.windows.com"
            "db6sch102090902.wns.windows.com"
            "db6sch102090905.wns.windows.com"
            "db6sch102090907.wns.windows.com"
            "db6sch102090908.wns.windows.com"
            "db6sch102090910.wns.windows.com"
            "db6sch102090911.wns.windows.com"
            "db6sch102091003.wns.windows.com"
            "db6sch102091007.wns.windows.com"
            "db6sch102091008.wns.windows.com"
            "db6sch102091009.wns.windows.com"
            "db6sch102091011.wns.windows.com"
            "db6sch102091103.wns.windows.com"
            "db6sch102091105.wns.windows.com"
            "db6sch102091204.wns.windows.com"
            "db6sch102091209.wns.windows.com"
            "db6sch102091305.wns.windows.com"
            "db6sch102091307.wns.windows.com"
            "db6sch102091308.wns.windows.com"
            "db6sch102091309.wns.windows.com"
            "db6sch102091314.wns.windows.com"
            "db6sch102091412.wns.windows.com"
            "db6sch102091503.wns.windows.com"
            "db6sch102091507.wns.windows.com"
            "db6sch102091508.wns.windows.com"
            "db6sch102091602.wns.windows.com"
            "db6sch102091603.wns.windows.com"
            "db6sch102091606.wns.windows.com"
            "db6sch102091607.wns.windows.com"
            "deploy.static.akamaitechnologies.com"
            "dev.virtualearth.net"
            "device.auth.xboxlive.com"
            "df.telemetry.microsoft.com"
            "diagnostics.support.microsoft.com"
            "disc101-prod.do.dsp.mp.microsoft.com"
            "disc201-prod.do.dsp.mp.microsoft.com"
            "disc401-prod.do.dsp.mp.microsoft.com"
            "displaycatalog.mp.microsoft.com"
            "dl.delivery.mp.microsoft.com"
            "dmd.metaservices.microsoft.com"
            "dns.msftncsi.com"
            "download.microsoft.com"
            "download.windowsupdate.com"
            "ec.atdmt.com"
            "ecn.dev.virtualearth.net"
            "emdl.ws.microsoft.com"
            "eu.vortex.data.microsoft.com"
            "fe2.update.microsoft.com"
            "fe2.update.microsoft.com.akadns.net"
            "fe3.delivery.dsp.mp.microsoft.com.nsatc.net"
            "fe3.delivery.mp.microsoft.com"
            "feedback.microsoft-hohm.com"
            "feedback.search.microsoft.com"
            "feedback.windows.com"
            "fg.ds.b1.download.windowsupdate.com"
            "fg.v4.download.windowsupdate.com"
            "flex.msn.com"
            "fs.microsoft.com"
            "g.live.com"
            "g.msn.com"
            "geo-prod.do.dsp.mp.microsoft.com"
            "geover-prod.do.dsp.mp.microsoft.com"
            "h1.msn.com"
            "h2.msn.com"
            "hk2.wns.windows.com"
            "hk2sch130020721.wns.windows.com"
            "hk2sch130020723.wns.windows.com"
            "hk2sch130020726.wns.windows.com"
            "hk2sch130020729.wns.windows.com"
            "hk2sch130020732.wns.windows.com"
            "hk2sch130020824.wns.windows.com"
            "hk2sch130020843.wns.windows.com"
            "hk2sch130020851.wns.windows.com"
            "hk2sch130020854.wns.windows.com"
            "hk2sch130020855.wns.windows.com"
            "hk2sch130020924.wns.windows.com"
            "hk2sch130020936.wns.windows.com"
            "hk2sch130020940.wns.windows.com"
            "hk2sch130020956.wns.windows.com"
            "hk2sch130020958.wns.windows.com"
            "hk2sch130020961.wns.windows.com"
            "hk2sch130021017.wns.windows.com"
            "hk2sch130021029.wns.windows.com"
            "hk2sch130021035.wns.windows.com"
            "hk2sch130021137.wns.windows.com"
            "hk2sch130021142.wns.windows.com"
            "hk2sch130021153.wns.windows.com"
            "hk2sch130021217.wns.windows.com"
            "hk2sch130021246.wns.windows.com"
            "hk2sch130021249.wns.windows.com"
            "hk2sch130021260.wns.windows.com"
            "hk2sch130021264.wns.windows.com"
            "hk2sch130021322.wns.windows.com"
            "hk2sch130021323.wns.windows.com"
            "hk2sch130021329.wns.windows.com"
            "hk2sch130021334.wns.windows.com"
            "hk2sch130021360.wns.windows.com"
            "hk2sch130021432.wns.windows.com"
            "hk2sch130021433.wns.windows.com"
            "hk2sch130021435.wns.windows.com"
            "hk2sch130021437.wns.windows.com"
            "hk2sch130021440.wns.windows.com"
            "hk2sch130021450.wns.windows.com"
            "hk2sch130021518.wns.windows.com"
            "hk2sch130021523.wns.windows.com"
            "hk2sch130021526.wns.windows.com"
            "hk2sch130021527.wns.windows.com"
            "hk2sch130021544.wns.windows.com"
            "hk2sch130021554.wns.windows.com"
            "hk2sch130021618.wns.windows.com"
            "hk2sch130021634.wns.windows.com"
            "hk2sch130021638.wns.windows.com"
            "hk2sch130021646.wns.windows.com"
            "hk2sch130021652.wns.windows.com"
            "hk2sch130021654.wns.windows.com"
            "hk2sch130021657.wns.windows.com"
            "hk2sch130021723.wns.windows.com"
            "hk2sch130021726.wns.windows.com"
            "hk2sch130021727.wns.windows.com"
            "hk2sch130021730.wns.windows.com"
            "hk2sch130021731.wns.windows.com"
            "hk2sch130021754.wns.windows.com"
            "hk2sch130021829.wns.windows.com"
            "hk2sch130021830.wns.windows.com"
            "hk2sch130021833.wns.windows.com"
            "hk2sch130021840.wns.windows.com"
            "hk2sch130021842.wns.windows.com"
            "hk2sch130021851.wns.windows.com"
            "hk2sch130021852.wns.windows.com"
            "hk2sch130021927.wns.windows.com"
            "hk2sch130021928.wns.windows.com"
            "hk2sch130021929.wns.windows.com"
            "hk2sch130021958.wns.windows.com"
            "hk2sch130022035.wns.windows.com"
            "hk2sch130022041.wns.windows.com"
            "hk2sch130022049.wns.windows.com"
            "hk2sch130022135.wns.windows.com"
            "hk2wns1.wns.windows.com"
            "hk2wns1b.wns.windows.com"
            "i-bl6p-cor001.api.p001.1drv.com"
            "i-by3p-cor001.api.p001.1drv.com"
            "i-by3p-cor002.api.p001.1drv.com"
            "i-ch1-cor001.api.p001.1drv.com"
            "i-ch1-cor002.api.p001.1drv.com"
            "i-sn2-cor001.api.p001.1drv.com"
            "i-sn2-cor002.api.p001.1drv.com"
            "i1.services.social.microsoft.com"
            "i1.services.social.microsoft.com.nsatc.net"
            "iecvlist.microsoft.com"
            "img-s-msn-com.akamaized.net"
            "inference.location.live.net"
            "insiderppe.cloudapp.net"
            "insiderservice.microsoft.com"
            "kv101-prod.do.dsp.mp.microsoft.com"
            "kv201-prod.do.dsp.mp.microsoft.com"
            "kv401-prod.do.dsp.mp.microsoft.com"
            "lb1.www.ms.akadns.net"
            "licensing.mp.microsoft.com"
            "live.rads.msn.com"
            "login.live.com"
            "ls2web.redmond.corp.microsoft.com"
            "m.adnxs.com"
            "m.hotmail.com"
            "mediaredirect.microsoft.com"
            "microsoftwindowsupdate.net"
            "mobile.pipe.aria.microsoft.com"
            "msedge.net"
            "msftncsi.com"
            "msntest.serving-sys.com"
            "nexus.officeapps.live.com"
            "nexusrules.officeapps.live.com"
            "oca.telemetry.microsoft.com"
            "oca.telemetry.microsoft.com.nsatc.net"
            "officeclient.microsoft.com"
            "oneclient.sfx.ms"
            "onesettings-bn2.metron.live.com.nsatc.net"
            "onesettings-cy2.metron.live.com.nsatc.net"
            "onesettings-db5.metron.live.com.nsatc.net"
            "onesettings-hk2.metron.live.com.nsatc.net"
            "pre.footprintpredict.com"
            "preview.msn.com"
            "pricelist.skype.com"
            "pti.store.microsoft.com"
            "query.prod.cms.rt.microsoft.com"
            "rad.live.com"
            "rad.msn.com"
            "redir.metaservices.microsoft.com"
            "register.cdpcs.microsoft.com"
            "reports.wes.df.telemetry.microsoft.com"
            "s.gateway.messenger.live.com"
            "s0.2mdn.net"
            "sO.2mdn.net"
            "schemas.microsoft.akadns.net"
            "search.msn.com"
            "secure.adnxs.com"
            "secure.flashtalking.com"
            "services.wes.df.telemetry.microsoft.com"
            "settings-sandbox.data.microsoft.com"
            "settings-ssl.xboxlive.com"
            "settings-win-ppe.data.microsoft.com"
            "settings-win.data.microsoft.com"
            "settings.data.glbdns2.microsoft.com"
            "settings.data.microsoft.com"
            "sls.update.microsoft.com"
            "sls.update.microsoft.com.akadns.net"
            "sn3301-c.1drv.com"
            "sn3301-e.1drv.com"
            "sn3301-g.1drv.com"
            "spynet2.microsoft.com"
            "spynetalt.microsoft.com"
            "spyneteurope.microsoft.akadns.net"
            "sqm.df.telemetry.microsoft.com"
            "sqm.telemetry.microsoft.com"
            "sqm.telemetry.microsoft.com.nsatc.net"
            "ssw.live.com"
            "static.2mdn.net"
            "statsfe1.ws.microsoft.com"
            "statsfe2.update.microsoft.com.akadns.net"
            "statsfe2.ws.microsoft.com"
            "storage.live.com"
            "store-images.s-microsoft.com"
            "storecatalogrevocation.storequality.microsoft.com"
            "storeedgefd.dsx.mp.microsoft.com"
            "support.microsoft.com"
            "survey.watson.microsoft.com"
            "t0.ssl.ak.dynamic.tiles.virtualearth.net"
            "t0.ssl.ak.tiles.virtualearth.net"
            "telecommand.telemetry.microsoft.com"
            "telecommand.telemetry.microsoft.com.nsatc.net"
            "telemetry.appex.bing.net"
            "telemetry.microsoft.com"
            "telemetry.urs.microsoft.com"
            "test.activity.windows.com"
            "tile-service.weather.microsoft.com"
            "time.windows.com"
            "tk2.plt.msn.com"
            "tlu.dl.delivery.mp.microsoft.com"
            "tsfe.trafficshaping.dsp.mp.microsoft.com"
            "ui.skype.com"
            "urs.smartscreen.microsoft.com"
            "v10.vortex-win.data.metron.live.com.nsatc.net"
            "v10.vortex-win.data.microsoft.com"
            "v4.download.windowsupdate.com"
            "version.hybrid.api.here.com"
            "view.atdmt.com"
            "vortex-bn2.metron.live.com.nsatc.net"
            "vortex-cy2.metron.live.com.nsatc.net"
            "vortex-db5.metron.live.com.nsatc.net"
            "vortex-hk2.metron.live.com.nsatc.net"
            "vortex-sandbox.data.microsoft.com"
            "vortex-win.data.metron.live.com.nsatc.net"
            "vortex-win.data.microsoft.com"
            "vortex.data.glbdns2.microsoft.com"
            "vortex.data.metron.live.com.nsatc.net"
            "vortex.data.microsoft.com"
            "watson.live.com"
            "watson.microsoft.com"
            "watson.ppe.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com.nsatc.net"
            "wdcp.microsoft.com"
            "wdcpalt.microsoft.com"
            "web.vortex.data.microsoft.com"
            "wes.df.telemetry.microsoft.com"
            "win10-trt.msedge.net"
            "win10.ipv6.microsoft.com"
            "win1710.ipv6.microsoft.com"
            "windowsupdate.com"
            "windowupdate.org"
            "wscont.apps.microsoft.com"
            "www.msedge.net"
            "www.msftconnecttest.com"
            "www.msftncsi.com"
        ) | % { Add-Content -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -Value $_.Replace($_, "0.0.0.0 $($_)") -Encoding UTF8 }
    }
}
Finally {
    Start-Sleep 3
}

If ($AdditionalFeatures) {
    Clear-Host
    Write-Log -Output "Calling the Additional-Features function script." -LogPath $LogFile -Level Info
    Start-Sleep 3
    Additional-Features @AddFeatures
}

Try {
    Clear-Host
    Write-Log -Output "Verifying the image health before finalizing." -LogPath $LogFile -Level Info
    $EndHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth
    If ($EndHealthCheck.ImageHealthState -eq "Healthy") {
        Write-Output ''
        Write-Output "The image is healthy."
        Start-Sleep 3
    }
    Else {
        Write-Output ''
        Write-Warning "The image has been flagged for corruption. Further servicing is recommended."
        Start-Sleep 3
    }
}
Catch {
    Write-Output ''
    Write-Log -Output "Failed to verify the image health." -LogPath $LogFile -Level Error
    Exit-Script
    Break
}
Finally {
    If (Test-OfflineHives) {
        [void](Dismount-OfflineHives)
    }
}

Try {
    Write-Output ''
    Write-Log -Output "Saving Image and Dismounting." -LogPath $LogFile -Level Info
    $DismountWindowsImage = @{
        Path             = $MountFolder
        Save             = $true
        CheckIntegrity   = $true
        ScratchDirectory = $TempFolder
        LogPath          = $DISMLog
        ErrorAction      = "Stop"
    }
    [void](Dismount-WindowsImage @DismountWindowsImage)
}
Catch {
    Write-Output ''
    Write-Log -Output "An error occured trying to save and dismount the Windows Image." -LogPath $LogFile -Level Error
    Exit-Script
    Break
}

Try {
    Write-Output ''
    Write-Log -Output "Rebuilding and compressing the new image." -LogPath $LogFile -Level Info
    $ExportImage = @{
        CheckIntegrity       = $true
        CompressionType      = "Maximum"
        SourceImagePath      = $ImageFile
        SourceIndex          = $Index
        DestinationImagePath = "$WorkFolder\install.wim"
        ScratchDirectory     = $TempFolder
        LogPath              = $DISMLog
        ErrorAction          = "Stop"
    }
    [void](Export-WindowsImage @ExportImage)
}
Catch {
    Write-Output ''
    Write-Log -Output "An error occured trying to rebuild and compress the the new image." -LogPath $LogFile -Level Error
    Exit-Script
    Break
}

Try {
    Write-Output ''
    Write-Log -Output "Finalizing Script." -LogPath $LogFile -Level Info
    [void]($SaveFolder = New-SaveDirectory)
    Move-Item -Path $WorkFolder\*.txt -Destination $SaveFolder -Force
    Move-Item -Path $WorkFolder\*.log -Destination $SaveFolder -Force
    Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force
    Move-Item -Path $DISMLog -Destination $SaveFolder -Force
    Start-Sleep 3
}
Catch {
    Write-Output ''
    Write-Log -Output "Failed to locate all required files in $env:TEMP." -LogPath $LogFile -Level Error
}
Finally {
    Remove-Item -Path $TempFolder -Recurse -Force
    Remove-Item -Path $ImageFolder -Recurse -Force
    Remove-Item -Path $MountFolder -Recurse -Force
    Remove-Item -Path $WorkFolder -Recurse -Force
    [void](Clear-WindowsCorruptMountPoint)
}

If ($Error.Count.Equals(0)) {
    Write-Output ''
    Write-Output "Newly optimized image has been saved to $SaveFolder."
    Write-Output ''
    Write-Log -Output "$Script completed with [0] errors." -LogPath $LogFile -Level Info
    Move-Item -Path $LogFile -Destination $SaveFolder -Force
    Write-Output ''
    Start-Sleep 3
}
Else {
    $SaveErrorLog = Join-Path -Path $env:TEMP -ChildPath "ErrorLog.log"
    Set-Content -Path $SaveErrorLog -Value $Error.ToArray() -Force
    Move-Item -Path $env:TEMP\ErrorLog.log -Destination $SaveFolder -Force
    Write-Output ''
    Write-Output "Newly optimized image has been saved to $SaveFolder."
    Write-Output ''
    Write-Log -Output "$Script completed with [$($Error.Count)] errors." -LogPath $LogFile -Level Warning
    Move-Item -Path $LogFile -Destination $SaveFolder -Force
    Write-Output ''
    Start-Sleep 3
}
# SIG # Begin signature block
# MIIJLQYJKoZIhvcNAQcCoIIJHjCCCRoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUr5R3ZnBu9P06z53ZOO8tGkLq
# n5egggYxMIIDFDCCAgCgAwIBAgIQgnJLApNodKpGiwFxYC7KeTAJBgUrDgMCHQUA
# MBgxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0EwHhcNMTgwMzEzMTAxNDI3WhcNMzkx
# MjMxMjM1OTU5WjAYMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3DlhtznwS9RYFDwLLneugmUEZecwxytmEZU+
# eXPfC3e7k85aYAhN9UEEhm/VsJB/NAFc5+khXqLVEWcuuD0xnnJholKRft3uP9ng
# L/ebtVbuZR/nz8rSL6X3XrM9htU4sH2a6dzS4ESFbu6z3Xlg3sjrw7QN89XEcFEw
# vKp5okD2sHaqP1AS/yJVNWLovBWY+W/RAWeVvLTjjSflcXNpbp2MgkrOHC65eB6w
# PhgeATjP2/wprl6e2p7sVkRI9hQw6eQdDeWcYuTIY/9u/2uBVnjISnhrh3V58SpI
# n3jV0apM8+H/YfuhEML2l7zc6xQ0358QoWIi9srkqH8sBFkrkQIDAQABo2IwYDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzBJBgNVHQEEQjBAgBB2Tn/VDn5XbZD6/biSSil9
# oRowGDEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQYIQgnJLApNodKpGiwFxYC7KeTAJ
# BgUrDgMCHQUAA4IBAQDJ+S0c+mO4p+DsBF/kZYNqWcgJ3mD1keYX7O7aSEdG1pCX
# +o9l4cj+u4NSGqc1sgO0U0Ftwq9El6Bk8k2YeWxJ8oUD3yQqPv1EXSs6tB53A6zA
# 4nrm/1dmnqqQI9KSvEKZblr9KYTy6AoRcpzEezLM0sFXTaSqHGCPvCYP3Qar6oI7
# eoaO8OkzcNH7dTxuXRrTWQ7IUeAr2/bUAJAbgnjwZpQ/yxdmjOnu+OdBXGtoe8Rv
# G01nyxAj94TaCXsPcV8KxAusML4iEAlkmLsXtnpPY8jfnHpSx/LN0nEA5x3nwqPQ
# DxRy0ZIeHb5ZXAo7v5E+G358O5CQ/TNGt2jGOrHqMIIDFTCCAgGgAwIBAgIQVJ8q
# dzf/f7xETWjhXWNf/jAJBgUrDgMCHQUAMBgxFjAUBgNVBAMTDU9NTklDLlRFQ0gt
# Q0EwHhcNMTgwMzEzMTAyMjA5WhcNMzkxMjMxMjM1OTU5WjAZMRcwFQYDVQQDEw5P
# TU5JQy5URUNIIENTQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCR
# mWrJc2EZ6cvOJHj7YQEcijDJ0bLSV+3Gi6G9CB5tKjlubGu9KqzTugTUEzxww6qe
# fE6YSE4XSLevdaOVqcRKmKZ2iwwGIK5VCw54XpQLNBVpDO+3j2tmm3en3zvtb2G0
# 73FO9zio6IyLz+0eoIEiXRTlJow0c1LSLbEitGaG+0YD6gSre5bSz6CWxmAVQqcD
# 2u1YtXGXs7LccHLo/xyJtWgqmo4F+/8GCbN/9OXpgVdGQ0DA04kDFZJ2Jp22+sd4
# gfpyY8lLNURnKqGGHSND9PB4p+uH1KaIL8zULJxOumz7Te3lm/LxkAN/dUye7zFX
# K+Xl1YiT0xfQIgx8yhUCAwEAAaNiMGAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSQYD
# VR0BBEIwQIAQdk5/1Q5+V22Q+v24kkopfaEaMBgxFjAUBgNVBAMTDU9NTklDLlRF
# Q0gtQ0GCEIJySwKTaHSqRosBcWAuynkwCQYFKw4DAh0FAAOCAQEAMpU5vXMt8BxR
# wTMYnLyNsSGXPoF8PI9LuO+gytZwdzcPPAoU46OczHY/xw6XDxsvI+87ytSAgFBv
# 9/mla+e+9g8AIZUH9wHAGKRbn9pqLST3q+xHtYdrPN+KKOaN4DsL81kCMolNEPMt
# NrG2IqBMiJSKglsNNTHkuPB1yNSw3Ix9W7qTFcoByjObZsZBE9vz90AwyPzTMQwt
# +FiyYwZI1ELp1cGrX1vW3QGnzkdl/h0VEt1SDYvS712tVGRm2U49dF43bSwsKHdA
# sccJgiQaf2tld9QPRWbtUK0PgTosBCpzjsl8MFS7TsHJ2dFGLAHefFqMM+fZgQa8
# iuBBshmR3TGCAmYwggJiAgEBMCwwGDEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQQIQ
# VJ8qdzf/f7xETWjhXWNf/jAJBgUrDgMCGgUAoIIBDzAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG
# 9w0BCQQxFgQU5S/CyCFSSPb/NlxQdBwPKVZ6AwQwga4GCisGAQQBgjcCAQwxgZ8w
# gZyggZmAgZYAQQAgAGYAdQBsAGwAeQAgAGEAdQB0AG8AbQBhAHQAZQBkACAAVwBp
# AG4AZABvAHcAcwAgADEAMAAgAFIAUwAyACAAYQBuAGQAIABSAFMAMwAgAG8AZgBm
# AGwAaQBuAGUAIABpAG0AYQBnAGUAIABvAHAAdABpAG0AaQB6AGEAdABpAG8AbgAg
# AHMAYwByAGkAcAB0AC4wDQYJKoZIhvcNAQEBBQAEggEAmHa/Lvb6SxyZDsQVLLZx
# GLws98Fx6KpeOPsYsyaSi66tao+i/NaEp4loAAZ/4qJwmUPUlQvl5omlKeWhL/1B
# oqWXCBsGsFCFlLp/JgyFH+QjnmrxXzcYrd+Jaz1yNbKqPlcL5pIaxQNhQ8JFEo3R
# YeU3bXwwiKwO1+GPWa9sV/Tq2BWWNLIYE9dY9PW2jt87ySa2fqLK3OheOKBH5BJ6
# GvSxxX1ZF8nONhr2cogVRudgnasZdQWLHHP9sDgA8iaoSxeVbRNxKjnA1wA6fMs6
# 2TfvUxgaEp7PVZPhCj1WPSwkLZrod1SnYRBSIIBBOFWaxHUAQe2/Pw0Di/6iZLlo
# Sg==
# SIG # End signature block
