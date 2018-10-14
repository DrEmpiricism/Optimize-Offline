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
	
	.PARAMETER Packages
		Populates and outputs a Gridview list of all installed Windows Capability Packages for selective removal.
	
	.PARAMETER Features
		Populates and outputs a Gridview list of all enabled Windows Optional Features for selective disabling.
	
	.PARAMETER OneDrive
		Performs a complete removal of Microsoft OneDrive, its associated directories and registry keys.
	
	.PARAMETER Registry
		Applies optimized registry values into the registry hives of the image.
	
	.PARAMETER DaRT
		Applies the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools to Windows Setup and Windows Recovery.
	
	.PARAMETER Drivers
		The full path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.PARAMETER NetFx3
		Either a boolean value of $true or the full path to the .NET Framework 3 payload packages to be applied to the image.
	
	.PARAMETER NoSetup
		Excludes the Setup and Post Installation Script(s) from being applied to the image.
	
	.PARAMETER WindowsStore
        	Specific to Windows 10 Enterprise LTSC only!
        	Sideloads the Microsoft Windows Store, and its dependencies, into the image.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\Win10Pro_Full.iso" -Index 3 -Build 16299 -MetroApps "Select" -SystemApps -Packages -OneDrive -Registry -DaRT -NetFx3 $true -Drivers "E:\Driver Folder"
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\install.wim" -Build 17134 -MetroApps "All" -SystemApps -Packages -Features -OneDrive -NetFx3 "C:\Windows 10\sources\sxs" -NoSetup
	
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
		Version:        3.1.2.0
		Last updated:	10/14/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $true,
        HelpMessage = 'The full path to a Windows Installation ISO or an install WIM file.')]
    [ValidateScript( {
            If ((Test-Path $(Resolve-Path -Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
            ElseIf ((Test-Path $(Resolve-Path -Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
            Else { Throw "Invalid image path: $_" }
        })]
    [Alias('ISO', 'WIM')]
    [string]$ImagePath,
    [Parameter(HelpMessage = 'If using a multi-index image, specify the index of the image.')]
    [ValidateRange(1, 16)]
    [int]$Index = 1,
    [Parameter(Mandatory = $true,
        HelpMessage = 'The build number of the Windows image being optimized.')]
    [ValidateRange(15063, 18204)]
    [int]$Build,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Provisioned Application Packages for selective removal or performs a complete removal of all packages.')]
    [ValidateSet('Select', 'All')]
    [Alias('Appx')]
    [string]$MetroApps = 'Select',
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all System Applications for selective removal.')]
    [switch]$SystemApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all installed Windows Capability Packages for selective removal.')]
    [switch]$Packages,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all enabled Windows Optional Features for selective disabling.')]
    [switch]$Features,
    [Parameter(HelpMessage = 'Performs a complete removal of Microsoft OneDrive, its associated directories and registry keys.')]
    [switch]$OneDrive,
    [Parameter(HelpMessage = 'Applies optimized registry values into the registry hives of the image.')]
    [switch]$Registry,
    [Parameter(HelpMessage = 'Applies the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools to Windows Setup and Windows Recovery.')]
    [switch]$DaRT,
    [Parameter(HelpMessage = 'The full path to a collection of driver packages, or a driver .inf file, to be injected into the image.')]
    [ValidateScript( { Test-Path $(Resolve-Path -Path $_) })]
    [string]$Drivers,
    [Parameter(HelpMessage = 'Either a boolean value of $true or the full path to the .NET Framework 3 payload packages to be applied to the image.')]
    [string]$NetFx3,
    [Parameter(HelpMessage = 'Excludes the Setup and Post Installation Script(s) from being applied to the image.')]
    [switch]$NoSetup,
    [Parameter(HelpMessage = 'Sideloads the Microsoft Windows Store, and its dependencies, into the image.')]
    [switch]$WindowsStore
)

#region Script Variables
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = 'SilentlyContinue'
$ScriptRoot = (Get-Item -Path '.' -Force).FullName
$Win32CalcPath = $ScriptRoot + "\Resources\Win32Calc"
$DaRTPath = $ScriptRoot + "\Resources\DaRT"
$StoreAppPath = $ScriptRoot + "\Resources\WindowsStore"
$OfflineBackupDirectory = $WorkFolder + '\' + "OfflineRegistryBackup_" + $(Get-Date -Format "MM-dd-yyyy")
$BkpTimestamp = Get-Date -Format "[M.dd.yy-hh.mm.ss]"
$OScript = "Optimize-Offline"
$LogFile = "$Env:TEMP\Optimize-Offline.log"
$DISMLog = "$Env:TEMP\DISM.log"
#endregion Script Variables

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
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(
        string host,
        string name,
        ref long luid
        );
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr token,
        bool disall,
        ref TOKEN_PRIVILEGES newst,
        int len,
        IntPtr prev,
        IntPtr relen
        );
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool OpenProcessToken(
        IntPtr curProcess,
        int acc,
        ref IntPtr processToken
        );
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(
        IntPtr handle
        );
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
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
    public static void AdjustPrivilege(IntPtr curProcess, string privilege, bool enable)
    {
        var processToken = IntPtr.Zero;
        if (!OpenProcessToken(curProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref processToken))
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
                processToken
                );
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
        $Admin = ((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]))
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
    Begin
    {
        $TakeOwnership = "SeTakeOwnershipPrivilege"
    }
    Process
    {
        $TakeOwnership | Invoke-ProcessPrivilege
        $ACL = Get-Acl -Path $Path
        $Admin = ((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]))
        $ACL.SetOwner($Admin)
        $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Admin, "FullControl", "None", "None", "Allow")))
        $TakeOwnership | Invoke-ProcessPrivilege -Disable
        $ACL | Set-Acl -Path $Path
    }
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
    $SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptRoot -ChildPath Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
    $SaveDir = Get-Item -LiteralPath $ScriptRoot\$SaveDir
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
    @("HKLM:\WIM_HKLM_SOFTWARE", "HKLM:\WIM_HKLM_SYSTEM", "HKLM:\WIM_HKCU", "HKLM:\WIM_HKU_DEFAULT") | ForEach {
        If (Test-Path -Path $_) { $HivesLoaded = $true }
    }
    Return $HivesLoaded
}

Function Clear-CurrentMount
{
    [CmdletBinding()]
    Param ()
	
    $Host.UI.RawUI.WindowTitle = "Cleaning-up mount path."
    Write-Host "Mount path detected. Performing clean-up." -ForegroundColor Cyan
    $MountPath = (Get-WindowsImage -Mounted).MountPath
    $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR "WIM"')
    If ($QueryHives) { [void]($QueryHives.ForEach{ REG UNLOAD $_ }) }
    Start-Process -FilePath DISM -ArgumentList ("/English /Unmount-Wim /MountDir:`"${MountPath}`" /Discard") -WindowStyle Hidden -Wait
    Get-ChildItem -Path '.' -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    [void](Clear-WindowsCorruptMountPoint)
}

Function Exit-Script
{
    $Host.UI.RawUI.WindowTitle = "Terminating Script."
    Start-Sleep 3
    Write-Output ''
    Out-Log -Content "Cleaning-up and terminating script." -Level Info
    If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $ScratchFolder -LogPath $DISMLog -LogLevel 1)
    [void](Clear-WindowsCorruptMountPoint)
    $SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptRoot -ChildPath Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]")); [void]$SaveDir
    If ($Error.Count)
    {
        $ErrorLog = Join-Path -Path $Env:TEMP -ChildPath "ErrorLog.log"
        Set-Content -Path $ErrorLog -Value $Error.ToArray() -Force -ErrorAction SilentlyContinue
        Move-Item -Path $ErrorLog -Destination $SaveDir -Force -ErrorAction SilentlyContinue
    }
    $TimeStamp = Get-Date -Format "MM-dd-yyyy hh:mm:ss tt"
    Add-Content -Path $LogFile -Value ''
    Add-Content -Path $LogFile -Value "***************************************************************************************************"
    Add-Content -Path $LogFile -Value "`t`t$($OScript) stopped at [$($TimeStamp)]"
    Add-Content -Path $LogFile -Value "***************************************************************************************************"
    Move-Item -Path $LogFile -Destination $SaveDir -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$WorkFolder\Registry-Optimizations.log") { Move-Item -Path "$WorkFolder\Registry-Optimizations.log" -Destination $SaveDir -Force -ErrorAction SilentlyContinue }
    Remove-Item -Path "$Env:TEMP\DISM.log" -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $ScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
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
If ((Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture -ne "64-bit") { Write-Warning "$OScript only supports a 64-bit architecture."; Break }
If (Get-WindowsImage -Mounted) { Clear-CurrentMount }

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
    Get-ChildItem -Path $ScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $CreateScriptDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptRoot -ChildPath "OptimizeOfflineTemp_$(Get-Random)"))
    If ($CreateScriptDir) { $ScriptDirectory = Get-Item -LiteralPath $ScriptRoot\$CreateScriptDir -ErrorAction Stop }
    $Host.UI.RawUI.WindowTitle = "Preparing image for optimizations."
    $Timer = New-Object System.Diagnostics.Stopwatch
    $Timer.Start()
}
Catch
{
    Write-Warning "Failed to create the script directory. Ensure the script path is writable."
    Break
}

Try
{
    If (([IO.FileInfo]$ImagePath).Extension -eq ".ISO")
    {
        $Source = ([System.IO.Path]::ChangeExtension($ImagePath, ([System.IO.Path]::GetExtension($ImagePath)).ToString().ToLower()))
        $Source = (Resolve-Path -Path $Source -ErrorAction Stop).ProviderPath
        $SourceMount = Mount-DiskImage -ImagePath $Source -StorageType ISO -PassThru -ErrorAction Stop
        $DriveLetter = ($SourceMount | Get-Volume).DriveLetter + ':'
        $ISODrive = Get-Item -Path $DriveLetter -Force -ErrorAction Stop
        $SourceName = $($Source.Split('\')[-1]).TrimEnd('.iso')
        $ISOMedia = "$($ScriptDirectory)\$($SourceName)"
        [void](New-Item -Path $ISOMedia -ItemType Directory -Force -ErrorAction Stop)
        $InstallWim = "$($DriveLetter)\sources\install.wim"
        If (!(Test-Path -Path $InstallWim))
        {
            Write-Warning "$(Split-Path -Path $ImagePath -Leaf) does not contain valid Windows Installation media."
            Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
        Else
        {
            Write-Host ('Exporting media from "{0}"' -f $(Split-Path -Path $Source -Leaf)) -ForegroundColor Cyan
            ForEach ($File In Get-ChildItem -Path $ISODrive.FullName -Recurse)
            {
                $NewPath = $ISOMedia + $File.FullName.Replace($ISODrive, '\')
                Copy-Item -Path $File.FullName -Destination $NewPath -Force -ErrorAction Stop
            }
            Dismount-DiskImage -ImagePath $Source -StorageType ISO
            $ISOIsExported = $true
        }
        If (Test-Path -Path "$ISOMedia\sources\install.wim")
        {
            [void]($MountFolder = New-MountDirectory)
            [void]($ImageFolder = New-ImageDirectory)
            [void]($WorkFolder = New-WorkDirectory)
            [void]($ScratchFolder = New-ScratchDirectory)
            Move-Item -Path "$ISOMedia\sources\install.wim" -Destination $ImageFolder -Force -ErrorAction Stop
            $InstallWim = Get-Item -Path "$ImageFolder\install.wim" -Force -ErrorAction Stop
            Set-ItemProperty -LiteralPath $InstallWim -Name IsReadOnly -Value $false -ErrorAction Stop
            If ((Test-Path -Path "$ISOMedia\sources\boot.wim") -and ($DaRT))
            {
                Move-Item -Path "$ISOMedia\sources\boot.wim" -Destination $ImageFolder -Force -ErrorAction Stop
                $BootWim = Get-Item -Path "$ImageFolder\boot.wim" -Force -ErrorAction Stop
                Set-ItemProperty -LiteralPath $BootWim -Name IsReadOnly -Value $false -ErrorAction Stop
                $BootIsPresent = $true
            }
        }
    }
    ElseIf (([IO.FileInfo]$ImagePath).Extension -eq ".WIM")
    {
        If (Test-Path -Path $ImagePath -Filter "install.wim")
        {
            $ImagePath = (Resolve-Path -Path $ImagePath -ErrorAction Stop).ProviderPath
            Write-Host ('Copying WIM from "{0}"' -f $(Split-Path -Path $ImagePath -Parent)) -ForegroundColor Cyan
            [void]($MountFolder = New-MountDirectory)
            [void]($ImageFolder = New-ImageDirectory)
            [void]($WorkFolder = New-WorkDirectory)
            [void]($ScratchFolder = New-ScratchDirectory)
            Copy-Item -Path $ImagePath -Destination $ImageFolder -Force -ErrorAction Stop
            $InstallWim = Get-Item -Path "$ImageFolder\install.wim" -Force -ErrorAction Stop
            If ($InstallWim.IsReadOnly) { Set-ItemProperty -LiteralPath $InstallWim -Name IsReadOnly -Value $false -ErrorAction Stop }
        }
        Else
        {
            Write-Warning "$ImagePath is not labeled as an install.wim"
            Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
    }
}
Catch
{
    Write-Output ''
    Write-Host "Unable to attain required image data content." -ForegroundColor Red
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
If (Test-Path -Path $DISMLog) { Remove-Item -Path $DISMLog -Force -ErrorAction SilentlyContinue }
If (Test-Path -Path $LogFile) { Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue }

If ((Get-WindowsImage -ImagePath $InstallWim -Index $Index).InstallationType -eq "Server")
{
    Write-Output ''
    Write-Warning "Server editions are not supported."
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}
Else
{
    [void](New-Item -Path $LogFile -ItemType File -Force)
    $TimeStamp = Get-Date -Format "MM-dd-yyyy hh:mm:ss tt"
    @"
***************************************************************************************************
			$($OScript) started at [$($TimeStamp)]
***************************************************************************************************

"@ | Out-File -FilePath $LogFile -Append -Encoding ASCII
}

Try
{
    $ImageVersion = (Get-WindowsImage -ImagePath $InstallWim -Index $Index -ErrorAction Stop).Version
    $ImageBuild = (Get-WindowsImage -ImagePath $InstallWim -Index $Index -ErrorAction Stop).Build
    $ImageName = (Get-WindowsImage -ImagePath $InstallWim -Index $Index -ErrorAction Stop).ImageName
    If ($ImageVersion -like "10.*")
    {
        If ($ImageBuild -lt '15063')
        {
            Write-Output ''
            Write-Warning "The image build is not supported [$($ImageBuild.ToString())]"
            Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
        Else
        {
            Write-Output ''
            Out-Log -Content "The image build is supported [$($ImageBuild.ToString())]" -Level Info
            Start-Sleep 3
            $Error.Clear()
        }
    }
    Else
    {
        Write-Output ''
        Write-Warning "The image version is not supported [$($ImageVersion.ToString())]"
        Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
}
Catch
{
    Write-Output ''
    Write-Warning "Failed to return the image version and build."
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

Try
{
    Write-Output ''
    Out-Log -Content "Mounting $($ImageName.ToString())" -Level Info
    $MountWindowsImage = @{
        ImagePath        = $InstallWim
        Index            = $Index
        Path             = $MountFolder
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        LogLevel         = 1
        ErrorAction      = "Stop"
    }
    [void](Mount-WindowsImage @MountWindowsImage)
    $ImageHealth = (Repair-WindowsImage -Path $MountFolder -CheckHealth -ErrorAction Stop).ImageHealthState
    If ($ImageHealth -eq "Healthy")
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
Catch
{
    Write-Output ''
    Out-Log -Content "Failed to return the image health state." -Level Error
    Exit-Script
    Break
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Backing-up the Default Registry."
    Write-Output ''
    Out-Log -Content "Backing-up the Default Registry." -Level Info
    [void](New-Item -Path $OfflineBackupDirectory -ItemType Directory -Force -ErrorAction Stop)
    [void](Mount-OfflineHives)
    Start-Process -FilePath REGEDIT -ArgumentList ("/E $OfflineBackupDirectory\HKLM_$BkpTimestamp.reg HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE") -WindowStyle Hidden -Wait -ErrorAction Stop
    Start-Process -FilePath REGEDIT -ArgumentList ("/E $OfflineBackupDirectory\HKLM_$BkpTimestamp.reg HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM") -WindowStyle Hidden -Wait -ErrorAction Stop
    Start-Process -FilePath REGEDIT -ArgumentList ("/E $OfflineBackupDirectory\HKCU_$BkpTimestamp.reg HKEY_LOCAL_MACHINE\WIM_HKCU") -WindowStyle Hidden -Wait -ErrorAction Stop
    Start-Process -FilePath REGEDIT -ArgumentList ("/E $OfflineBackupDirectory\HKU_$BkpTimestamp.reg HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT") -WindowStyle Hidden -Wait -ErrorAction Stop
    [void](Dismount-OfflineHives)
    [void](Compress-Archive -Path $OfflineBackupDirectory -DestinationPath "$WorkFolder\RegistryBackup.Zip" -CompressionLevel Optimal -ErrorAction Stop)
    Remove-Item -Path $OfflineBackupDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
Catch
{
    Write-Output ''
    Out-Log -Content "Failed to back-up the Default Registry." -Level Error
    Exit-Script
    Break
}
Finally
{
    If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
}

If (($MetroApps -and $ImageName -notlike "*LTSC"))
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
                        Path             = $MountFolder
                        PackageName      = $($_)
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        LogLevel         = 1
                        ErrorAction      = "Stop"
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
                    Path             = $MountFolder
                    PackageName      = $($_.PackageName)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
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
        $InboxAppsPackage = (Get-ChildItem -Path $InboxAppsKey).Name.Split('\') | Where { $_ -like "*Microsoft.*" }
        $GetSystemApps = $InboxAppsPackage | Select -Property `
        @{ Label = 'Name'; Expression = { ($_.Split('_')[0]) } },
        @{ Label = 'PackageName'; Expression = { ($_) } } |
            Out-GridView -Title "Remove System Applications." -PassThru
        $SystemAppPackage = $GetSystemApps.PackageName
        If ($GetSystemApps)
        {
            Clear-Host
            $SystemAppPackage | ForEach {
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
        $Host.UI.RawUI.WindowTitle = "Removing Windows Capability Packages."
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
                    Path             = $MountFolder
                    Name             = $($_)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
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

If ($OneDrive)
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Removing Microsoft OneDrive."
        Out-Log -Content "Removing Microsoft OneDrive." -Level Info
        Start-Sleep 3
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\OneDrive" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableMeteredNetworkFileSync" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\OneDrive" -Name "DisablePersonalSync" -Value 1 -Type DWord
        If ($ImageName -notlike "*LTSC")
        {
            If ((Get-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue) -match "OneDriveSetup")
            {
                Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force -ErrorAction Stop
            }
        }
        If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}")
        {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -Recurse -ErrorAction Stop
        }
        If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}")
        {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -Recurse -ErrorAction Stop
        }
        [void](Dismount-OfflineHives)
        If (Test-Path -Path "$MountFolder\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk")
        {
            Remove-Item -LiteralPath "$MountFolder\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Stop
        }
        If (Test-Path -Path "$MountFolder\Windows\WinSxS\*onedrive*")
        {
            [void](New-Item -Path $WorkFolder -ItemType Directory -Name OneDriveWinSxS -Force -ErrorAction Stop)
            Copy-Item -Path "$MountFolder\Windows\WinSxS\*onedrive*" -Destination "$WorkFolder\OneDriveWinSxS" -Recurse -ErrorAction Stop
            [void](Compress-Archive -Path "$WorkFolder\OneDriveWinSxS\*" -DestinationPath "$WorkFolder\OneDriveBackup.Zip" -CompressionLevel Optimal -ErrorAction Stop)
            [void](Set-FolderOwnership -Path "$MountFolder\Windows\WinSxS\*onedrive*" -ErrorAction SilentlyContinue)
            Get-ChildItem -Path "$MountFolder\Windows\WinSxS\*onedrive*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$WorkFolder\OneDriveWinSxS" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to remove Microsoft OneDrive." -Level Error
        Exit-Script
        Break
    }
}

If ($MetroAppsComplete -eq $true)
{
    Try
    {
        If ((Get-AppxProvisionedPackage -Path $MountFolder |
                    Where DisplayName -Match "Microsoft.Wallet").Count.Equals(0) -or (Get-AppxProvisionedPackage -Path $MountFolder |
                    Where DisplayName -Match "Microsoft.WindowsMaps").Count.Equals(0))
        {
            $Host.UI.RawUI.WindowTitle = "Disabling Provisioned App Package Services."
            If ($OneDrive) { Write-Output '' }
            Out-Log -Content "Disabling Provisioned App Package Services." -Level Info
            Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SYSTEM `"$MountFolder\Windows\System32\config\system`"") -WindowStyle Hidden -Wait
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            }
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            }
            Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SYSTEM") -WindowStyle Hidden -Wait
        }
    }
    Catch
    {
        Out-Log -Content "An error occurred removing Provisoned App Package Services." -Level Error
        Exit-Script
        Break
    }
}

If ($ImageName -notlike "*LTSC")
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Cleaning-up the Start Menu and Taskbar Layout."
        Write-Output ''
        Out-Log -Content "Cleaning-up the Start Menu and Taskbar Layout." -Level Info
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
        Out-Log -Content "Failed to clean-up the Start Menu and Taskbar Layout." -Level Error
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
        Out-Log -Content "Disabling Windows Defender Services, Drivers and Smartscreen Integration." -Level Info
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Name "Notification_Suppress" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord
        If ((Get-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue) -match "SecurityHealth")
        {
            Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force -ErrorAction Stop
        }
        @("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            }
        }
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderApiLogger" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderAuditLogger" -Recurse -Force -ErrorAction SilentlyContinue
        [void](Dismount-OfflineHives)
        Start-Sleep 3
        If ((Get-WindowsOptionalFeature -Path $MountFolder -FeatureName "Windows-Defender-Default-Definitions").State -eq "Enabled")
        {
            Write-Output ''
            Out-Log -Content "Disabling Windows Optional Feature: Windows-Defender-Default-Defintions" -Level Info
            $DisableDefenderFeature = @{
                Path             = $MountFolder
                FeatureName      = "Windows-Defender-Default-Definitions"
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                LogLevel         = 1
                ErrorAction      = "Stop"
            }
            [void](Disable-WindowsOptionalFeature @DisableDefenderFeature)
        }
        $DisableDefenderComplete = $true
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to disable remaining Windows Defender Services, Drivers and Smartscreen Integration." -Level Error
        Exit-Script
        Break
    }
}

If ($MetroApps -eq "All" -or $RemovedSystemApps -contains "Microsoft.XboxGameCallableUI" -or ((Get-AppxProvisionedPackage -Path $MountFolder |
                Where PackageName -Like "*Xbox*").Count -lt 5) -and $ImageName -notlike "*LTSC")
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Removing Xbox Remnants."
        Write-Output ''
        Out-Log -Content "Disabling Xbox Services and Drivers." -Level Info
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord -ErrorAction Stop
        @("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            }
        }
        [void](Dismount-OfflineHives)
        $DisableXboxComplete = $true
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to disable Xbox Services and Drivers." -Level Error
        Exit-Script
        Break
    }
}

Try
{
    If ((Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -Like "*SMB1Protocol*").State -eq "Enabled")
    {
        $Host.UI.RawUI.WindowTitle = "Disabling the SMBv1 Protocol Feature."
        Write-Output ''
        Out-Log -Content "Disabling the SMBv1 Protocol Feature." -Level Info
        [void](Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -Like "*SMB1Protocol*" |
                Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $ScratchFolder -LogPath $DISMLog -LogLevel 1 -ErrorAction Stop)
    }
}
Catch
{
    Write-Output ''
    Out-Log -Content "Failed to Disable the SMBv1 Protocol Feature." -Level Error
    Exit-Script
    Break
}

If ($Features)
{
    $DisabledOptionalFeatures = [System.Collections.ArrayList]@()
    Try
    {
        Clear-Host
        $Host.UI.RawUI.WindowTitle = "Disabling Windows Features."
        $GetFeatures = (Get-WindowsOptionalFeature -Path $MountFolder | Where State -EQ "Enabled")
        $Int = 1
        ForEach ($Feature In $GetFeatures)
        {
            $GetFeatures = New-Object -TypeName PSObject
            $GetFeatures | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $GetFeatures | Add-Member -MemberType NoteProperty -Name FeatureName -Value $Feature.FeatureName
            $GetFeatures | Add-Member -MemberType NoteProperty -Name State -Value $Feature.State
            $Int++
            [void]$DisabledOptionalFeatures.Add($GetFeatures)
        }
        $DisableFeatures = $DisabledOptionalFeatures | Out-GridView -Title "Disable Windows Features." -PassThru
        $FeatureName = $DisableFeatures.FeatureName
        If ($DisableFeatures)
        {
            $FeatureName | ForEach {
                Out-Log -Content "Disabling Windows Feature: $($_)" -Level Info
                $DisableFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $_
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = "Stop"
                }
                [void](Disable-WindowsOptionalFeature @DisableFeature)
            }
            Clear-Host
        }
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to disable all Windows Features." -Level Error
        Exit-Script
        Break
    }
    Finally
    {
        $Int = $null
    }
}

If ($WindowsStore -and $ImageName -like "*LTSC")
{
    If (Test-Path -LiteralPath $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle)
    {
        If (!$Features) { Write-Output '' }
        $Host.UI.RawUI.WindowTitle = "Sideloading the Microsoft Store Application."
        Out-Log -Content "Sideloading the Microsoft Store Application." -Level Info
        Try
        {
            $StoreBundle = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.WindowsStore*.appxbundle -Recurse -ErrorAction Stop).FullName
            $PurchaseBundle = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.StorePurchaseApp*.appxbundle -Recurse -ErrorAction Stop).FullName
            $XboxBundle = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.XboxIdentityProvider*.appxbundle -Recurse -ErrorAction Stop).FullName
            $InstallerBundle = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.DesktopAppInstaller*.appxbundle -Recurse -ErrorAction Stop).FullName
            $StoreLicense = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.WindowsStore*.xml -Recurse -ErrorAction Stop).FullName
            $PurchaseLicense = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.StorePurchaseApp*.xml -Recurse -ErrorAction Stop).FullName
            $IdentityLicense = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.XboxIdentityProvider*.xml -Recurse -ErrorAction Stop).FullName
            $InstallerLicense = (Get-ChildItem -Path $StoreAppPath -Include Microsoft.DesktopAppInstaller*.xml -Recurse -ErrorAction Stop).FullName
            $DepAppx = @()
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Include Microsoft.VCLibs*.appx -Recurse -ErrorAction Stop).FullName
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Include *Native.Framework*.appx -Recurse -ErrorAction Stop).FullName
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Include *Native.Runtime*.appx -Recurse -ErrorAction Stop).FullName
            Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SOFTWARE `"$MountFolder\Windows\System32\config\software`"") -WindowStyle Hidden -Wait
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord -ErrorAction Stop
            Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SOFTWARE") -WindowStyle Hidden -Wait
            $StorePackage = @{
                Path                  = $MountFolder
                PackagePath           = $StoreBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $StoreLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                LogLevel              = 1
                ErrorAction           = "Stop"
            }
            [void](Add-AppxProvisionedPackage @StorePackage)
            $PurchasePackage = @{
                Path                  = $MountFolder
                PackagePath           = $PurchaseBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $PurchaseLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                LogLevel              = 1
                ErrorAction           = "Stop"
            }
            [void](Add-AppxProvisionedPackage @PurchasePackage)
            $IdentityPackage = @{
                Path                  = $MountFolder
                PackagePath           = $XboxBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $IdentityLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                LogLevel              = 1
                ErrorAction           = "Stop"
            }
            [void](Add-AppxProvisionedPackage @IdentityPackage)
            $DepAppx = @()
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Include *Native.Runtime*.appx -Recurse -ErrorAction Stop).FullName
            $InstallerPackage = @{
                Path                  = $MountFolder
                PackagePath           = $InstallerBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $InstallerLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                LogLevel              = 1
                ErrorAction           = "Stop"
            }
            [void](Add-AppxProvisionedPackage @InstallerPackage)
            Start-Process -FilePath REG -ArgumentList ("LOAD HKLM\WIM_HKLM_SOFTWARE `"$MountFolder\Windows\System32\config\software`"") -WindowStyle Hidden -Wait
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 0 -Type DWord -ErrorAction Stop
            Start-Process -FilePath REG -ArgumentList ("UNLOAD HKLM\WIM_HKLM_SOFTWARE") -WindowStyle Hidden -Wait
            Get-AppxProvisionedPackage -Path $MountFolder | Format-List | Out-File -FilePath $WorkFolder\Sideloaded.txt
        }
        Catch
        {
            Write-Output ''
            Out-Log -Content "Failed to Sideload the Microsoft Store Application." -Level Error
            Exit-Script
            Break
        }
        Finally
        {
            If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
        }
    }
    Else
    {
        Write-Output ''
        Out-Log -Content "Missing the required Microsoft Store package files." -Level Error
        Start-Sleep 3
    }
}

#region Registry Optimizations
If ($Registry)
{
    Try
    {
        Write-Output ''
        $Host.UI.RawUI.WindowTitle = "Applying Optimized Registry Values."
        Out-Log -Content "Applying Optimized Registry Values." -Level Info
        If (Test-Path -Path "$WorkFolder\Registry-Optimizations.log") { Remove-Item -Path "$WorkFolder\Registry-Optimizations.log" -Force }
        [void](Mount-OfflineHives)
        #****************************************************************
        Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\InputPersonalization\TrainedDataStore" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Cortana Outgoing Network Traffic." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana ActionUriServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe|Name=Block Cortana ActionUriServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana PlacesServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe|Name=Block Cortana PlacesServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana RemindersServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana RemindersServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana RemindersShareTargetApp.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe|Name=Block Cortana RemindersShareTargetApp.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana SearchUI.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block Cortana SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana Package" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Cortana Package|Desc=Block Cortana Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|Platform=2:6:2|Platform2=GTEQ|" `
            -Type String
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
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        @("AutoLogger-Diagtrack-Listener", "Circular Kernel Context Logger", "Diagtrack-Listener", "WFP-IPsec Trace", "WPR_initiated_DiagTrackMiniLogger_WPR System Collector") | ForEach {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\$_")
            {
                Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\$_" -Recurse -Force -ErrorAction Stop
            }
        }
        #****************************************************************
        Write-Output "Disabling Office 2016 Telemetry and Logging." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows Update Automatic Driver Downloads." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling 'Find My Device'." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type DWord
        #***************************************************************
        Write-Output "Disabling Activity History." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Enabling PIN requirement for pairing devices." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord
        #****************************************************************	
        Write-Output "Disabling WiFi Sense." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord
        If ($ImageBuild -lt '17134')
        {
            #****************************************************************
            Write-Output "Disabling HomeGroup Services." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1 -Type DWord
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupListener" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupProvider" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        }
        If ($RemovedSystemApps -contains "Microsoft.BioEnrollment")
        {
            #****************************************************************
            Write-Output "Disabling Biometric Services." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWord
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Disabling Text Suggestions and Screen Monitoring." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Steps Recorder." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Compatibility Assistant." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows Asking for Feedback." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling the Password Reveal button." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows Media Player Statistics Tracking." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Microsoft Windows Media Digital Rights Management." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord
        #***************************************************************
        Write-Output "Disabling Advertisement ID." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Explorer Tips, Sync Notifications and Document Tracking." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FolderContentsInfoTip" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableBalloonTips" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StartButtonBalloonTip" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentProgForNewUserInStartMenu" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling System Advertisements and Windows Spotlight." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "IncludeEnterpriseSpotlight" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Toast Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Feature Advertisement Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoBalloonFeatureAdvertisements" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling System Tray Promotion Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoSystraySystemPromotion" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Typing Data Telemetry." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
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
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_ -Value 0 -Type DWord -ErrorAction Stop
        }
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceAppSuggestionsEnabled" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Explorer Ads and Tips." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows 'Getting to Know Me' and Tablet Mode Keylogging." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord
        #***************************************************************
        Write-Output "Disabling the Windows Insider Program and its Telemetry." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Notifications on Lock Screen." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Lock Screen Camera and Overlays." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Automatic Map Downloads." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Automatic Map Updates." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\Maps" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows Auto-Update and Auto-Reboot." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Type DWord
        #****************************************************************
        Write-Output "Disabling System and Settings Syncronization." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        @("Accessibility", "AppSync", "BrowserSettings", "Credentials", "DesktopTheme", "Language", "PackageState", "Personalization", "StartLayout", "Windows") | ForEach {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_" -Name "Enabled" -Value 0 -Type DWord
        }
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Value 5 -Type DWord
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSyncUserOverride" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling System Tracking, Location Sensors and Non-Explicit App Access." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Type" -Value "LooselyCoupled" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "InitialAppValue" -Value "Unspecified" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc" -Name "Start" -Value 4 -Type DWord
        #****************************************************************	
        Write-Output "Disabling Shared Experiences." >>  "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Value 0 -Type DWord
        #***************************************************************	
        Write-Output "Disabling Running Background Applications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        If ($ImageName -notlike "*LTSC") 
        {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "Migrated" -Value 4 -Type DWord
            Get-ChildItem -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" -ErrorAction SilentlyContinue | ForEach {
                Set-ItemProperty -LiteralPath $_ -Name "Disabled" -Value 1 -Type DWord -ErrorAction Stop
                Set-ItemProperty -LiteralPath $_ -Name "DisabledByUser" -Value 1 -Type DWord -ErrorAction Stop
            }
        }
        #****************************************************************
        Write-Output "Disabling App Access from Linked Devices." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Hiding 'Recently Added Apps' on Start Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Web Access to Language List." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\International\User Profile" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Advertising ID." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling the Link-Local Multicast Name Resolution (LLMNR) Protocol." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Error Reporting." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WerSvc" -Name "Start" -Value 4 -Type DWord
        #****************************************************************
        Write-Output "Enabling .NET Strong Cryptography." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Speech Model Updates." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling First Log-on Animation." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Windows Start-up Sound." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Changing Search Bar Icon to Magnifying Glass Icon." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Moving Drive Letter Before Drive Label." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord
        #****************************************************************
        If ($ImageBuild -lt '17686')
        {
            #****************************************************************	
            Write-Output "Enabling Dark Theme for Settings and Modern Apps." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
            #****************************************************************
            Write-Output "Enabling Dark Inactive Window Borders." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\DWM" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\DWM" -Name "AccentColor" -Value 4282927692 -Type DWord
        }
        #****************************************************************
        Write-Output "Increasing Taskbar and Theme Transparency." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord
        #****************************************************************
        Write-Output "Disabling 'Shortcut' text for Shortcuts." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value 00000000 -Type Binary
        #****************************************************************
        Write-Output "Enabling Explorer opens to This PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord
        #****************************************************************
        If ($ImageBuild -ge '17134' -and $ImageName -notlike "*LTSC")
        {
            #****************************************************************	
            Write-Output "Removing Microsoft Edge Desktop Shortcut Creation." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord
        }
        If ($ImageName -notlike "*LTSC")
        {
            #****************************************************************
            Write-Output "Removing Windows Store Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
            #****************************************************************
            Write-Output "Removing Windows Mail Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord
            #****************************************************************
            Write-Output "Disabling the Windows Mail Application." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord
        }
        If ($ImageBuild -ge '16273')
        {
            #****************************************************************	
            Write-Output "Removing People Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type DWord
        }
        #****************************************************************
        Write-Output "Disabling 'How do you want to open this file?' prompt." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Switching to Smaller Control Panel Icons." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Adding This PC Icon to Desktop." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Adding 'Reboot to Recovery' to My PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-RegistryOwner -SubKey "WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" -Name "Icon" -Value "%SystemRoot%\System32\imageres.dll,-110" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" -Name "(default)" -Value "SHUTDOWN.EXE -R -O -F -T 00" -Type String
        #****************************************************************
        Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Disabling Live Tiles." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling the Sets Feature." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSets" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Connected Drive Autoplay and Autorun." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord
        #****************************************************************
        If ($ImageBuild -ge '16273')
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
                Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction Stop
            }
        }
        ElseIf ($ImageBuild -lt '16273')
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
                Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction Stop
            }
        }
        If ($ImageBuild -ge "15063")
        {
            #****************************************************************	
            Write-Output "Removing '3D Print with 3D Builder' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            @("HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3ds\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Print",
                "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dae\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.dxf\Shell\3D Print",
                "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Print",
                "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Print", "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\.wrl\Shell\3D Print") | ForEach {
                Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction Stop
            }
        }
        #****************************************************************
        Write-Output "Restoring Windows Photo Viewer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        @(".bmp", ".gif", ".jfif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".wdp") | ForEach {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value (New-Object Byte[] 0) -Type Binary
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
            Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction Stop
        }
        #****************************************************************
        Write-Output "Removing 'Share' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -Value "" -Type String
        #****************************************************************
        Write-Output "Removing 'Give Access To' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" -Value "" -Type String
        #****************************************************************
        Write-Output "Removing 'Cast To Device' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "" -Type String
        #****************************************************************
        Write-Output "Removing Recently and Frequently Used Items in Explorer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord
        #****************************************************************
        Write-Output "Removing all User Folders from This PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        If ($ImageBuild -ge '16273')
        {
            # 3D Objects
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction Stop
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction Stop
        }
        # Desktop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Force -ErrorAction Stop
        # Documents
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Force -ErrorAction Stop
        # Downloads
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Force -ErrorAction Stop
        # Music
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Force -ErrorAction Stop
        # Pictures
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Force -ErrorAction Stop
        # Videos
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Force -ErrorAction Stop
        #****************************************************************
        Write-Output "Removing Drives from the Navigation Pane." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" -Force -ErrorAction Stop
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" -Force -ErrorAction Stop
        #****************************************************************
        Write-Output "Cleaning-up Windows Control Panel Links." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowCpl" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "1" -Value "Microsoft.OfflineFiles" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "2" -Value "Microsoft.EaseOfAccessCenter" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "3" -Value "Microsoft.PhoneAndModem" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "4" -Value "Microsoft.RegionAndLanguage" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "5" -Value "Microsoft.ScannersAndCameras" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "6" -Value "Microsoft.SpeechRecognition" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "7" -Value "Microsoft.SyncCenter" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "8" -Value "Microsoft.Infrared" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "9" -Value "Microsoft.ColorManagement" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "10" -Value "Microsoft.Fonts" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "11" -Value "Microsoft.Troubleshooting" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "12" -Value "Microsoft.InternetOptions" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "13" -Value "Microsoft.HomeGroup" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "14" -Value "Microsoft.DateAndTime" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "15" -Value "Microsoft.AutoPlay" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "16" -Value "Microsoft.DeviceManager" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "17" -Value "Microsoft.FolderOptions" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "18" -Value "Microsoft.RegionAndLanguage" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "19" -Value "Microsoft.TaskbarAndStartMenu" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "20" -Value "Microsoft.PenAndTouch" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "21" -Value "Microsoft.BackupAndRestore" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "22" -Value "Microsoft.DevicesAndPrinters" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "23" -Value "Microsoft.WindowsDefender" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "24" -Value "Microsoft.WorkFolders" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "25" -Value "Microsoft.WindowsAnytimeUpgrade" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" -Name "26" -Value "Microsoft.Language" -Type String
        #****************************************************************
        If ($ImageBuild -ge '16273')
        {
            #****************************************************************	
            Write-Output "Cleaning-up Immersive Control Panel Settings Links." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
            If ($RemovedSystemApps -contains "Microsoft.Windows.SecHealthUI")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                    -Name "SettingsPageVisibility" `
                    -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsinsider;windowsdefender" `
                    -Type String
            }
            Else
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                    -Name "SettingsPageVisibility" `
                    -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;phone;privacy-phonecall;privacy-callhistory;phone-defaultapps;windowsinsider" `
                    -Type String
            }
        }
        ElseIf ($ImageBuild -lt '16273')
        {
            #****************************************************************	
            Write-Output "Cleaning-up Immersive Control Panel Settings Links." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
            If ($RemovedSystemApps -contains "Microsoft.Windows.SecHealthUI")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                    -Name "SettingsPageVisibility" `
                    -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsinsider;windowsdefender" `
                    -Type String
            }
            Else
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                    -Name "SettingsPageVisibility" `
                    -Value "hide:cortana-language;cortana-moredetails;cortana-notifications;datausage;maps;network-dialup;network-mobilehotspot;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;holographic-audio;tabletmode;typing;sync;pen;speech;findmydevice;regionlanguage;printers;gaming-gamebar;gaming-gamemode;gaming-gamedvr;gaming-broadcasting;gaming-trueplay;gaming-xboxnetworking;windowsinsider" `
                    -Type String
            }
        }
        #****************************************************************
        Write-Output "Disabling Recent Document History." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Automatic Sound Reduction." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord
        #****************************************************************
        Write-Output "Enabling Windows to use latest .NET Framework." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Enabling the Fraunhofer IIS MPEG Layer-3 (MP3) Codec." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc")
        {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction Stop
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction Stop
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type ExpandString
        #****************************************************************
        Write-Output "Enabling the auto-removal of the DefaultUser0 account." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-RegistryOwner -SubKey "WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" -Name "AutoElevationAllowed" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling Sticky Keys." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value 122 -Type DWord
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value 58 -Type DWord
        #****************************************************************
        Write-Output "Increasing Icon Cache Size." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 4096 -Type DWord
        #****************************************************************
        Write-Output "Disabling OOBE Privacy Experience." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OOBE" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Disabling OOBE Cortana." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -Value 1 -Type DWord
        #****************************************************************
        Write-Output "Adding 'Open with Notepad' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        [void](New-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" -Force -ErrorAction Stop)
        [void](New-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" -Force -ErrorAction Stop)
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" -Name "Icon" -Value "Notepad.exe,-2" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" -Name "(default)" -Value "Notepad.exe %1" -Type ExpandString
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
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Icon" -Value "CMD.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "SeparatorAfter" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Icon" -Value "CMD.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "SeparatorAfter" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString
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
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\Background\shell\ElevatedPowerShell\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/S,/K,PUSHD,%V && START PowerShell && EXIT' -Verb RunAs`"" -Type ExpandString
        #****************************************************************
        Write-Output "Adding 'Take Ownership' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        [void](New-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Force -ErrorAction Stop)
        [void](New-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Force -ErrorAction Stop)
        [void](New-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Force -ErrorAction Stop)
        [void](New-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Force -ErrorAction Stop)
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "(default)" -Value "Take Ownership" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "NoWorkingDirectory" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "Position" -Value "Middle" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F `"%1`" && ICACLS `"%1`" /GRANT:R *S-1-3-4:F /T /C /L & PAUSE' -Verb RunAs`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Name "IsolatedCommand" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F `"%1`" && ICACLS `"%1`" /GRANT:R *S-1-3-4:F /T /C /L & PAUSE' -Verb RunAs`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "(default)" -Value "Take Ownership" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "AppliesTo" -Value "NOT (System.ItemPathDisplay:=`"C:\Users`" OR System.ItemPathDisplay:=`"C:\ProgramData`" OR System.ItemPathDisplay:=`"C:\Windows`" OR System.ItemPathDisplay:=`"C:\Windows\System32`" OR System.ItemPathDisplay:=`"C:\Program Files`" OR System.ItemPathDisplay:=`"C:\Program Files (x86)`")" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "NoWorkingDirectory" -Value "" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "Position" -Value "Middle" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F `"%1`" /R /D Y && ICACLS `"%1`" /GRANT:R *S-1-3-4:F /T /C /L /Q & PAUSE' -Verb RunAs`"" -Type ExpandString
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Name "IsolatedCommand" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F `"%1`" /R /D Y && ICACLS `"%1`" /GRANT:R *S-1-3-4:F /T /C /L /Q & PAUSE' -Verb RunAs`"" -Type ExpandString
        #****************************************************************
        Write-Output "Adding 'Restart Explorer' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Icon" -Value "Explorer.exe" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"(Get-Process -Name explorer).Kill()`"" -Type String
        #****************************************************************
        $SetRegistryComplete = $true
        [void](Dismount-OfflineHives)
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to Apply all Registry Optimizations." -Level Error
        Exit-Script
        Break
    }
}
#endregion Registry Optimizations

If ($ImageName -notlike "*LTSC")
{
    If ((Get-AppxProvisionedPackage -Path $MountFolder | Where PackageName -Like "*Calculator*").Count.Equals(0))
    {
        If ((Test-Path -Path "$Win32CalcPath\System32" -Filter win32calc*) -and (Test-Path -Path "$Win32CalcPath\SysWOW64" -Filter win32calc*))
        {
            Try
            {
                $Host.UI.RawUI.WindowTitle = "Applying the Win32 Calculator."
                Write-Output ''
                Out-Log -Content "Applying the Win32 Calculator." -Level Info
                Copy-Item -Path "$Win32CalcPath\System32" -Destination "$MountFolder\Windows" -Recurse -Force -ErrorAction Stop
                Copy-Item -Path "$Win32CalcPath\SysWOW64" -Destination "$MountFolder\Windows" -Recurse -Force -ErrorAction Stop
                [void](Mount-OfflineHives)
                New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -ErrorAction Stop
                New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -ErrorAction Stop
                New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -ErrorAction Stop
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -Name "(default)" -Value "@%SystemRoot%\System32\win32calc.exe,0" -Type ExpandString -ErrorAction Stop
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -Name "(default)" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorAction Stop
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -Name "ShellExecute" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorAction Stop
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
                Write-Output ''
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
}
Else { Write-Output '' }

If ($DaRT)
{
    If ((Test-Path -LiteralPath $DaRTPath -Filter MSDaRT10.wim) -and (Test-Path -LiteralPath $DaRTPath -Filter DebuggingTools_*.wim))
    {
        If ($ImageBuild -eq '15063') { $BuildCode = "RS2" }
        ElseIf ($ImageBuild -eq '16299') { $BuildCode = "RS3" }
        ElseIf ($ImageBuild -eq '17134') { $BuildCode = "RS4" }
        ElseIf ($ImageBuild -ge '17730') { $BuildCode = "RS5" }
        If ($BootIsPresent -eq $true)
        {
            Clear-Host
            $Host.UI.RawUI.WindowTitle = "Applying Microsoft DaRT 10."
            Out-Log -Content "Applying Microsoft DaRT 10 $($BuildCode) to Windows Setup and Windows Recovery." -Level Info
            Start-Sleep 3
        }
        Else
        {
            Clear-Host
            $Host.UI.RawUI.WindowTitle = "Applying Microsoft DaRT 10."
            Out-Log -Content "Applying Microsoft DaRT 10 $($BuildCode) to Windows Recovery." -Level Info
            Start-Sleep 3
        }
        Try
        {
            If ($BootIsPresent -eq $true)
            {
                $BootWim = Get-Item -Path "$ImageFolder\boot.wim" -Force -ErrorAction Stop
                $NewBootMount = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "BootMount_$(Get-Random)" -ErrorAction Stop))
                If ($NewBootMount) { $BootMount = Get-Item -LiteralPath "$ScriptDirectory\$NewBootMount" -ErrorAction Stop }
                $MountBootImage = @{
                    Path             = $BootMount
                    ImagePath        = $BootWim
                    Index            = 2
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Mounting the Boot Image." -Level Info
                [void](Mount-WindowsImage @MountBootImage)
                $MSDaRT10Boot = @{
                    ImagePath        = "$DaRTPath\MSDaRT10.wim"
                    Index            = 1
                    ApplyPath        = $BootMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Applying the Microsoft DaRT $($BuildCode) Base Package to the Boot Image." -Level Info
                [void](Expand-WindowsImage @MSDaRT10Boot)
                Start-Sleep 3
                $DeguggingToolsBoot = @{
                    ImagePath        = "$DaRTPath\DebuggingTools_$($BuildCode).wim"
                    Index            = 1
                    ApplyPath        = $BootMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Applying Windows 10 $($BuildCode) Debugging Tools to the Boot Image." -Level Info
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
                Write-Output ''
                Out-Log -Content "Cleaning-up the Boot Image."
                If (Test-Path -Path "$BootMount\Windows\WinSxS\Temp\PendingDeletes\*")
                {
                    [void](Set-FileOwnership -Path "$BootMount\Windows\WinSxS\Temp\PendingDeletes\*" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$BootMount\Windows\WinSxS\Temp\PendingDeletes\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$BootMount\Windows\WinSxS\Temp\TransformerRollbackData\*")
                {
                    [void](Set-FileOwnership -Path "$BootMount\Windows\WinSxS\Temp\TransformerRollbackData\*" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$BootMount\Windows\WinSxS\Temp\TransformerRollbackData\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$BootMount\Windows\WinSxS\ManifestCache\*" -Filter *.bin)
                {
                    [void](Set-FileOwnership -Path "$BootMount\Windows\WinSxS\ManifestCache\*.bin" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$BootMount\Windows\WinSxS\ManifestCache\*.bin" -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$BootMount\Windows\INF\*" -Filter *.log)
                {
                    [void](Set-FileOwnership -Path "$BootMount\Windows\INF\*.log" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$BootMount\Windows\INF\*.log" -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$BootMount\Windows\CbsTemp\*")
                {
                    [void](Set-FileOwnership -Path "$BootMount\Windows\CbsTemp\*" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$BootMount\Windows\CbsTemp\*" -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$BootMount\PerfLogs")
                {
                    Remove-Item -Path "$BootMount\PerfLogs" -Recurse -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path ("$BootMount\" + '$Recycle.Bin'))
                {
                    Remove-Item -Path ("$BootMount\" + '$Recycle.Bin') -Recurse -Force -ErrorAction SilentlyContinue
                }
                $DismountBootImage = @{
                    Path             = $BootMount
                    Save             = $true
                    CheckIntegrity   = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
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
                $BootWim = Get-Item -Path "$($WorkFolder)\boot.wim" -Force -ErrorAction Stop
            }
            If (Test-Path -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -PathType Leaf)
            {
                Start-Process -FilePath ATTRIB -ArgumentList ("-S -H -I `"$MountFolder\Windows\System32\Recovery\winre.wim`"") -NoNewWindow -Wait
                Copy-Item -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -Destination $ImageFolder -Force -ErrorAction Stop
                $RecoveryWim = Get-Item -Path "$ImageFolder\winre.wim" -Force -ErrorAction Stop
                $NewRecoveryMount = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "RecoveryMount_$(Get-Random)" -ErrorAction Stop))
                If ($NewRecoveryMount) { $RecoveryMount = Get-Item -LiteralPath "$ScriptDirectory\$NewRecoveryMount" -ErrorAction Stop }
                $MountRecoveryImage = @{
                    Path             = $RecoveryMount
                    ImagePath        = $RecoveryWim
                    Index            = 1
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Mounting the Recovery Image." -Level Info
                [void](Mount-WindowsImage @MountRecoveryImage)
                $MSDaRT10Recovery = @{
                    ImagePath        = "$DaRTPath\MSDaRT10.wim"
                    Index            = 1
                    ApplyPath        = $RecoveryMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Applying the Microsoft DaRT $($BuildCode) Base Package to the Recovery Image." -Level Info
                [void](Expand-WindowsImage @MSDaRT10Recovery)
                Start-Sleep 3
                $DeguggingToolsRecovery = @{
                    ImagePath        = "$DaRTPath\DebuggingTools_$($BuildCode).wim"
                    Index            = 1
                    ApplyPath        = $RecoveryMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Applying Windows 10 $($BuildCode) Debugging Tools to the Recovery Image." -Level Info
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
                Write-Output ''
                Out-Log -Content "Cleaning-up the Recovery Image."
                If (Test-Path -Path "$RecoveryMount\Windows\WinSxS\Temp\PendingDeletes\*")
                {
                    [void](Set-FileOwnership -Path "$RecoveryMount\Windows\WinSxS\Temp\PendingDeletes\*" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$RecoveryMount\Windows\WinSxS\Temp\PendingDeletes\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$RecoveryMount\Windows\WinSxS\Temp\TransformerRollbackData\*")
                {
                    [void](Set-FileOwnership -Path "$RecoveryMount\Windows\WinSxS\Temp\TransformerRollbackData\*" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$RecoveryMount\Windows\WinSxS\Temp\TransformerRollbackData\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$RecoveryMount\Windows\WinSxS\ManifestCache\*" -Filter *.bin)
                {
                    [void](Set-FileOwnership -Path "$RecoveryMount\Windows\WinSxS\ManifestCache\*.bin" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$RecoveryMount\Windows\WinSxS\ManifestCache\*.bin" -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$RecoveryMount\Windows\INF\*" -Filter *.log)
                {
                    [void](Set-FileOwnership -Path "$RecoveryMount\Windows\INF\*.log" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$RecoveryMount\Windows\INF\*.log" -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$RecoveryMount\Windows\CbsTemp\*")
                {
                    [void](Set-FileOwnership -Path "$RecoveryMount\Windows\CbsTemp\*" -ErrorAction SilentlyContinue)
                    Remove-Item -Path "$RecoveryMount\Windows\CbsTemp\*" -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path "$RecoveryMount\PerfLogs")
                {
                    Remove-Item -Path "$RecoveryMount\PerfLogs" -Recurse -Force -ErrorAction SilentlyContinue
                }
                If (Test-Path -Path ("$RecoveryMount\" + '$Recycle.Bin'))
                {
                    Remove-Item -Path ("$RecoveryMount\" + '$Recycle.Bin') -Recurse -Force -ErrorAction SilentlyContinue
                }
                $DismountRecoveryImage = @{
                    Path             = $RecoveryMount
                    Save             = $true
                    CheckIntegrity   = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    ErrorAction      = "Stop"
                }
                Write-Output ''
                Out-Log -Content "Saving and Dismounting the Recovery Image." -Level Info
                [void](Dismount-WindowsImage @DismountRecoveryImage)
                Write-Output ''
                Out-Log -Content "Rebuilding the Recovery Image." -Level Info
                $ExportRecovery = "/English /Export-Image /SourceImageFile:`"${ImageFolder}\winre.wim`" /All /DestinationImageFile:`"${WorkFolder}\winre.wim`" /Compress:Max /CheckIntegrity /Quiet"
                Start-Process -FilePath DISM -ArgumentList $ExportRecovery -WindowStyle Hidden -Wait
                Copy-Item -Path "$($WorkFolder)\winre.wim" -Destination "$MountFolder\Windows\System32\Recovery" -Force -ErrorAction Stop
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
            Out-Log -Content "Failed to apply Microsoft DaRT 10." -Level Error
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

If ($Drivers)
{
    Try
    {
        If (Get-ChildItem -Path $Drivers -Recurse -Include *.inf)
        {
            If ($DaRTApplied -eq $true) { Clear-Host }
            Else { Write-Output '' }
            $Host.UI.RawUI.WindowTitle = "Injecting Driver Packages."
            Out-Log -Content "Injecting Driver Packages." -Level Info
            $InjectDriverPackages = @{
                Path             = $MountFolder
                Driver           = $Drivers
                Recurse          = $true
                ForceUnsigned    = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                LogLevel         = 1
                ErrorAction      = "Stop"
            }
            [void](Add-WindowsDriver @InjectDriverPackages)
            Get-WindowsDriver -Path $MountFolder | Format-List | Out-File -FilePath $WorkFolder\InjectedDriverList.txt
        }
        Else
        {
            Write-Output ''
            Out-Log -Content "$($Drivers) contains no valid Driver Packages." -Level Error
            Start-Sleep 3
        }
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to inject Driver Packages into the image." -Level Error
        Exit-Script
        Break
    }
}


If ($NetFx3)
{
    If ($Drivers) { Write-Output '' }
    If ((Get-WindowsOptionalFeature -Path $MountFolder -FeatureName NetFx3).State -eq "DisabledWithPayloadRemoved")
    {
        Try
        {
            If (($ISOIsExported -eq $true) -and (Get-ChildItem -Path "$ISOMedia\sources\sxs" -Recurse -Include *netfx3*.cab))
            {
                $EnableNetFx3 = @{
                    FeatureName      = "NetFx3"
                    Path             = $MountFolder
                    All              = $true
                    LimitAccess      = $true
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    NoRestart        = $true
                    ScratchDirectory = $ScratchFolder
                    Source           = "$ISOMedia\sources\sxs"
                    ErrorAction      = "Stop"
                }
                $Host.UI.RawUI.WindowTitle = "Applying the .NET Framework Payload Package."
                Out-Log -Content "Applying the .NET Framework Payload Package." -Level Info
                [void](Enable-WindowsOptionalFeature @EnableNetFx3)
            }
            ElseIf (($ISOIsExported -ne $true) -and (Get-ChildItem -Path $NetFx3 -Recurse -Include *netfx3*.cab))
            {
                $EnableNetFx3 = @{
                    FeatureName      = "NetFx3"
                    Path             = $MountFolder
                    All              = $true
                    LimitAccess      = $true
                    LogPath          = $DISMLog
                    LogLevel         = 1
                    NoRestart        = $true
                    ScratchDirectory = $ScratchFolder
                    Source           = $NetFx3
                    ErrorAction      = "Stop"
                }
                $Host.UI.RawUI.WindowTitle = "Applying the .NET Framework Payload Package."
                Out-Log -Content "Applying the .NET Framework Payload Package." -Level Info
                [void](Enable-WindowsOptionalFeature @EnableNetFx3)
            }
        }
        Catch
        {
            Write-Output ''
            Out-Log -Content "Failed to apply the .NET Framework Payload Package." -Level Error
            Exit-Script
            Break
        }
    }
}

If (!$NoSetup)
{
    If ($Drivers -or $NetFx3) { Write-Output '' }
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Generating a Setup and Post-Installation Script."
        Out-Log -Content "Generating a Setup and Post-Installation Script." -Level Info
        Start-Sleep 3
        New-Container -Path "$MountFolder\Windows\Setup\Scripts" -ErrorAction Stop
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
SCHTASKS /QUERY | FINDSTR /B /I "AgentFallBack2016" >NUL 2>&1 && SCHTASKS /change /TN "\Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "AgentFallBack2019" >NUL 2>&1 && SCHTASKS /change /TN "\Microsoft\Office\OfficeTelemetry\AgentFallBack2019" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "AitAgent" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Background Synchronization" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Background Synchronization" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "BackgroundUploadTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "BackupTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackupTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "BthSQM" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /DISABLE >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Cellular" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Management\Provisioning\Cellular" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "CleanupOfflineContent" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Consolidator" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "CreateObjectTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\CloudExperienceHost\" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft-Windows-DiskDiagnosticDataCollector" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >NUL 2>&1   
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitor" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyMonitorToastTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "FamilySafetyRefreshTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "FODCleanupTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\HelloFace" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "KernelCeipTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Logon Synchronization" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Offline Files\Logon Synchronization" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "MapsToastTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "MapsUpdateTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Microsoft Compatibility Appraiser" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "MNO Metadata Parser" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "MobilityManager" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Ras\MobilityManager" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "OfficeTelemetryAgentLogOn" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "OfficeTelemetryAgentFallBack" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Office 15 Subscription Heartbeat" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Office 16 Subscription Heartbeat" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\Office 16 Subscription Heartbeat" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "OfficeTelemetryAgentLogOn2016" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Office 17 Subscription Heartbeat" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\Office 17 Subscription Heartbeat" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "OfficeTelemetryAgentLogOn2019" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2019" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "ProgramDataUpdater" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Proxy" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "SmartScreenSpecific" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\AppID\SmartScreenSpecific" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "UpdateLibrary" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL 2>&1
'@ | Out-File -FilePath $SetupScript -Encoding ASCII -ErrorAction Stop
        $XboxTasks = @'

SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTaskLogon" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable >NUL 2>&1
'@
        $DefenderTasks = @'

SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL 2>&1
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL 2>&1 && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL 2>&1
'@
        $FirewallRules = @'

SET LOCALAPPDATA=%USERPROFILE%\AppData\Local
PowerShell -Command "& { Get-NetFirewallRule | Where-Object Group -Like `"*@{*`" | Remove-NetFirewallRule -ErrorAction SilentlyContinue }"
PowerShell -Command "& { Get-NetFirewallRule | Where-Object Group -EQ `"DiagTrack`" | Remove-NetFirewallRule -ErrorAction SilentlyContinue }"
PowerShell -Command "& { Get-NetFirewallRule | Where-Object DisplayGroup -EQ `"Delivery Optimization`" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue }"
PowerShell -Command "& { Get-NetFirewallRule | Where-Object DisplayGroup -Like `"Windows Media Player Network Sharing Service*`" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue }"
PowerShell -Command "& { Set-AutologgerConfig -Name `"AutoLogger-Diagtrack-Listener`" -Start 0 -ErrorAction SilentlyContinue }"

NETSH ADVFIREWALL FIREWALL ADD RULE NAME="ContentDeliveryAdverts" action="block" dir="in" interface="any" program="%SystemDrive%\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\ContentDeliveryManager.Background.dll" Description="Prevent ContentDeliveryManager Inbound Traffic." enable=yes >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="ContentDeliveryAdverts" action="block" dir="out" interface="any" program="%SystemDrive%\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\ContentDeliveryManager.Background.dll" Description="Prevent ContentDeliveryManager Outbound Traffic." enable=yes >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="Block Windows Telemetry [DiagTrack]" dir="Out" action="Block" program="%SystemDrive%\windows\system32\svchost.exe" service="DiagTrack" protocol="TCP" remoteport=80,443 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="Block Windows Error Reporting Service [WerSvc]" dir="Out" action="Block" program="%SystemDrive%\windows\system32\svchost.exe" service="WerSvc" protocol="TCP" remoteport=80,443 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="SmartScreen" action="block" dir="in" interface="any" program="%WinDir%\System32\smartscreen.exe" Description="Prevent SmartScreen Inbound Traffic." enable=yes >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="SmartScreen" action="block" dir="out" interface="any" program="%WinDir%\System32\smartscreen.exe" Description="Prevent SmartScreen Outbound Traffic." enable=yes >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="in" action="block" protocol="UDP" localport="3478" >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="in" action="block" protocol="UDP" remoteport=3478 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="in" action="block" protocol="UDP" localport=19302 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="in" action="block" protocol="UDP" remoteport=19302 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="out" action="block" protocol="UDP" localport=3478 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="out" action="block" protocol="UDP" remoteport=3478 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="out" action="block" protocol="UDP" localport=19302 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="WebRTC Leak Fix" dir="out" action="block" protocol="UDP" remoteport=19302 >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="Compatability Telemetry Runner" action="block" dir="in" interface="any" program="%SystemDrive%\Windows\system32\CompatTelRunner.exe" Description="Prevent CompatTelRunner Inbound Traffic." enable=yes >NUL 2>&1
NETSH ADVFIREWALL FIREWALL ADD RULE NAME="Compatability Telemetry Runner" action="block" dir="out" interface="any" program="%SystemDrive%\Windows\system32\CompatTelRunner.exe" Description="Prevent CompatTelRunner Outbound Traffic." enable=yes >NUL 2>&1

 IF EXIST "%WINDIR%\System32\CompatTelRunner.exe" (
	TAKEOWN /F "%WINDIR%\System32\CompatTelRunner.exe" /A >NUL 2>&1
	ICACLS "%WINDIR%\System32\CompatTelRunner.exe" /GRANT:R *S-1-5-32-544:F /C >NUL 2>&1
	TASKKILL /IM CompatTelRunner.exe /F >NUL 2>&1
	DEL /F /Q /S "%WINDIR%\System32\CompatTelRunner.exe" >NUL 2>&1
 )
'@
        $SetupEnd = @'

POWERCFG -H OFF >NUL 2>&1
NBTSTAT -R >NUL 2>&1
IPCONFIG /FLUSHDNS >NUL 2>&1
NET STOP DNSCACHE >NUL 2>&1
NET START DNSCACHE >NUL 2>&1
DEL /F /Q /S "%ProgramData%\Microsoft\Diagnosis\ETLLogs\*" >NUL 2>&1
DEL /F /Q "%ProgramData%\Microsoft\Diagnosis\*.rbs" >NUL 2>&1
DEL /F /Q "%WINDIR%\Panther\unattend.xml" >NUL 2>&1
DEL /F /Q "%WINDIR%\System32\Sysprep\unattend.xml" >NUL 2>&1
DEL "%~f0"
'@
        If ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -eq $true) { Out-File -FilePath $SetupScript -InputObject $DefenderTasks, $XboxTasks, $FirewallRules, $SetupEnd -Append -Encoding ASCII -ErrorAction Stop }
        ElseIf ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -ne $true) { Out-File -FilePath $SetupScript -InputObject $DefenderTasks, $FirewallRules, $SetupEnd -Append -Encoding ASCII -ErrorAction Stop }
        ElseIf ($DisableDefenderComplete -ne $true -and $DisableXboxComplete -eq $true) { Out-File -FilePath $SetupScript -InputObject $XboxTasks, $FirewallRules, $SetupEnd -Append -Encoding ASCII -ErrorAction Stop }
        Else { Out-File -FilePath $SetupScript -InputObject $FirewallRules, $SetupEnd -Append -Encoding ASCII -ErrorAction Stop }
        Clear-Host
    }
    Catch
    {
        Write-Output ''
        Out-Log -Content "Failed to generate a setup and post-installation script." -Level Error
        Exit-Script
        Break
    }
}

Try
{
    If ($NoSetup) { Clear-Host }
    $Host.UI.RawUI.WindowTitle = "Cleaning-up the Image."
    Out-Log -Content "Cleaning-up the Image."
    If ($MetroApps -eq "All" -and $MetroAppsComplete -eq $true -and $ImageName -notlike "*LTSC")
    {
        Start-Process -FilePath TAKEOWN -ArgumentList ("/F `"$MountFolder\Program Files\WindowsApps`" /R") -WindowStyle Hidden -Wait
        Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Program Files\WindowsApps`" /INHERITANCE:E /GRANT `"$($Env:USERNAME):(OI)(CI)F`" /T /C") -WindowStyle Hidden -Wait
        Get-ChildItem -Path "$MountFolder\Program Files\WindowsApps\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Program Files\WindowsApps`" /SETOWNER `"NT Service\TrustedInstaller`"") -WindowStyle Hidden -Wait
        Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Program Files\WindowsApps`" /INHERITANCE:R /REMOVE `"$($Env:USERNAME)`"") -WindowStyle Hidden -Wait
    }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\Temp\PendingDeletes\*")
    {
        [void](Set-FileOwnership -Path "$MountFolder\Windows\WinSxS\Temp\PendingDeletes\*" -ErrorAction SilentlyContinue)
        Remove-Item -Path "$MountFolder\Windows\WinSxS\Temp\PendingDeletes\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\Temp\TransformerRollbackData\*")
    {
        [void](Set-FileOwnership -Path "$MountFolder\Windows\WinSxS\Temp\TransformerRollbackData\*" -ErrorAction SilentlyContinue)
        Remove-Item -Path "$MountFolder\Windows\WinSxS\Temp\TransformerRollbackData\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\ManifestCache\*" -Filter *.bin)
    {
        [void](Set-FileOwnership -Path "$MountFolder\Windows\WinSxS\ManifestCache\*.bin" -ErrorAction SilentlyContinue)
        Remove-Item -Path "$MountFolder\Windows\WinSxS\ManifestCache\*.bin" -Force -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$MountFolder\Windows\INF\*" -Filter *.log)
    {
        [void](Set-FileOwnership -Path "$MountFolder\Windows\INF\*.log" -ErrorAction SilentlyContinue)
        Remove-Item -Path "$MountFolder\Windows\INF\*.log" -Force -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$MountFolder\Windows\CbsTemp\*")
    {
        [void](Set-FileOwnership -Path "$MountFolder\Windows\CbsTemp\*" -ErrorAction SilentlyContinue)
        Remove-Item -Path "$MountFolder\Windows\CbsTemp\*" -Force -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$MountFolder\PerfLogs")
    {
        Remove-Item -Path "$MountFolder\PerfLogs" -Recurse -Force -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path ("$MountFolder\" + '$Recycle.Bin'))
    {
        Remove-Item -Path ("$MountFolder\" + '$Recycle.Bin') -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Finally
{
    $ImageHealth = (Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState
}

If ($ImageHealth -eq "Healthy")
{
    Write-Output ''
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
    $Host.UI.RawUI.WindowTitle = "Saving and Dismounting the Image."
    Write-Output ''
    Out-Log -Content "Saving and Dismounting the Image." -Level Info
    $DismountWindowsImage = @{
        Path             = $MountFolder
        Save             = $true
        CheckIntegrity   = $true
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        LogLevel         = 1
        ErrorAction      = "Stop"
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
    $Host.UI.RawUI.WindowTitle = "Rebuilding and Exporting the Image."
    Write-Output ''
    Out-Log -Content "Rebuilding and Exporting the Image." -Level Info
    $ExportInstall = "/English /Export-Image /SourceImageFile:`"${InstallWim}`" /All /DestinationImageFile:`"${WorkFolder}\install.wim`" /Compress:Max /CheckIntegrity /Quiet"
    Start-Process -FilePath DISM -ArgumentList $ExportInstall -WindowStyle Hidden -Wait -ErrorAction Stop
}
Catch
{
    Write-Output ''
    Out-Log -Content "Failed to rebuild and export the image." -Level Error
    Exit-Script
    Break
}
Finally
{
    [void](Clear-WindowsCorruptMountPoint)
}

If ($ISOIsExported -eq $true -and (Test-Path -Path $ISOMedia -PathType Container))
{
    $Host.UI.RawUI.WindowTitle = "Optimizing the Windows Setup File Structure."
    Write-Output ''
    Out-Log -Content "Optimizing the Windows Setup File Structure." -Level Info
    If (Test-Path -Path "$ISOMedia\autorun.inf") { Remove-Item -Path "$ISOMedia\autorun.inf" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\setup.exe") { Remove-Item -Path "$ISOMedia\setup.exe" -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path "$ISOMedia\*.dll" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$ISOMedia\ca") { Remove-Item -Path "$ISOMedia\ca" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\NanoServer") { Remove-Item -Path "$ISOMedia\NanoServer" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\support") { Remove-Item -Path "$ISOMedia\support" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\upgrade") { Remove-Item -Path "$ISOMedia\upgrade" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\dlmanifests") { Remove-Item -Path "$ISOMedia\sources\dlmanifests" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\etwproviders") { Remove-Item -Path "$ISOMedia\sources\etwproviders" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\inf") { Remove-Item -Path "$ISOMedia\sources\inf" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\hwcompat") { Remove-Item -Path "$ISOMedia\sources\hwcompat" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\migration") { Remove-Item -Path "$ISOMedia\sources\migration" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\replacementmanifests") { Remove-Item -Path "$ISOMedia\sources\replacementmanifests" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\servicing") { Remove-Item -Path "$ISOMedia\sources\servicing" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\servicingstackmisc") { Remove-Item -Path "$ISOMedia\sources\servicingstackmisc" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\vista") { Remove-Item -Path "$ISOMedia\sources\vista" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\xp") { Remove-Item -Path "$ISOMedia\sources\xp" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\winsetupboot.hiv") { Remove-Item -Path "$ISOMedia\sources\winsetupboot.hiv" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\en-US\setup.exe.mui") { Move-Item -Path "$ISOMedia\sources\en-US\setup.exe.mui" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\EI.CFG") { Move-Item -Path "$ISOMedia\sources\EI.CFG" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\*.clg") { Move-Item -Path "$ISOMedia\sources\*.clg" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\gatherosstate.exe") { Move-Item -Path "$ISOMedia\sources\gatherosstate.exe" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\setup.exe") { Move-Item -Path "$ISOMedia\sources\setup.exe" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\lang.ini") { Move-Item -Path "$ISOMedia\sources\lang.ini" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\pid.txt") { Move-Item -Path "$ISOMedia\sources\pid.txt" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path "$ISOMedia\sources\en-US\*.adml" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\en-US\*.mui" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\en-US\*.rtf" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\en-US\*.txt" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.dll" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.gif" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.xsl" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.bmp" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.mof" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.ini" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.cer" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.exe" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.sdb" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.txt" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.nls" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.xml" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.cat" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.inf" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.sys" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.bin" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.ait" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.admx" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.dat" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.ttf" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.cfg" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.xsd" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.rtf" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\*.xrm-ms" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$ISOMedia\setup.exe.mui") { Move-Item -Path "$ISOMedia\setup.exe.mui" -Destination "$ISOMedia\sources\en-US" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\EI.CFG") { Move-Item -Path "$ISOMedia\EI.CFG" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path "$ISOMedia\*.clg" -Recurse -Force -ErrorAction SilentlyContinue | Move-Item -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$ISOMedia\gatherosstate.exe") { Move-Item -Path "$ISOMedia\gatherosstate.exe" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\setup.exe") { Move-Item -Path "$ISOMedia\setup.exe" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\lang.ini") { Move-Item -Path "$ISOMedia\lang.ini" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\pid.txt") { Move-Item -Path "$ISOMedia\pid.txt" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Finalizing Image Optimizations."
    Write-Output ''
    Out-Log -Content "Finalizing Image Optimizations." -Level Info
    [void]($SaveFolder = New-SaveDirectory)
    If ($ISOIsExported -eq $true)
    {
        Move-Item -Path "$WorkFolder\install.wim" -Destination "$ISOMedia\sources" -Force
        If (Test-Path -Path "$WorkFolder\boot.wim") { Move-Item -Path "$WorkFolder\boot.wim" -Destination "$ISOMedia\sources" -Force }
        Move-Item -Path $ISOMedia -Destination $SaveFolder -Force
    }
    Else
    {
        Move-Item -Path "$WorkFolder\install.wim" -Destination $SaveFolder -Force
        If (Test-Path -Path "$WorkFolder\boot.wim") { Move-Item -Path "$WorkFolder\boot.wim" -Destination $SaveFolder -Force }
    }
    If (Test-Path -Path "$WorkFolder\OneDriveBackup.Zip") { Move-Item -Path "$WorkFolder\OneDriveBackup.Zip" -Destination $SaveFolder -Force }
    If (Test-Path -Path "$WorkFolder\RegistryBackup.Zip") { Move-Item -Path "$WorkFolder\RegistryBackup.Zip" -Destination $SaveFolder -Force }
    Move-Item -Path "$WorkFolder\*.txt" -Destination $SaveFolder -Force
    Move-Item -Path "$WorkFolder\*.log" -Destination $SaveFolder -Force
    Start-Sleep 3
    $Timer.Stop()
    If ($Error.Count.Equals(0))
    {
        Write-Output ''
        Write-Host "$OScript completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($Error.Count)] errors." -ForegroundColor White
        Start-Sleep 3
        Write-Output ''
    }
    Else
    {
        $SaveErrorLog = Join-Path -Path $Env:TEMP -ChildPath ErrorLog.log
        Set-Content -Path $SaveErrorLog -Value $Error.ToArray() -Force
        Move-Item -Path $Env:TEMP\ErrorLog.log -Destination $SaveFolder -Force
        Write-Output ''
        Write-Warning "$OScript completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($Error.Count)] errors."
        Start-Sleep 3
        Write-Output ''
    }
}
Finally
{
    $TimeStamp = Get-Date -Format "MM-dd-yyyy hh:mm:ss tt"
    @"

***************************************************************************************************
			$($OScript) completed at [$($TimeStamp)]
***************************************************************************************************
"@ | Out-File -FilePath $LogFile -Append -Encoding ASCII
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    Remove-Item -Path $DISMLog -Force -ErrorAction SilentlyContinue
    Move-Item -Path $LogFile -Destination $SaveFolder -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    $Host.UI.RawUI.WindowTitle = "Optimizations Complete."
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
