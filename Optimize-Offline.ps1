#Requires -RunAsAdministrator
#Requires -Version 5
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for 64-bit Windows 10 builds RS2, RS3 and RS4.
	
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
		The full path to a Windows Installation ISO or an install WIM file.
	
	.PARAMETER Index
		If using a multi-index image, specify the index of the image.
	
	.PARAMETER Build
		The build number of the Windows image being optimized.
	
	.PARAMETER SelectApps
		Populates and outputs a Gridview list of all Provisioned Application Packages for selected removal.
	
	.PARAMETER AllApps
		Automatically removes all Provisioning Application Packages.
	
	.PARAMETER SystemApps
		Outputs System Applications that can be removed, thus preventing them from being provisioned and installed during Windows Setup.
	
	.PARAMETER SetRegistry
		Sets optimized registry values into the offline registry hives.
	
	.PARAMETER Harden
		Increases device security and further restricts access to such things as system and app sensors.
	
	.PARAMETER Drivers
		The full path to a collection of driver packages, or a driver .inf file, to be injected into the image.
	
	.PARAMETER OnDemandPackages
		Populates and outputs a Gridview list of all OnDemand and Language Packages for selected removal.
	
	.PARAMETER OptionalFeatures
		Populates and outputs a Gridview list of all Optional Features for selected removal.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\install.wim" -Build 16299 -AllApps -SetRegistry -Drivers "E:\DriverFolder" -OptionalFeatures
	
	.NOTES
        	If you are unsure about a System App, do not remove it.
        
	.NOTES
		===========================================================================
		Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.150
		Created on:   	11/30/2017
		Created by:     BenTheGreat
		Contact:        Ben@Omnic.Tech
		Filename:     	Optimize-Offline.ps1
		Version:        3.1.0.2
		Last updated:	05/27/2018
		===========================================================================
#>
[CmdletBinding()]
[OutputType([System.Object])]
Param
(
    [Parameter(Mandatory = $true,
        HelpMessage = 'The full path to a Windows Installation ISO or an install WIM file.')]
    [ValidateScript( {
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
    [ValidateRange(15063, 17134)]
    [int]$Build,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Provisioned Application Packages for selected removal.')]
    [Alias('Select')]
    [switch]$SelectApps,
    [Parameter(HelpMessage = 'Automatically removes all Provisioning Application Packages.')]
    [Alias('All')]
    [switch]$AllApps,
    [Parameter(HelpMessage = 'Outputs System Applications that can be removed, thus preventing them from being provisioned and installed during Windows Setup.')]
    [switch]$SystemApps,
    [Parameter(HelpMessage = 'Sets optimized registry values into the offline registry hives.')]
    [Alias('RegEdit')]
    [switch]$SetRegistry,
    [Parameter(HelpMessage = 'Increases device security and further restricts access to such things as system and app sensors.')]
    [switch]$Harden,
    [Parameter(Mandatory = $false,
        HelpMessage = 'The path to a collection of driver packages, or a driver .inf file, to be injected into the image.')]
    [ValidateScript( { Test-Path $(Resolve-Path -Path $_) })]
    [string]$Drivers,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all OnDemand and Language Packages for selected removal.')]
    [Alias('OnDemand')]
    [switch]$OnDemandPackages,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Optional Features for selected removal.')]
    [Alias('Features')]
    [switch]$OptionalFeatures
)
#region Script Variables
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$Host.UI.RawUI.WindowTitle = "Optimizing Image."
$ProgressPreference = 'SilentlyContinue'
$Script = "Optimize-Offline"
$LogFile = "$Env:TEMP\Optimize-Offline.log"
$DISMLog = "$Env:TEMP\DISM.log"
$ProvisionedAppList = [System.Collections.ArrayList]@()
$OnDemandPackageList = [System.Collections.ArrayList]@()
$OptionalFeaturesList = [System.Collections.ArrayList]@()
$SystemAppsList = [System.Collections.ArrayList]@()
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
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = "Info"
    )
    Begin {
        $VerbosePreference = "Continue"
    }
    Process {
        If (!(Test-Path -Path $LogFile)) {
            Write-Verbose "Logging has started."
            Write-Output ''
            Start-Sleep 2
            [void](New-Item -Path $LogFile -ItemType File -Force)
        }
        $DateFormat = Get-Date -Format "[MM-dd-yyyy hh:mm:ss]"
        Switch ($Level) {
            'Info' { Write-Verbose $Output; $LogLevel = "INFO:" }
            'Warning' { Write-Warning $Output; $LogLevel = "WARNING:" }
            'Error' { Write-Error $Output; $LogLevel = "ERROR:" }
        }
    }
    End {
        "$DateFormat $LogLevel $Output" | Out-File -FilePath $LogFile -Append
    }
}

Function Invoke-ProcessPrivilege {
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
    Begin {
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
'@ -Language CSharp
		
        $CurProcess = Get-Process -Id $Process
    }
    Process {
        [AccessTokens]::AdjustPrivilege($CurProcess.Handle, $Privilege, !$Disable)
    }
    End {
        $CurProcess.Close()
    }
}

Function Set-RegistryOwner {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$SubKey
    )
	
    Begin {
        $TakeOwnership = "SeTakeOwnershipPrivilege"
    }
    Process {
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

Function Set-FileOwnership {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        $Path
    )
    Invoke-Expression -Command ('TAKEOWN /F $Path /A')
    $ACL = Get-Acl -Path $Path
    $SID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $Admin = $SID.Translate([System.Security.Principal.NTAccount])
    $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Admin, "FullControl", "None", "None", "Allow")))
    $ACL | Set-Acl -Path $Path
}

Function Set-FolderOwnership {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        $Path
    )
    Set-FileOwnership -Path $Path
    ForEach ($Object In Get-ChildItem -Path $Path -Recurse -Force) {
        If (Test-Path -Path $Object -PathType Container) {
            Set-FolderOwnership -Path $Object.FullName
        }
        Else {
            Set-FileOwnership -Path $Object.FullName
        }
    }
}

Function New-WorkDirectory {
    $WorkDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "WorkOffline_$(Get-Random)"))
    $WorkDir = Get-Item -LiteralPath $PSScriptRoot\$WorkDir -Force
    $WorkDir
}

Function New-TempDirectory {
    $TempDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "TempOffline_$(Get-Random)"))
    $TempDir = Get-Item -LiteralPath $PSScriptRoot\$TempDir -Force
    $TempDir
}

Function New-ImageDirectory {
    $ImageDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "ImageOffline_$(Get-Random)"))
    $ImageDir = Get-Item -LiteralPath $PSScriptRoot\$ImageDir -Force
    $ImageDir
}

Function New-MountDirectory {
    $MountDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "MountOffline_$(Get-Random)"))
    $MountDir = Get-Item -LiteralPath $PSScriptRoot\$MountDir -Force
    $MountDir
}

Function New-SaveDirectory {
    $SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
    $SaveDir = Get-Item -LiteralPath $PSScriptRoot\$SaveDir
    $SaveDir
}

Function Mount-OfflineHives {
    Invoke-Expression -Command ('REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\Windows\System32\config\software"')
    Invoke-Expression -Command ('REG LOAD HKLM\WIM_HKLM_SYSTEM "$MountFolder\Windows\System32\config\system"')
    Invoke-Expression -Command ('REG LOAD HKLM\WIM_HKCU "$MountFolder\Users\Default\NTUSER.DAT"')
    Invoke-Expression -Command ('REG LOAD HKLM\WIM_HKU_DEFAULT "$MountFolder\Windows\System32\config\default"')
}

Function Dismount-OfflineHives {
    [System.GC]::Collect()
    Invoke-Expression -Command ('REG UNLOAD HKLM\WIM_HKLM_SOFTWARE')
    Invoke-Expression -Command ('REG UNLOAD HKLM\WIM_HKLM_SYSTEM')
    Invoke-Expression -Command ('REG UNLOAD HKLM\WIM_HKCU')
    Invoke-Expression -Command ('REG UNLOAD HKLM\WIM_HKU_DEFAULT')
}

Function Test-OfflineHives {
    @("HKLM:\WIM_HKLM_SOFTWARE", "HKLM:\WIM_HKLM_SYSTEM", "HKLM:\WIM_HKCU", "HKLM:\WIM_HKU_DEFAULT") |
        ForEach { If (Test-Path -Path $_) { $HivesLoaded = $true } }; Return $HivesLoaded
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
    $SaveDir = [void](New-Item -Path $PSScriptRoot -Name Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]" -ItemType Directory -Force); $SaveDir
    If ($Error.Count) {
        $ErrorLog = Join-Path -Path $Env:TEMP -ChildPath "ErrorLog.log"
        Set-Content -Path $ErrorLog -Value $Error.ToArray() -Force
        Move-Item -Path $ErrorLog -Destination $SaveDir -Force
    }
    Move-Item -Path $LogFile -Destination $SaveDir -Force
    Move-Item -Path $DISMLog -Destination $SaveDir -Force
    If ($SetRegistry -or $Harden) {
        Move-Item -Path "$WorkFolder\Registry-Optimizations.log" -Destination $SaveDir -Force
    }
    Remove-Item -Path $WorkFolder -Recurse -Force
    Remove-Item -Path $TempFolder -Recurse -Force
    Remove-Item -Path $ImageFolder -Recurse -Force
    Remove-Item -Path $MountFolder -Recurse -Force
}

Function New-Container {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    If (!(Test-Path -Path $Path)) {
        [void](New-Item -Path $Path -ItemType Directory -Force)
    }
}
#endregion Helper Functions

If (!(Test-Admin)) { Write-Warning "Administrative access is required. Please re-launch $Script with elevation."; Break }

If ($SelectApps -and $AllApps) { Write-Warning "The SelectApps switch and AllApps switch cannot be enabled at the same time."; Break }

If ($SetRegistry -and $Harden) { Write-Warning "The SetRegistry switch and Hardened switch cannot be enabled at the same time."; Break }

If (([IO.FileInfo]$ImagePath).Extension -eq ".ISO") {
    $ImagePath = (Resolve-Path -Path $ImagePath).ProviderPath
    $MountImage = Mount-DiskImage -ImagePath $ImagePath -StorageType ISO -PassThru
    $DriveLetter = ($MountImage | Get-Volume).DriveLetter
    $InstallWim = "$($DriveLetter):\sources\install.wim"
    $BootWim = "$($DriveLetter):\sources\boot.wim"
    If ((Test-Path -Path $InstallWim -PathType Leaf) -and (Test-Path -Path $BootWim -PathType Leaf)) {
        Write-Verbose "Copying WIM from $(Split-Path -Path $ImagePath -Leaf)" -Verbose
        [void]($MountFolder = New-MountDirectory)
        [void]($ImageFolder = New-ImageDirectory)
        [void]($WorkFolder = New-WorkDirectory)
        [void]($TempFolder = New-TempDirectory)
        Invoke-Expression -Command ('ATTRIB.EXE +H $MountFolder')
        Invoke-Expression -Command ('ATTRIB.EXE +H $ImageFolder')
        Invoke-Expression -Command ('ATTRIB.EXE +H $WorkFolder')
        Invoke-Expression -Command ('ATTRIB.EXE +H $TempFolder')
        Copy-Item -Path $InstallWim -Destination $ImageFolder -Force
        $InstallWim = Get-Item -Path "$ImageFolder\install.wim" -Force
        Set-ItemProperty -Path $InstallWim -Name IsReadOnly -Value $false
        Dismount-DiskImage -ImagePath $ImagePath -StorageType ISO
    }
    Else {
        Write-Warning "$(Split-Path -Path $ImagePath -Leaf) does not contain valid Windows Installation media."
        Remove-Item -Path $MountFolder -Recurse -Force
        Remove-Item -Path $ImageFolder -Recurse -Force
        Remove-Item -Path $WorkFolder -Recurse -Force
        Remove-Item -Path $TempFolder -Recurse -Force
        Break
    }
}
ElseIf (([IO.FileInfo]$ImagePath).Extension -eq ".WIM") {
    If (Test-Path -LiteralPath $ImagePath -Filter "install.wim") {
        $ImagePath = (Resolve-Path -Path $ImagePath).ProviderPath
        Write-Verbose "Copying WIM from $(Split-Path -Path $ImagePath -Parent)" -Verbose
        [void]($MountFolder = New-MountDirectory)
        [void]($ImageFolder = New-ImageDirectory)
        [void]($WorkFolder = New-WorkDirectory)
        [void]($TempFolder = New-TempDirectory)
        Invoke-Expression -Command ('ATTRIB.EXE +H $MountFolder')
        Invoke-Expression -Command ('ATTRIB.EXE +H $ImageFolder')
        Invoke-Expression -Command ('ATTRIB.EXE +H $WorkFolder')
        Invoke-Expression -Command ('ATTRIB.EXE +H $TempFolder')
        Copy-Item -Path $ImagePath -Destination $ImageFolder -Force
        $InstallWim = Get-Item -Path "$ImageFolder\install.wim" -Force
        If ($InstallWim.IsReadOnly) { Set-ItemProperty -Path $InstallWim -Name IsReadOnly -Value $false }
    }
    Else {
        Write-Warning "$ImagePath is not labeled as an install.wim"
        Remove-Item -Path $MountFolder -Recurse -Force
        Remove-Item -Path $ImageFolder -Recurse -Force
        Remove-Item -Path $WorkFolder -Recurse -Force
        Remove-Item -Path $TempFolder -Recurse -Force
        Break
    }
}

If (Test-Path -Path "$Env:windir\Logs\DISM\dism.log") { Remove-Item -Path "$Env:windir\Logs\DISM\dism.log" -Force }

If (Test-Path -Path $DISMLog) { Remove-Item -Path $DISMLog -Force }

If (Test-Path -Path $LogFile) { Remove-Item -Path $LogFile -Force }

Try {
    If ((Get-WindowsImage -ImagePath $InstallWim -Index $Index -LogPath $DISMLog).Version -notlike "10.*") { Break }
}
Catch {
    Write-Output ''
    Write-Error "The supplied image is not Windows 10 and is not supported."
    Remove-Item -Path $MountFolder -Recurse -Force
    Remove-Item -Path $ImageFolder -Recurse -Force
    Remove-Item -Path $WorkFolder -Recurse -Force
    Remove-Item -Path $TempFolder -Recurse -Force
    Break
}

Try {
    $GetBuild = (Get-WindowsImage -ImagePath $InstallWim -Index $Index -LogPath $DISMLog).Build
    If ($GetBuild -lt '15063') {
        Write-Output ''
        Write-Error "The image build [$($GetBuild.ToString())] is not supported." -ErrorAction Stop
    }
    Else {
        Write-Output ''
        Write-Output "The image build [$($GetBuild.ToString())] is supported."
        Start-Sleep 3
        Clear-Host
        $Error.Clear()
        Write-Log -Output "Mounting Image." -Level Info
        $MountWindowsImage = @{
            ImagePath        = $InstallWim
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

If ($ImageIsMounted -eq $true) {
    Write-Output ''
    Write-Log -Output "Verifying image health." -Level Info
    $StartHealthCheck = (Repair-WindowsImage -Path $MountFolder -CheckHealth -LogPath $DISMLog)
    If ($StartHealthCheck.ImageHealthState -eq "Healthy") {
        Write-Output ''
        Write-Output "The image is healthy."
        Start-Sleep 3
        Clear-Host
    }
    Else {
        Write-Output ''
        Write-Log -Output "The image has been flagged for corruption. Further servicing is required before the image can be optimized." -Level Error
        Exit-Script
        Break
    }
}

If ($SelectApps) {
    Try {
        $GetAppx = Get-AppxProvisionedPackage -Path $MountFolder
        $Int = 1
        ForEach ($Appx In $GetAppx) {
            $GetAppx = New-Object -TypeName PSObject
            $GetAppx | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $GetAppx | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Appx.DisplayName
            $GetAppx | Add-Member -MemberType NoteProperty -Name PackageName -Value $Appx.PackageName
            $Int++
            [void]$ProvisionedAppList.Add($GetAppx)
        }
        $RemoveAppx = $ProvisionedAppList | Out-GridView -Title "Remove Provisioned App Packages." -PassThru
        $PackageName = $RemoveAppx.PackageName
        If ($RemoveAppx) {
            $PackageName | ForEach {
                Write-Log -Output "Removing Provisioned App Package: $($_.Split('_')[0])" -Level Info
                [void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $($_) -ScratchDirectory $TempFolder -LogPath $DISMLog -ErrorAction Stop)
            }
        }
        $Int = ''
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to remove all selected Provisioned App Packages." -Level Error
        Exit-Script
        Break
    }
}

If ($AllApps) {
    Try {
        Get-AppxProvisionedPackage -Path $MountFolder -ScratchDirectory $TempFolder -LogPath $DISMLog | ForEach {
            Write-Log -Output "Removing Provisioned App Package: $($_.DisplayName)" -Level Info
            [void](Remove-AppxProvisionedPackage -Path $MountFolder -PackageName $($_.PackageName) -ScratchDirectory $TempFolder -LogPath $DISMLog -ErrorAction Stop)
        }
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to remove all Provisioned App Packages." -Level Error
        Exit-Script
        Break
    }
}

If ($SystemApps) {
    Try {
        Clear-Host
        Write-Warning "Do NOT remove any System Applications if you are unsure of its affects on a live installation."
        Start-Sleep 5
        Write-Output ''
        [void](Invoke-Expression -Command ('REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\Windows\System32\config\software"'))
        $InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
        $InboxApps = (Get-ChildItem -Path $InboxAppsKey).Name.Split('\') | Where { $_ -like "*Microsoft.*" }
        $SelectSystemApps = $InboxApps | Select-Object -Property `
        @{ Label = 'Name'; Expression = { ($_.Split('_')[0]) } },
        @{ Label = 'PackageName'; Expression = { ($_) } } |
            Out-GridView -Title "Remove System Applications." -PassThru
        $AppName = $SelectSystemApps.Name
        $AppPackage = $SelectSystemApps.PackageName
        If ($SelectSystemApps) {
            Clear-Host
            $AppPackage | ForEach {
                $FullKeyPath = "$($InboxAppsKey)\" + $($_)
                $AppKey = $FullKeyPath.Replace("HKLM:", "HKLM")
                Write-Log -Output "Removing System Application: $($_.Split('_')[0])" -Level Info
                [void](Invoke-Expression -Command ('REG DELETE $AppKey /F') -ErrorAction Stop)
                [void]$SystemAppsList.Add($($_.Split('_')[0]))
                Start-Sleep 2
            }
        }
        $SystemAppsComplete = $true
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to remove required registry subkeys." -Level Error
        Exit-Script
        Break
    }
    Finally {
        [void](Invoke-Expression -Command ('REG UNLOAD HKLM\WIM_HKLM_SOFTWARE'))
    }
}

If ($SetRegistry -or $Harden) {
    #region Default Registry Optimizations
    If (Test-Path -Path "$WorkFolder\Registry-Optimizations.log") {
        Remove-Item -Path "$WorkFolder\Registry-Optimizations.log" -Force
    }
    Clear-Host
    Write-Log -Output "Enhancing system security, usability and performance with registry optimizations." -Level Info
    Try {
        [void](Mount-OfflineHives)
        #****************************************************************
        Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Cortana Outgoing Network Traffic." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling System Telemetry and Data Collecting." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Office 2016 Telemetry and Logging." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling 'Find My Device'." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling PIN requirement for pairing devices." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling HomeGroup Services." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupListener" -Name "Start" -Value 4 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\HomeGroupProvider" -Name "Start" -Value 4 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Text Suggestions and Screen Monitoring." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Steps Recorder." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Compatibility Assistant." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Error Reporting." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling WiFi Sense." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Windows Asking for Feedback." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling the Password Reveal button." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Windows Media Player Statistics Tracking." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Microsoft Windows Media Digital Rights Management." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Activity History." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord
        #***************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Advertisement ID." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
        #***************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling the MeltDown (CVE-2017-5754) Compatibility Flag." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "CADCA5FE-87D3-4B96-B7FB-A231484277CC" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Explorer Tips, Sync Notifications and Document Tracking." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling System Advertisements and Windows Spotlight." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Toast Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Feature Advertisement Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoBalloonFeatureAdvertisements" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling System Tray Promotion Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoSystraySystemPromotion" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Typing Data Telemetry." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Automatic Download of Content, Ads and Suggestions." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        @("ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RotatingLockScreenEnabled",
            "RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContent-202914Enabled",
            "SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled", "SubscribedContent-310091Enabled",
            "SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314381Enabled", "SubscribedContent-314559Enabled", "SubscribedContent-314563Enabled",
            "SubscribedContent-338380Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled",
            "SubscribedContent-353698Enabled") | ForEach {
            Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_ -Value 0 -Type DWord -ErrorAction Stop
        }
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceAppSuggestionsEnabled" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Explorer Ads and Tips." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Windows 'Getting to Know Me' and Tablet Mode Keylogging" >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Notifications on Lock Screen." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Lock Screen Camera and Overlays." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Map Auto Downloads." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Speech Model Updates." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling First Log-on Animation." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling the Windows Insider Program." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Changing Search Bar to Magnifying Glass Icon." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Moving Drive Letter Before Drive Label." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling Dark Theme for Settings and Modern Apps." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Increasing Taskbar and Theme Transparency." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling 'Shortcut' text for Shortcuts." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value 00000000 -Type Binary
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling Explorer opens to This PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Removing Windows Store Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Removing Windows Mail Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling the Windows Mail Application." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord
        #****************************************************************
        If ($Build -ge '16273') {
            #****************************************************************
            Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
            Write-Output "Removing People Icon from Taskbar" >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
            Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type DWord
        }
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling 'How do you want to open this file?' prompt." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Switching to Smaller Control Panel Icons." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding This PC Icon to Desktop." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
        $NewStartPanel = @{
            Path  = "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
            Name  = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
            Value = 0
            Type  = "DWord"
        }
        Set-ItemProperty @NewStartPanel
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
        $ClassicStartMenu = @{
            Path  = "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
            Name  = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
            Value = 0
            Type  = "DWord"
        }
        Set-ItemProperty @ClassicStartMenu
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Reboot to Recovery' to My PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-RegistryOwner -SubKey "WIM_HKLM_SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell"
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
            Value = "SHUTDOWN.EXE -R -O -F -T 00"
            Type  = "String"
        }
        Set-ItemProperty @RecoveryCommand
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Live Tiles." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Connected Drive Autoplay and Autorun." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord
        #****************************************************************
        If ($Build -ge '16273') {
            #****************************************************************
            Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
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
        ElseIf ($Build -lt '16273') {
            #****************************************************************
            Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
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
        If ($Build -ge "15063") {
            #****************************************************************
            Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Restoring Windows Photo Viewer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        @(".bmp", ".gif", ".jfif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".wdp") | ForEach {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_"
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids"
            Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$_" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String
            Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$_\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value (New-Object Byte[] 0) -Type Binary
        }
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Removing 'Share' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -Value "" -Type String
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Removing 'Give Access To' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" -Value "" -Type String
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Removing 'Cast To Device' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "" -Type String
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Hiding Recently and Frequently Used Items in Explorer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Hiding all User Folders from This PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        If ($Build -ge '16273') {
            Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction Stop
            Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction Stop
        }
        @("B4BFCC3A-DB2C-424C-B029-7FE99A87C641", "A8CDFF1C-4878-43be-B5FD-F8091C1C60D0", "d3162b92-9365-467a-956b-92703aca08af", "374DE290-123F-4565-9164-39C4925E467B",
            "088e3905-0323-4b02-9826-5d99428e115f", "1CF1260C-4DD0-4ebb-811F-33C572699FDE", "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de", "3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA",
            "24ad3ad4-a569-4530-98e1-ab02f9417aa8", "A0953C92-50DC-43bf-BE83-3742FED03C9C", "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a") | ForEach {
            Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{$_}" -Force -ErrorAction Stop
            Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{$_}" -Force -ErrorAction Stop
        }
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Removing Drives from the Navigation Pane." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}"
        Remove-Item "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}"
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Cleaning up Control Panel CPL links." >> "$WorkFolder\Registry-Optimizations.log"
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
            Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
            Write-Output "Cleaning-up Immersive Control Panel Settings Links." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            If ($SystemAppsComplete -eq $true -and $SystemAppsList -contains "Microsoft.Windows.SecHealthUI") {
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
            Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
            Write-Output "Cleaning-up Immersive Control Panel Settings Links." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            If ($SystemAppsComplete -eq $true -and $SystemAppsList -contains "Microsoft.Windows.SecHealthUI") {
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Recent Document History." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Automatic Sound Reduction." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling Windows to use latest .NET Framework." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling the Fraunhofer IIS MPEG Layer-3 (MP3) Codec." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force
        Remove-Item -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type ExpandString
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type ExpandString
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling Full Base Reset." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" -Name "DisableResetbase" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Enabling the removal of the 'DefaultUser0' ghost account." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-RegistryOwner -SubKey "WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}"
        $DefaultUser0 = @{
            Path        = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}"
            Name        = "AutoElevationAllowed"
            Value       = 1
            Type        = "DWord"
            ErrorAction = "Stop"
        }
        Set-ItemProperty @DefaultUser0
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Sticky Keys." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys"
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response"
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value 122 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value 58 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Increasing Icon Cache Size." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 4096 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Hibernation." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Session Manager\Power" -Name "HibernteEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Open with Notepad' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        [void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" /v "Icon" /t REG_SZ /d "Notepad.exe,-2" /f)
        [void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" /ve /t REG_SZ /d "Notepad.exe %1" /f)
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Copy-Move' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB630-2971-11D1-A18C-00C04FD75D13}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB631-2971-11D1-A18C-00C04FD75D13}" -ErrorAction Stop
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Extended Disk Clean-up' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up\command" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up" -Name "Icon" -Value "CleanMgr.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up\command" -Name "(default)" -Value "WScript C:\Windows\Extended-Disk-Cleanup.vbs" -Type String -ErrorAction Stop
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Create Quick Restore Point' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point\command" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" -Name "Icon" -Value "SystemPropertiesProtection.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point\command" -Name "(default)" -Value "WScript C:\Windows\Create-Restore-Point.vbs" -Type String -ErrorAction Stop
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Elevated Command-Prompt' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Icon" -Value "CMD.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "SeparatorAfter" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Position" -Value "Bottom" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Icon" -Value "CMD.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "SeparatorAfter" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Position" -Value "Bottom" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString -ErrorAction Stop
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Elevated PowerShell' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -Name "(default)" -Value "Powershell Start-Process PowerShell -Verb RunAs -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''`"%V`"'''" -Type ExpandString -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -Name "(default)" -Value "Powershell Start-Process PowerShell -Verb RunAs -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''`"%V`"'''" -Type ExpandString -ErrorAction Stop
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Install CAB' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs\Command" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -Name "(default)" -Value "Install" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -Name "HasLUAShield" -Value "" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs\Command" -Name "(default)" -Value "CMD /K DISM /ONLINE /ADD-PACKAGE /PACKAGEPATH:`"%1`"" -Type ExpandString -ErrorAction Stop
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Adding 'Restart Explorer' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Icon" -Value "Explorer.exe" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Position" -Value "Bottom" -Type String -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -Name "(default)" -Value "Restart-Explorer.cmd" -Type String -ErrorAction Stop
        #****************************************************************
        [void](Dismount-OfflineHives)
        $SetRegistryComplete = $true
    }
    Catch {
        Write-Output ''
        Write-Error "Failed to apply all Registry Optimizations."
        Exit-Script
        Break
    }
    #endregion Default Registry Optimizations
}

If ($Harden) {
    #region Hardened Registry Optimizations
    Try {
        Write-Output ''
        Write-Log -Output "Adding Hardened Registry Values." -Level Info
        [void](Mount-OfflineHives)
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling System and Settings Syncronization." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        @("Accessibility", "AppSync", "BrowserSettings", "Credentials", "DesktopTheme", "Language", "PackageState", "Personalization", "StartLayout", "Windows") | ForEach {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$_"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Location Sensors, App Syncronization and Non-Explicit App Access." >> "$WorkFolder\Registry-Optimizations.log"
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
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Shared Experiences." >> "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Value 0 -Type DWord
        #****************************************************************
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling SmartScreen." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Disabling Windows Auto-Update and Auto-Reboot." >> "$WorkFolder\Registry-Optimizations.log"
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
        Write-Output '' >> "$WorkFolder\Registry-Optimizations.log"
        Write-Output "Link-Local Multicast Name Resolution (LLMNR) protocol." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
        #****************************************************************
        [void](Dismount-OfflineHives)
        $HardenRegistryComplete = $true
        Start-Sleep 3
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to apply Hardened Registry Settings." -Level Error
        Exit-Script
        Break
    }
}
#endregion Default Hardened Registry Optimizations

If ($SetRegistryComplete -eq $true) {
	
    $CreateRestorePoint = @'
Function SystemOS    
    Set objWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & ".\root\cimv2")
    Set colOS = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
    For Each objOS in colOS
        If instr(objOS.Caption, "Windows 10") Then
        	SystemOS = "Windows 10"   
        End If
	Next
End Function

If SystemOS = "Windows 10" Then
	If WScript.Arguments.length =0 Then
  		Set objShell = CreateObject("Shell.Application")
		objShell.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " Run", , "runas", 1 
         Else  
               const HKEY_LOCAL_MACHINE = &H80000002
               strComputer = "."
               Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
               strKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
               strValueName = "SystemRestorePointCreationFrequency"
               oReg.SetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,0  	
        CreateSRP  
  	End If
End If

Sub CreateSRP
	Set SRP = getobject("winmgmts:\\.\root\default:Systemrestore")
	sDesc = "Manual Restore Point"
	sDesc = InputBox ("Enter a restore point description.", "Manually Create System Restore Point","Manual Restore Point")
	If Trim(sDesc) <> "" Then
		sOut = SRP.createrestorepoint (sDesc, 0, 100)
		If sOut <> 0 Then
	 		WScript.echo "Error " & sOut & ": Unable to create Restore Point."
                else 
                MsgBox "The restore point " & Chr(34) & sDesc & Chr(34) & " was created successfully.", 0, "Manually Create System Restore Point"
		End If
	End If
End Sub
'@
	
    $ExtendedCleanup = @'
If WScript.Arguments.length =0 Then
  Set CleanupObj = CreateObject("Shell.Application")
  CleanupObj.ShellExecute "Wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " Run", , "runas", 1
Else
   Set Cleanup = WScript.CreateObject("WSCript.Shell")
   Cleanup.run ("CMD.EXE /C CLEANMGR /SAGESET:65535 & CLEANMGR /SAGERUN:65535"), 0
End If
'@
	
    $RestartExplorer = @'
@ECHO OFF
ECHO:
ECHO Killing Explorer
ECHO:
TASKKILL /F /IM Explorer.exe
ECHO:
ECHO Ready to restart Explorer
TIMEOUT /T -1
START "Starting Explorer" Explorer.exe
TIMEOUT /T 5 /NOBREAK >NUL
ECHO:
ECHO Explorer has started successfully.
TIMEOUT /T 3 /NOBREAK >NUL
EXIT
'@
	
    Out-File -FilePath "$MountFolder\Windows\Create-Restore-Point.vbs" -InputObject $CreateRestorePoint
    Out-File -FilePath "$MountFolder\Windows\Extended-Disk-Cleanup.vbs" -InputObject $ExtendedCleanup
    Out-File -FilePath "$MountFolder\Windows\Restart-Explorer.cmd" -InputObject $RestartExplorer -Encoding ASCII
}

Try {
    Write-Output ''
    Write-Log -Output "Applying a custom Start Menu and Taskbar Layout." -Level Info
    Start-Sleep 3
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
    Out-File -FilePath "$MountFolder\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -InputObject $LayoutTemplate
    Write-Output ''
    Write-Log -Output "Creating required Shortcuts." -Level Info
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
Catch {
    Write-Output ''
    Write-Log -Output "Failed to create required shortcuts." -Level Error
    Exit-Script
    Break
}

If ($SelectApps -or $AllApps) {
    Try {
        Write-Output ''
        Write-Log -Output "Disabling removed Provisoned App Package services." -Level Info
        If ((Get-AppxProvisionedPackage -Path $MountFolder | Where { $_.DisplayName -Match "Microsoft.Wallet" }).Count.Equals(0)) {
            [void](Mount-OfflineHives)
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            [void](Dismount-OfflineHives)
        }
        If ((Get-AppxProvisionedPackage -Path $MountFolder | Where { $_.DisplayName -Match "Microsoft.WindowsMaps" }).Count.Equals(0)) {
            [void](Mount-OfflineHives)
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
            [void](Dismount-OfflineHives)
        }
    }
    Catch {
        Write-Output ''
        Write-Log -Output "An error occurred removing Provisoned App Package services." -Level Error
        Exit-Script
        Break
    }
}

If ($SystemAppsComplete -eq $true -and $SystemAppsList -contains "Microsoft.Windows.SecHealthUI" -or $HardenRegistryComplete -eq $true) {
    Write-Output ''
    Write-Log -Output "Disabling remaining Windows Defender services and drivers." -Level Info
    Try {
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -ErrorAction Stop
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
        If ((Get-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue) -match "SecurityHealth") {
            [void](Remove-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction Stop)
        }
        @("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach {
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        }
        [void](Dismount-OfflineHives)
        $DisableDefenderComplete = $true
        Start-Sleep 3
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to disable remaining Windows Defender services and drivers." -Level Error
        Exit-Script
        Break
    }
}

If ($Build -ge '16273') {
    Write-Output ''
    Write-Log -Output "Disabling Windows-Defender-Default-Defintions." -Level Info
    $DisableDefenderFeature = @{
        Path             = $MountFolder
        FeatureName      = "Windows-Defender-Default-Definitions"
        ScratchDirectory = $TempFolder
        LogPath          = $DISMLog
    }
    [void](Disable-WindowsOptionalFeature @DisableDefenderFeature)
}

If ($AllApps -or $SystemAppsList -contains "Microsoft.XboxGameCallableUI" -or $HardenRegistryComplete -eq $true -or ((Get-AppxProvisionedPackage -Path $MountFolder | Where { $_.PackageName -like "*Xbox*" }).Count -lt 5)) {
    Write-Output ''
    Write-Log -Output "Disabling remaining Xbox services and drivers." -Level Info
    Try {
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord
        @("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach {
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$_" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        }
        [void](Dismount-OfflineHives)
        Start-Sleep 3
        $DisableXboxComplete = $true
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to disable remaining Xbox services and drivers." -Level Error
        Exit-Script
        Break
    }
}

If ($OnDemandPackages) {
    Try {
        $GetOnDemand = Get-WindowsPackage -Path $MountFolder
        $Int = 1
        ForEach ($Package In $GetOnDemand) {
            $GetOnDemand = New-Object -TypeName PSObject
            $GetOnDemand | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $GetOnDemand | Add-Member -MemberType NoteProperty -Name PackageName -Value $Package.PackageName
            $GetOnDemand | Add-Member -MemberType NoteProperty -Name PackageState -Value $Package.PackageState
            $Int++
            [void]$OnDemandPackageList.Add($GetOnDemand)
        }
        $RemoveOnDemand = $OnDemandPackageList | Out-GridView -Title "Select any OnDemand Packages to remove." -PassThru
        $PackageName = $RemoveOnDemand.PackageName
        If ($RemoveOnDemand) {
            Clear-Host
            $PackageName | ForEach {
                $Append = $_.Replace("Package", "").Split('~')[0]
                Write-Log -Output "Removing Windows Package: $($Append.TrimEnd('-'))" -Level Info
                $RemoveOnDemandPackage = @{
                    Path             = $MountFolder
                    PackageName      = $_
                    ScratchDirectory = $TempFolder
                    LogPath          = $DISMLog
                    ErrorAction      = "Stop"
                }
                [void](Remove-WindowsPackage @RemoveOnDemandPackage)
            }
        }
        $Int = ''
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to Remove all OnDemand Packages." -Level Error
        Exit-Script
        Break
    }
}

If ($OptionalFeatures) {
    Try {
        $GetFeatures = Get-WindowsOptionalFeature -Path $MountFolder
        $Int = 1
        ForEach ($Feature In $GetFeatures) {
            $GetFeatures = New-Object -TypeName PSObject
            $GetFeatures | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $GetFeatures | Add-Member -MemberType NoteProperty -Name FeatureName -Value $Feature.FeatureName
            $GetFeatures | Add-Member -MemberType NoteProperty -Name State -Value $Feature.State
            $Int++
            [void]$OptionalFeaturesList.Add($GetFeatures)
        }
        $RemoveFeatures = $OptionalFeaturesList | Out-GridView -Title "Disable Optional Features." -PassThru
        $FeatureName = $RemoveFeatures.FeatureName
        If ($RemoveFeatures) {
            Clear-Host
            $FeatureName | ForEach {
                Write-Log -Output "Disabling Optional Feature: $($_)" -Level Info
                $DisableWindowsOptionalFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $_
                    ScratchDirectory = $TempFolder
                    LogPath          = $DISMLog
                    ErrorAction      = "Stop"
                }
                [void](Disable-WindowsOptionalFeature @DisableWindowsOptionalFeature)
            }
        }
        $Int = ''
    }
    Catch {
        Write-Output ''
        Write-Log -Output "Failed to Disable all Optional Features." -Level Error
        Exit-Script
        Break
    }
}

If ($Drivers) {
    If ((Test-Path -Path $Drivers -PathType Container) -and (Get-ChildItem -Path $Drivers -Recurse -Filter "*.inf")) {
        Write-Output ''
        Write-Log -Output "Injecting driver packages into the image." -Level Info
        [void](Add-WindowsDriver -Path $MountFolder -Driver $Drivers -Recurse -ForceUnsigned -ScratchDirectory $TempFolder -LogPath $DISMLog)
        Get-WindowsDriver -Path $MountFolder | Format-List | Out-File -FilePath $WorkFolder\InjectedDriverList.txt
    }
    ElseIf (Test-Path -Path $Drivers -PathType Leaf -Filter "*.inf") {
        Write-Output ''
        Write-Log -Output "Injecting driver package into the image." -Level Info
        [void](Add-WindowsDriver -Path $MountFolder -Driver $Drivers -ForceUnsigned -ScratchDirectory $TempFolder -LogPath $DISMLog)
        Get-WindowsDriver -Path $MountFolder | Format-List | Out-File -FilePath $WorkFolder\InjectedDriverList.txt
    }
    Else {
        Write-Output ''
        Write-Log -Output "$Drivers is not a valid driver package path." -Level Warning
    }
}

If ((Get-AppxProvisionedPackage -Path $MountFolder | Where { $_.PackageName -like "*Calculator*" }).Count.Equals(0)) {
    $Win32CalcPath = Join-Path -Path $PSScriptRoot -ChildPath '.\Resources\Win32Calc' -Resolve
    If ((Test-Path -LiteralPath "$Win32CalcPath\win32calc.exe") -and (Test-Path -LiteralPath "$Win32CalcPath\win32calc.exe.mui")) {
        Try {
            Write-Output ''
            Write-Log -Output "Applying the Win32 Calculator." -Level Info
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
            $CalcStr = "Calculator.lnk=@%SystemRoot%\System32\shell32.dll,-22019"
            Invoke-Expression -Command ('ATTRIB.EXE -S -H $IniFile') -ErrorAction Stop
            If (!(Select-String -Path $IniFile -Pattern $CalcStr -SimpleMatch -Quiet)) {
                Add-Content -Path $IniFile -Value $CalcStr -Encoding Unicode -Force
            }
            Else {
                (Get-Content -Path $IniFile) | Where { $_ -ne $CalcStr } | Set-Content -Path $IniFile
                Add-Content -Path $IniFile -Value $CalcStr -Encoding Unicode -Force
            }
            Invoke-Expression -Command ('ATTRIB.EXE +S +H $IniFile') -ErrorAction Stop
        }
        Catch {
            Write-Output ''
            Write-Log -Output "Failed to apply the Win32 Calculator." -Level Warning
            If (Test-OfflineHives) {
                [void](Dismount-OfflineHives)
            }
            Start-Sleep 3
        }
    }
}

If ($SetRegistryComplete -eq $true) {
    $SetupComplete = @'
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
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "SpeechModelDownloadTask" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
'@
	
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
NBTSTAT -R >NUL
IPCONFIG /FLUSHDNS >NUL
NET STOP DNSCACHE >NUL
NET START DNSCACHE >NUL
DEL /F /Q "%WINDIR%\Panther\unattend.xml" >NUL 2>&1
DEL /F /Q "%WINDIR%\System32\Sysprep\unattend.xml" >NUL 2>&1
DEL "%~f0"
'@
	
    New-Container -Path "$MountFolder\Windows\Setup\Scripts"
    $SetupScript = "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd"
    Out-File -FilePath $SetupScript -InputObject $SetupComplete -Encoding ASCII
	
    If ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -eq $true) {
        Out-File -FilePath $SetupScript -InputObject $DefenderTasks, $XboxTasks, $SetupEnd -Append -Encoding ASCII
    }
    ElseIf ($DisableDefenderComplete -eq $true -and $DisableXboxComplete -ne $true) {
        Out-File -FilePath $SetupScript -InputObject $DefenderTasks, $SetupEnd -Append -Encoding ASCII
    }
    ElseIf ($DisableDefenderComplete -ne $true -and $DisableXboxComplete -eq $true) {
        Out-File -FilePath $SetupScript -InputObject $XboxTasks, $SetupEnd -Append -Encoding ASCII
    }
    Else {
        Out-File -FilePath $SetupScript -InputObject $SetupEnd -Append -Encoding ASCII
    }
}

If ((Test-Connection $Env:COMPUTERNAME -Quiet) -eq $true) {
    Write-Output ''
    Write-Log -Output "Updating the default Hosts File." -Level Info
    Start-Sleep 3
    Rename-Item -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -NewName hosts.bak -Force
    $URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    $Output = "$MountFolder\Windows\System32\drivers\etc\hosts"
    (New-Object System.Net.WebClient).DownloadFile($URL, $Output)
    (Get-Content -Path "$MountFolder\Windows\System32\drivers\etc\hosts") | Set-Content -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -Encoding UTF8 -Force
}

Try {
    Write-Output ''
    Write-Log -Output "Verifying the image health before finalizing." -Level Info
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
    Write-Log -Output "Failed to verify the image health." -Level Error
    Exit-Script
    Break
}

Try {
    Write-Output ''
    Write-Log -Output "Saving Image and Dismounting." -Level Info
    $DismountWindowsImage = @{
        Path             = $MountFolder
        Save             = $true
        CheckIntegrity   = $true
        ScratchDirectory = $TempFolder
        LogPath          = $DISMLog
        ErrorAction      = "Stop"
    }
    $RecycleBin = "$MountFolder\" + '$Recycle.Bin'
    If (Test-Path -Path $RecycleBin) { Remove-Item -Path $RecycleBin -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\PerfLogs") { Remove-Item -Path "$MountFolder\PerfLogs" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\Backup\*") { Remove-Item -Path "$MountFolder\Windows\WinSxS\Backup\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\ManifestCache\*.bin") { Remove-Item -Path "$MountFolder\Windows\WinSxS\ManifestCache\*.bin" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\Temp\PendingDeletes\*") { Remove-Item -Path "$MountFolder\Windows\WinSxS\Temp\PendingDeletes\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\WinSxS\Temp\TransformerRollbackData\*") { Remove-Item -Path "$MountFolder\Windows\WinSxS\Temp\TransformerRollbackData\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\inf\*.log") { Remove-Item -Path "$MountFolder\Windows\inf\*.log" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\CbsTemp\*") { Remove-Item -Path "$MountFolder\Windows\CbsTemp\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
    [void](Dismount-WindowsImage @DismountWindowsImage)
    [void](Clear-WindowsCorruptMountPoint)
}
Catch {
    Write-Output ''
    Write-Log -Output "An error occured trying to save and dismount the Windows Image." -Level Error
    Exit-Script
    Break
}

Try {
    Write-Output ''
    Write-Log -Output "Rebuilding and compressing the new image." -Level Info
    $ExportImage = @{
        CheckIntegrity       = $true
        CompressionType      = "Maximum"
        SourceImagePath      = $InstallWim
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
    Write-Log -Output "An error occured trying to rebuild and compress the the new image." -Level Error
    Exit-Script
    Break
}

Try {
    Write-Output ''
    Write-Log -Output "Finalizing Script." -Level Info
    [void]($SaveFolder = New-SaveDirectory)
    Move-Item -Path "$WorkFolder\*.txt" -Destination $SaveFolder -Force
    Move-Item -Path "$WorkFolder\*.log" -Destination $SaveFolder -Force
    Move-Item -Path "$WorkFolder\install.wim" -Destination $SaveFolder -Force
    Move-Item -Path $DISMLog -Destination $SaveFolder -Force
    Start-Sleep 3
}
Finally {
    Remove-Item -Path $TempFolder -Recurse -Force
    Remove-Item -Path $ImageFolder -Recurse -Force
    Remove-Item -Path $MountFolder -Recurse -Force
    Remove-Item -Path $WorkFolder -Recurse -Force
    [void](Clear-WindowsCorruptMountPoint)
    If (Test-Path -Path "$Env:windir\Logs\DISM\dism.log") { Remove-Item -Path "$Env:windir\Logs\DISM\dism.log" -Force }
}

If ($Error.Count.Equals(0)) {
    Write-Output ''
    Write-Output "Newly optimized image has been saved to $SaveFolder."
    Write-Output ''
    Write-Log -Output "$Script completed with [0] errors." -Level Info
    Move-Item -Path $LogFile -Destination $SaveFolder -Force
    Write-Output ''
    Start-Sleep 3
}
Else {
    $SaveErrorLog = Join-Path -Path $Env:TEMP -ChildPath "ErrorLog.log"
    Set-Content -Path $SaveErrorLog -Value $Error.ToArray() -Force
    Move-Item -Path $Env:TEMP\ErrorLog.log -Destination $SaveFolder -Force
    Write-Output ''
    Write-Output "Newly optimized image has been saved to $($SaveFolder.Name)"
    Write-Output ''
    Write-Log -Output "$Script completed with [$($Error.Count)] errors." -Level Warning
    Move-Item -Path $LogFile -Destination $SaveFolder -Force
    Write-Output ''
    Start-Sleep 3
}
# SIG # Begin signature block
# MIIMDgYJKoZIhvcNAQcCoIIL/zCCC/sCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhmIK3SYWmNLnrgmwI1ZF9G1x
# nLugggj8MIIDfTCCAmWgAwIBAgIQfY66zkudTZ9EnV2nSZm8oDANBgkqhkiG9w0B
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
# FiUxggJ8MIICeAIBATBcMEUxFDASBgoJkiaJk/IsZAEZFgRURUNIMRUwEwYKCZIm
# iZPyLGQBGRYFT01OSUMxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0ECEyEAAAAFfOz8
# 2RcyuMQAAAAAAAUwCQYFKw4DAhoFAKCB9jAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUIvX0xgBmPjOTF7eHwjo+j+6jpCcwgZUGCisGAQQBgjcCAQwxgYYwgYOggYCA
# fgBBACAAZgB1AGwAbAB5ACAAYQB1AHQAbwBtAGEAdABlAGQAIABXAGkAbgBkAG8A
# dwBzACAAMQAwACAAbwBmAGYAbABpAG4AZQAgAGkAbQBhAGcAZQAgAG8AcAB0AGkA
# bQBpAHoAYQB0AGkAbwBuACAAcwBjAHIAaQBwAHQALjANBgkqhkiG9w0BAQEFAASC
# AQDIyj+af31KLvi+P10360LWj9/oZaEl+MiXRHuXTY6JIQLvjw2Fp5eiDtiBeboB
# jnbJOGasSezJH7GHgxLtv0fI0kEg4MpFXF45cz86g+mBAa67yA69F7qLKWQbOOXm
# 3PQqzzR12geYNsnatLe/kfl/rWRNNQ9mXn07SmvrhJF3ezVxV/rAc4jboBCo0J5Y
# +wRRfTiPMnGrNJcksQ/lOw6sz6JcMoF3o8Ct3brossgW4NyHVMlB12syG0ebky4+
# zR6dEZnFeOmqonw7xOncETkM+NvxfBu86GCEDSai0HauYKK6kyyvRJmKUdsxoYoZ
# v2VmPa8pkLqxwpoj/r0NOMwk
# SIG # End signature block
