#Requires -RunAsAdministrator
#Requires -Version 5
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for 64-bit Windows 10 builds RS4-RS5.
	
	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, enhanced privacy, cleaner aesthetics, increased performance and a significantly better user experience.
	
	.PARAMETER ImagePath
		The full path to a Windows Installation ISO or an install WIM file.
	
	.PARAMETER Index
		If using a multi-index image, specify the index of the image.
	
	.PARAMETER MetroApps
		Select = Populates and outputs a Gridview list of all Provisioned Application Packages for selective removal.
		All = Automatically removes all Provisioned Application Packages.
		Whitelist = Removes all Provisioned Application Packages that are not whitelisted.
	
	.PARAMETER SystemApps
		Populates and outputs a Gridview list of all System Applications for selective removal.
	
	.PARAMETER Packages
		Populates and outputs a Gridview list of all installed Windows Capability Packages for selective removal.
	
	.PARAMETER Features
		Populates and outputs both a Gridview list of all enabled Windows Optional Features for selective disabling followed by all disabled Windows Optional Features for selective enabling.
	
	.PARAMETER WindowsStore
		Specific to Windows 10 Enterprise LTSC 2019 only!
		Integrates the Microsoft Windows Store packages, and its dependencies packages, into the image.
	
	.PARAMETER MicrosoftEdge
		Specific to Windows 10 Enterprise LTSC 2019 only!
		Integrates the Microsoft Edge Browser packages into the image.
	
	.PARAMETER Win32Calc
		Specific to non-Windows 10 Enterprise LTSC 2019 editions only!
		Integrates the traditional Calculator packages from Windows 10 Enterprise LTSC 2019 into the image.
	
	.PARAMETER Dedup
		Integrates the Windows Server Data Deduplication packages into the image.
	
	.PARAMETER DaRT
		Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools to Windows Setup and Windows Recovery.
	
	.PARAMETER Drivers
		Injects driver packages into the image.
	
	.PARAMETER NetFx3
		Integrates the .NET Framework 3 payload packages into the image and enables the NetFx3 Windows Feature.
	
	.PARAMETER Registry
		Integrates optimized registry values into the registry hives of the image.
	
	.PARAMETER ISO
		Requires the installation of the Windows ADK (Assessment and Deployment Kit)
		Only applicable when a Windows Installation Media ISO image is used as the source image.
		Creates a new bootable Windows Installation Media ISO.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\Win10Pro_Full.iso" -Index 3 -MetroApps "Select" -SystemApps -Packages -Features -Win32Calc -Dedup -DaRT -Registry -NetFx3 -Drivers -ISO
		.\Optimize-Offline.ps1 -ImagePath "D:\Win Images\install.wim" -MetroApps "Whitelist" -SystemApps -Packages -Features -Dedup -Registry
		.\Optimize-Offline.ps1 -ImagePath "D:\Win10 LTSC 2019\install.wim" -SystemApps -Packages -Features -WindowsStore -MicrosoftEdge -Registry -NetFx3 -DaRT
	
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
		Version:        3.1.3.5
		Last updated:	01/05/2019
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
    [string]$ImagePath,
    [Parameter(HelpMessage = 'If using a multi-index image, specify the index of the image to be optimized.')]
    [ValidateRange(1, 16)]
    [int]$Index = 1,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Provisioned Application Packages for selective removal, or performs a complete removal of all packages.')]
    [ValidateSet('Select', 'All', 'Whitelist')]
    [string]$MetroApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all System Applications for selective removal.')]
    [switch]$SystemApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all installed Windows Capability Packages for selective removal.')]
    [switch]$Packages,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all enabled Windows Optional Features for selective disabling.')]
    [switch]$Features,
    [Parameter(HelpMessage = 'Integrates the Microsoft Windows Store, and its dependencies, into the image.')]
    [switch]$WindowsStore,
    [Parameter(HelpMessage = 'Integrates the Microsoft Edge Browser packages into the image.')]
    [switch]$MicrosoftEdge,
    [Parameter(HelpMessage = 'Integrates the traditional Calculator packages from Windows 10 Enterprise LTSC 2019 into the image.')]
    [switch]$Win32Calc,
    [Parameter(HelpMessage = 'Integrates the Windows Server Data Deduplication packages into the image.')]
    [switch]$Dedup,
    [Parameter(HelpMessage = 'Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools to Windows Setup and Windows Recovery.')]
    [switch]$DaRT,
    [Parameter(HelpMessage = 'Injects driver packages into the image.')]
    [switch]$Drivers,
    [Parameter(HelpMessage = 'Integrates the .NET Framework 3 payload packages into the image and enables the NetFx3 Windows Feature.')]
    [switch]$NetFx3,
    [Parameter(HelpMessage = 'Integrates optimized registry values into the registry hives of the image.')]
    [switch]$Registry,
    [Parameter(HelpMessage = 'Creates a new bootable Windows Installation Media ISO.')]
    [switch]$ISO
)

#region Script Variables
$DefaultVariables = $(Get-Variable).Name
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = 'SilentlyContinue'
$ScriptName = "Optimize-Offline"
$ScriptVersion = "3.1.3.5"
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
    Add-Content -Path $ScriptLog -Value "$LogLevel $Content" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
}

Function New-WorkDirectory
{
    $WorkDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "WorkOffline"))
    $WorkDirectory = Get-Item -LiteralPath (Join-Path -Path $ScriptDirectory -ChildPath $WorkDirectory) -Force
    $WorkDirectory.FullName
}

Function New-ScratchDirectory
{
    $ScratchDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "ScratchOffline"))
    $ScratchDirectory = Get-Item -LiteralPath (Join-Path -Path $ScriptDirectory -ChildPath $ScratchDirectory) -Force
    $ScratchDirectory.FullName
}

Function New-ImageDirectory
{
    $ImageDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "ImageOffline"))
    $ImageDirectory = Get-Item -LiteralPath (Join-Path -Path $ScriptDirectory -ChildPath $ImageDirectory) -Force
    $ImageDirectory.FullName
}

Function New-MountDirectory
{
    $MountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "MountOffline"))
    $MountDirectory = Get-Item -LiteralPath (Join-Path -Path $ScriptDirectory -ChildPath $MountDirectory) -Force
    $MountDirectory.FullName
}

Function New-SaveDirectory
{
    $SaveDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline"_[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
    $SaveDirectory = Get-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $SaveDirectory) -Force -ErrorAction SilentlyContinue
    $SaveDirectory.FullName
}

Function Mount-OfflineHives
{
    @("LOAD HKLM\WIM_HKLM_SOFTWARE `"$MountFolder\Windows\System32\config\software`"", "LOAD HKLM\WIM_HKLM_SYSTEM `"$MountFolder\Windows\System32\config\system`"", "LOAD HKLM\WIM_HKCU `"$MountFolder\Users\Default\NTUSER.DAT`"") |
        ForEach { Start-Process -FilePath REG -ArgumentList $($_) -WindowStyle Hidden -Wait }
}

Function Dismount-OfflineHives
{
    [System.GC]::Collect()
    @("UNLOAD HKLM\WIM_HKLM_SOFTWARE", "UNLOAD HKLM\WIM_HKLM_SYSTEM", "UNLOAD HKLM\WIM_HKCU") |
        ForEach { Start-Process -FilePath REG -ArgumentList $($_) -WindowStyle Hidden -Wait }
}

Function Test-OfflineHives
{
    @("HKLM:\WIM_HKLM_SOFTWARE", "HKLM:\WIM_HKLM_SYSTEM", "HKLM:\WIM_HKCU") |
        ForEach { If (Test-Path -Path $($_)) { $HivesLoaded = $true } }
    Return $HivesLoaded
}

Function New-Container
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    If (!(Test-Path -LiteralPath $Path)) { [void](New-Item -Path $Path -ItemType Directory -Force) }
}

Function Exit-Script
{
    [CmdletBinding()]
    Param ()
	
    $Host.UI.RawUI.WindowTitle = "Terminating Script."
    Start-Sleep 3
    Out-Log -Content "Cleaning-up and terminating script." -Level Info
    If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
    [void](Clear-WindowsCorruptMountPoint)
    $SaveFolder = [void](New-SaveDirectory)
    If ($ProcessError.Count -gt 0)
    {
        $ErrorLog = Join-Path -Path $SaveFolder -ChildPath ErrorLog.log
        ForEach ($Process In $ProcessError) { Add-Content -Path $ErrorLog -Value $Process.Exception.Message -Force -ErrorAction SilentlyContinue }
    }
    $TimeStamp = Get-Date -Format "MM.dd.yyyy HH:mm:ss"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations finalized at [$($TimeStamp)]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Move-Item -Path $ScriptLog -Destination $SaveFolder -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$WorkFolder\Registry-Optimizations.log") { Move-Item -Path "$WorkFolder\Registry-Optimizations.log" -Destination $SaveFolder -Force -ErrorAction SilentlyContinue }
    Remove-Item -Path $DISMLog -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    ((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $_ }
    Write-Output ''
    Break
}
#endregion Helper Functions

If (!(Test-Admin)) { Write-Warning "Administrative access is required. Please re-launch $ScriptName with elevation."; Break }

Try { Get-Module -ListAvailable Dism -ErrorAction SilentlyContinue | Import-Module -ErrorAction Stop }
Catch { Write-Warning "Missing the required PowerShell Dism module."; Break }

If (Get-WindowsImage -Mounted)
{
    $Host.UI.RawUI.WindowTitle = "Cleaning-up mount location."
    Write-Host "Cleaning-up current unused mount location. Please wait." -ForegroundColor Cyan
    $MountFolder = (Get-WindowsImage -Mounted).MountPath
    If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
    Else
    {
        $QueryHives = [void](Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR WIM') -ErrorAction SilentlyContinue)
        If ($QueryHives) { $QueryHives.ForEach{ [void](Invoke-Expression -Command ("REG UNLOAD $_") -ErrorAction SilentlyContinue) } }
    }
    [void](Dismount-WindowsImage -Path $($MountFolder) -Discard -ErrorAction SilentlyContinue)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    [void](Clear-WindowsCorruptMountPoint)
    $MountFolder = $null
    Clear-Host
}

Try
{
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $ScriptDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "OptimizeOfflineTemp_$(Get-Random)"))
    If ($ScriptDirectory) { $ScriptDirectory = Get-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $ScriptDirectory) -ErrorVariable +ProcessError -ErrorAction Stop }
    $Host.UI.RawUI.WindowTitle = "Preparing image for optimizations."
    $Timer = New-Object System.Diagnostics.Stopwatch -ErrorAction SilentlyContinue
    $Timer.Start()
    If ($ProcessError.Count -gt 0) { $ProcessError.Clear() }
}
Catch
{
    Write-Warning "Failed to create the script directory. Ensure the script path is writable."
    Break
}

If (([IO.FileInfo]$ImagePath).Extension -eq ".ISO")
{
    $SourceImage = ([System.IO.Path]::ChangeExtension($ImagePath, ([System.IO.Path]::GetExtension($ImagePath)).ToString().ToLower()))
    $SourceName = [System.IO.Path]::GetFileNameWithoutExtension($SourceImage)
    $SourceMount = Mount-DiskImage -ImagePath $SourceImage -StorageType ISO -PassThru
    $DriveLetter = ($SourceMount | Get-Volume).DriveLetter + ':'
    If (!(Test-Path -Path "$($DriveLetter)\sources\install.wim"))
    {
        Write-Warning ('"{0}" does not contain valid Windows Installation media.' -f $(Split-Path -Path $SourceImage -Leaf))
        Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
    Else
    {
        Write-Host ('Exporting media from "{0}"' -f $(Split-Path -Path $SourceImage -Leaf)) -ForegroundColor Cyan
        Try
        {
            $ISODrive = Get-Item -Path $DriveLetter -ErrorAction Stop
            $ISOMedia = Join-Path -Path $ScriptDirectory -ChildPath $SourceName
            New-Container -Path $ISOMedia -ErrorAction Stop
            ForEach ($File In Get-ChildItem -Path $ISODrive.FullName -Recurse -ErrorAction SilentlyContinue)
            {
                $MediaPath = $ISOMedia + $File.FullName.Replace($ISODrive, '\')
                Copy-Item -Path $($File.FullName) -Destination $MediaPath -Force -ErrorAction SilentlyContinue
            }
            $ISOIsExported = $true
        }
        Catch
        {
            Write-Warning ('Unable to export media from "{0}"' -f $(Split-Path -Path $SourceImage -Leaf))
            Remove-Item -Path $ScriptDirectory -Recurse -ErrorAction SilentlyContinue
            Break
        }
        Finally
        {
            Dismount-DiskImage -ImagePath $SourceImage -StorageType ISO
        }
        Try
        {
            [void]($MountFolder = New-MountDirectory)
            [void]($ImageFolder = New-ImageDirectory)
            [void]($WorkFolder = New-WorkDirectory)
            [void]($ScratchFolder = New-ScratchDirectory)
            Move-Item -Path "$ISOMedia\sources\install.wim" -Destination $ImageFolder -ErrorAction Stop
            Set-ItemProperty -LiteralPath "$ImageFolder\install.wim" -Name IsReadOnly -Value $false -ErrorAction Stop
            $InstallWim = (Get-Item -Path "$ImageFolder\install.wim" -ErrorAction Stop).FullName
            If ((Test-Path -Path "$ISOMedia\sources\boot.wim") -and ($DaRT))
            {
                Move-Item -Path "$ISOMedia\sources\boot.wim" -Destination $ImageFolder -ErrorAction Stop
                Set-ItemProperty -LiteralPath "$ImageFolder\boot.wim" -Name IsReadOnly -Value $false -ErrorAction Stop
                $BootWim = (Get-Item -Path "$ImageFolder\boot.wim" -ErrorAction Stop).FullName
            }
        }
        Catch
        {
            Write-Warning $($_.Exception.Message)
            Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
    }
}
ElseIf (([IO.FileInfo]$ImagePath).Extension -eq ".WIM")
{
    $SourceImage = ([System.IO.Path]::ChangeExtension($ImagePath, ([System.IO.Path]::GetExtension($ImagePath)).ToString().ToLower()))
    If (Test-Path -Path $SourceImage -Filter install.wim)
    {
        Try
        {
            Write-Host ('Copying WIM from "{0}"' -f $(Split-Path -Path $SourceImage -Parent)) -ForegroundColor Cyan
            [void]($MountFolder = New-MountDirectory)
            [void]($ImageFolder = New-ImageDirectory)
            [void]($WorkFolder = New-WorkDirectory)
            [void]($ScratchFolder = New-ScratchDirectory)
            Copy-Item -Path $SourceImage -Destination $ImageFolder -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "$ImageFolder\install.wim" -Name IsReadOnly -Value $false -ErrorVariable +ProcessError -ErrorAction Stop
            $InstallWim = (Get-Item -Path "$ImageFolder\install.wim" -ErrorVariable +ProcessError -ErrorAction Stop).FullName
        }
        Catch
        {
            Write-Warning $($ProcessError.Exception.Message)
            Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
    }
    Else
    {
        Write-Warning ('The source image is not an install.wim: "{0}"' -f $(Split-Path -Path $SourceImage -Leaf))
        Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
}

Try
{
    $WimImage = (Get-WindowsImage -ImagePath $InstallWim -Index $Index -ErrorVariable +ProcessError -ErrorAction Stop)
    $WimInfo = [PSCustomObject]@{
        Name     = $($WimImage.ImageName)
        Edition  = $($WimImage.EditionID)
        Version  = $($WimImage.Version)
        Build    = $($WimImage.Build.ToString())
        Language = $($WimImage.Languages)
    }
    If ($WimImage.Architecture -eq 9)
    {
        $WimInfo | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '9', 'amd64') -ErrorVariable +ProcessError -ErrorAction Stop
    }
}
Catch
{
    Write-Warning "$($ProcessError.Exception.Message)"
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

If ($WimInfo.Architecture -ne 'amd64')
{
    Write-Warning "$($ScriptName) currently only supports 64-bit architectures."
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}
If ($WimInfo.Edition.Contains('Server'))
{
    Write-Warning "Unsupported Image Edition: [$($WimInfo.Edition)]"
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}
If ($WimInfo.Version.StartsWith(10))
{
    If ($WimInfo.Build -lt '17134')
    {
        Write-Warning "Unsupported Image Build: [$($WimInfo.Build)]"
        Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
}
Else
{
    Write-Warning "Unsupported Image Version: [$($WimInfo.Version)]"
    Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

Try
{
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    $DISMLog = Join-Path -Path $WorkFolder -ChildPath DISM.log
    $ScriptLog = Join-Path -Path $WorkFolder -ChildPath Optimize-Offline.log
    $TimeStamp = Get-Date -Format "MM.dd.yyyy HH:mm:ss"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "$ScriptName v$ScriptVersion starting at [$($TimeStamp)]"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizing image: `"$($WimInfo.Name)`""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value ""
    If ($ProcessError.Count -gt 0) { $ProcessError.Clear() }
    Out-Log -Content "Supported Image Build: [$($WimInfo.Build)]" -Level Info
    Start-Sleep 3
    Out-Log -Content "Mounting $($WimInfo.Name)" -Level Info
    $MountWindowsImage = @{
        ImagePath        = $InstallWim
        Index            = $Index
        Path             = $MountFolder
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        ErrorVariable    = '+ProcessError'
        ErrorAction      = "Stop"
    }
    [void](Mount-WindowsImage @MountWindowsImage)
}
Catch
{
    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
    Exit-Script
    Break
}

If ((Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState -eq "Healthy")
{
    Out-Log -Content "Pre-Optimization Image Health State: [Healthy]" -Level Info
}
Else
{
    Out-Log -Content "The image has been flagged for corruption. Further servicing is required before the image can be optimized." -Level Error
    Exit-Script
    Break
}

If ($MetroApps -and $($WimInfo.Name) -notlike "*LTSC" -and (Get-AppxProvisionedPackage -Path $MountFolder).Count -gt 0)
{
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Removing Metro Apps."
    If ($MetroApps -eq "Select")
    {
        $SelectedAppxPackages = [System.Collections.ArrayList]@()
        $GetAppx = Get-AppxProvisionedPackage -Path $MountFolder
        $Int = 1
        ForEach ($Appx In $GetAppx)
        {
            $GetAppx = New-Object -TypeName PSObject
            $GetAppx | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $GetAppx | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Appx.DisplayName
            $GetAppx | Add-Member -MemberType NoteProperty -Name PackageName -Value $Appx.PackageName
            $Int++
            [void]$SelectedAppxPackages.Add($GetAppx)
        }
        $RemoveAppx = $SelectedAppxPackages | Out-GridView -Title "Remove Provisioned App Packages." -PassThru
        $PackageName = $RemoveAppx.PackageName
        Try
        {
            If ($RemoveAppx)
            {
                $PackageName | ForEach {
                    Out-Log -Content "Removing Appx Provisioned Package: $($_.Split('_')[0])" -Level Info
                    $RemoveSelectAppx = @{
                        Path             = $MountFolder
                        PackageName      = $($_)
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorVariable    = '+ProcessError'
                        ErrorAction      = "Stop"
                    }
                    [void](Remove-AppxProvisionedPackage @RemoveSelectAppx)
                }
                $MetroAppsComplete = $true
            }
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
        Finally
        {
            $SelectedAppxPackages.Clear()
            $Int = $null
        }
    }
    ElseIf ($MetroApps -eq "All")
    {
        Try
        {
            Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
                Out-Log -Content "Removing Appx Provisioned Package: $($_.DisplayName)" -Level Info
                $RemoveAllAppx = @{
                    Path             = $MountFolder
                    PackageName      = $($_.PackageName)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                [void](Remove-AppxProvisionedPackage @RemoveAllAppx)
            }
            $MetroAppsComplete = $true
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
    }
    ElseIf ($MetroApps -eq "Whitelist")
    {
        $AppxWhitelistPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\AppxPackageWhitelist.xml"
        If (Test-Path -Path $AppxWhitelistPath)
        {
            [XML]$GetList = Get-Content -Path $AppxWhitelistPath
            If ($GetList.Appx.DisplayName.Count -eq 0)
            {
                Out-Log -Content "The Whitelist is either empty or has improper syntax." -Level Error
                Start-Sleep 3
                Return
            }
            Else
            {
                $AppxWhitelist = @()
                $AppxWhitelist += $GetList.Appx.DisplayName
                Try
                {
                    Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
                        If ($_.DisplayName -notin $AppxWhitelist)
                        {
                            Out-Log -Content "Removing Appx Provisioned Package: $($_.DisplayName)" -Level Info
                            $RemoveAppx = @{
                                Path             = $MountFolder
                                PackageName      = $($_.PackageName)
                                ScratchDirectory = $ScratchFolder
                                LogPath          = $DISMLog
                                ErrorVariable    = '+ProcessError'
                                ErrorAction      = "Stop"
                            }
                            [void](Remove-AppxProvisionedPackage @RemoveAppx)
                        }
                    }
                    $MetroAppsComplete = $true
                }
                Catch
                {
                    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
                    Exit-Script
                    Break
                }
                Finally
                {
                    $AppxWhitelist = @()
                }
            }
        }
        Else
        {
            Out-Log -Content "Missing required Whitelist file." -Level Error
            Start-Sleep 3
        }
    }
    Clear-Host
}

If ($SystemApps)
{
    $RemovedSystemApps = [System.Collections.ArrayList]@()
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Removing System Applications."
    Try
    {
        Write-Warning "Do NOT remove any System Application if you are unsure of its impact on a live installation."
        Start-Sleep 5
        [void](Mount-OfflineHives)
        $InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
        $PackageList = (Get-ChildItem -Path $InboxAppsKey -ErrorAction SilentlyContinue).Name.Split('\') | Where { $_ -like "Microsoft.*" -or $_ -like "Windows.*" }
        $InboxApps = $PackageList | Select -Property `
        @{ Label = 'Name'; Expression = { ($_.Split('_')[0]) } },
        @{ Label = 'Package'; Expression = { ($_) } } | Out-GridView -Title "Remove System Applications." -PassThru
        $RemoveSystemApps = $InboxApps.Package
        If ($RemoveSystemApps)
        {
            Clear-Host
            $RemoveSystemApps | ForEach {
                $FullKeyPath = Join-Path -Path $InboxAppsKey -ChildPath $($_)
                $FullKeyPath = $FullKeyPath -replace "HKLM:", "HKLM"
                Out-Log -Content "Removing System Application: $($_.Split('_')[0])" -Level Info
                [void](Invoke-Expression -Command ("REG DELETE `"$FullKeyPath`" /F") -ErrorVariable +ProcessError -ErrorAction Stop)
                [void]$RemovedSystemApps.Add($($_.Split('_')[0]))
                Start-Sleep 2
            }
        }
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Exit-Script
        Break
    }
    Finally
    {
        [void](Dismount-OfflineHives)
        Clear-Host
    }
}

If ($Packages)
{
    $RemovedWindowsPackages = [System.Collections.ArrayList]@()
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Removing Windows Capability Packages."
    Try
    {
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
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                [void](Remove-WindowsCapability @CapabilityPackage)
            }
        }
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Exit-Script
        Break
    }
    Finally
    {
        [void]$RemovedWindowsPackages.Clear()
        $Int = $null
        Clear-Host
    }
}

Try
{
    If ($MetroAppsComplete -eq $true)
    {
        If ((Get-AppxProvisionedPackage -Path $MountFolder | Where DisplayName -Match Microsoft.Wallet).Count.Equals(0) -or (Get-AppxProvisionedPackage -Path $MountFolder | Where DisplayName -Match Microsoft.WindowsMaps).Count.Equals(0))
        {
            $Host.UI.RawUI.WindowTitle = "Disabling Appx Provisioned Package Services."
            Out-Log -Content "Disabling Appx Provisioned Package Services." -Level Info
            [void](Mount-OfflineHives)
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService") { Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord -ErrorVariable +ProcessError -ErrorAction Stop }
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker") { Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -ErrorVariable +ProcessError -ErrorAction Stop }
            [void](Dismount-OfflineHives)
        }
    }
}
Catch
{
    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
    If (Test-OfflineHives) { [void](Dismount-OfflineHives) }
    Start-Sleep 3
}

If ($RemovedSystemApps -contains "Microsoft.Windows.SecHealthUI")
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Removing Windows Defender Remnants."
        Out-Log -Content "Disabling Windows Defender Services, Drivers and Smartscreen Integration." -Level Info
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowBehaviorMonitoring" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowCloudProtection" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Name "Notification_Suppress" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        If ((Get-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue) -match "Enabled")
        {
            Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Force -ErrorAction SilentlyContinue
        }
        If ((Get-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue) -match "SecurityHealth")
        {
            Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force -ErrorVariable +ProcessError -ErrorAction Stop
        }
        @("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderApiLogger" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderAuditLogger" -Recurse -Force -ErrorAction SilentlyContinue
        [void](Dismount-OfflineHives)
        $DisableDefenderComplete = $true
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Exit-Script
        Break
    }
}

If ($DisableDefenderComplete -eq $true -and (Get-WindowsOptionalFeature -Path $MountFolder -FeatureName Windows-Defender-Default-Definitions).State -eq "Enabled")
{
    Try
    {
        Out-Log -Content "Disabling Windows Feature: Windows-Defender-Default-Definitions" -Level Info
        $DisableDefenderFeature = @{
            Path             = $MountFolder
            FeatureName      = "Windows-Defender-Default-Definitions"
            ScratchDirectory = $ScratchFolder
            LogPath          = $DISMLog
            ErrorVariable    = '+ProcessError'
            ErrorAction      = "Stop"
        }
        [void](Disable-WindowsOptionalFeature @DisableDefenderFeature)
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Exit-Script
        Break
    }
}

Try
{
    If ($MetroApps -eq "All" -or $RemovedSystemApps -contains "Microsoft.XboxGameCallableUI" -or (Get-AppxProvisionedPackage -Path $MountFolder | Where PackageName -Like *Xbox*).Count -lt 5)
    {
        $Host.UI.RawUI.WindowTitle = "Removing Xbox Remnants."
        Out-Log -Content "Disabling Xbox Services and Drivers." -Level Info
        [void](Mount-OfflineHives)
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        @("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        [void](Dismount-OfflineHives)
    }
}
Catch
{
    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
    Exit-Script
    Break
}

If (Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -Like *SMB1* | Where State -EQ Enabled)
{
    $Host.UI.RawUI.WindowTitle = "Disabling the SMBv1 Protocol Windows Feature."
    Out-Log -Content "Disabling the SMBv1 Protocol Windows Feature." -Level Info
    [void](Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -Like *SMB1* | Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
}

If ($Features)
{
    $DisabledOptionalFeatures = [System.Collections.ArrayList]@()
    $EnabledOptionalFeatures = [System.Collections.ArrayList]@()
    Try
    {
        Clear-Host
        $Host.UI.RawUI.WindowTitle = "Disabling Windows Features."
        $EnabledFeatures = (Get-WindowsOptionalFeature -Path $MountFolder | Where State -EQ Enabled)
        $Int = 1
        ForEach ($EnabledFeature In $EnabledFeatures)
        {
            $EnabledFeatures = New-Object -TypeName PSObject
            $EnabledFeatures | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $EnabledFeatures | Add-Member -MemberType NoteProperty -Name FeatureName -Value $EnabledFeature.FeatureName
            $EnabledFeatures | Add-Member -MemberType NoteProperty -Name State -Value $EnabledFeature.State
            $Int++
            [void]$DisabledOptionalFeatures.Add($EnabledFeatures)
        }
        $DisableFeatures = $DisabledOptionalFeatures | Out-GridView -Title "Disable Windows Features." -PassThru
        $FeatureName = $DisableFeatures.FeatureName
        If ($DisableFeatures)
        {
            $FeatureName | ForEach {
                Out-Log -Content "Disabling Windows Feature: $($_)" -Level Info
                $DisableFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $($_)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                [void](Disable-WindowsOptionalFeature @DisableFeature)
            }
        }
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Start-Sleep 3
        Break
    }
    Finally
    {
        [void]$DisabledOptionalFeatures.Clear()
        $Int = $null
        Clear-Host
    }
    Try
    {
        Clear-Host
        $Host.UI.RawUI.WindowTitle = "Enabling Windows Features."
        $DisabledFeatures = (Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -NotLike *SMB1* | Where FeatureName -NE Windows-Defender-Default-Definitions | Where State -EQ Disabled)
        $Int = 1
        ForEach ($DisabledFeature In $DisabledFeatures)
        {
            $DisabledFeatures = New-Object -TypeName PSObject
            $DisabledFeatures | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $DisabledFeatures | Add-Member -MemberType NoteProperty -Name FeatureName -Value $DisabledFeature.FeatureName
            $DisabledFeatures | Add-Member -MemberType NoteProperty -Name State -Value $DisabledFeature.State
            $Int++
            [void]$EnabledOptionalFeatures.Add($DisabledFeatures)
        }
        $EnableFeatures = $EnabledOptionalFeatures | Out-GridView -Title "Enable Windows Features." -PassThru
        $FeatureName = $EnableFeatures.FeatureName
        If ($EnableFeatures)
        {
            $FeatureName | ForEach {
                Out-Log -Content "Enabling Windows Feature: $($_)" -Level Info
                $EnableFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $($_)
                    All              = $true
                    LimitAccess      = $true
                    NoRestart        = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                [void](Enable-WindowsOptionalFeature @EnableFeature)
            }
        }
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Start-Sleep 3
        Break
    }
    Finally
    {
        [void]$EnabledOptionalFeatures.Clear()
        $Int = $null
        Clear-Host
    }
    Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt
}

If ($WindowsStore -and $WimInfo.Name -like "*LTSC")
{
    $StoreAppPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\WindowsStore"
    If (Test-Path -LiteralPath $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle)
    {
        $Host.UI.RawUI.WindowTitle = "Applying the Microsoft Store Application Packages."
        Out-Log -Content "Applying the Microsoft Store Application Packages." -Level Info
        Try
        {
            $StoreBundle = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle -ErrorAction SilentlyContinue).FullName
            $PurchaseBundle = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.appxbundle -ErrorAction SilentlyContinue).FullName
            $XboxBundle = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.appxbundle -ErrorAction SilentlyContinue).FullName
            $InstallerBundle = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.appxbundle -ErrorAction SilentlyContinue).FullName
            $StoreLicense = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.xml -ErrorAction SilentlyContinue).FullName
            $PurchaseLicense = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.xml -ErrorAction SilentlyContinue).FullName
            $IdentityLicense = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.xml -ErrorAction SilentlyContinue).FullName
            $InstallerLicense = (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.xml -ErrorAction SilentlyContinue).FullName
            $DepAppx = @()
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Filter Microsoft.VCLibs*.appx -ErrorAction SilentlyContinue).FullName
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Filter *Native.Framework*.appx -ErrorAction SilentlyContinue).FullName
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx -ErrorAction SilentlyContinue).FullName
            [void](Mount-OfflineHives)
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord -ErrorVariable +ProcessError -ErrorAction Stop
            [void](Dismount-OfflineHives)
            $StorePackage = @{
                Path                  = $MountFolder
                PackagePath           = $StoreBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $StoreLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                ErrorVariable         = '+ProcessError'
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
                ErrorVariable         = '+ProcessError'
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
                ErrorVariable         = '+ProcessError'
                ErrorAction           = "Stop"
            }
            [void](Add-AppxProvisionedPackage @IdentityPackage)
            $DepAppx = @()
            $DepAppx += (Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx -ErrorAction SilentlyContinue).FullName
            $InstallerPackage = @{
                Path                  = $MountFolder
                PackagePath           = $InstallerBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $InstallerLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                ErrorVariable         = '+ProcessError'
                ErrorAction           = "Stop"
            }
            [void](Add-AppxProvisionedPackage @InstallerPackage)
            [void](Mount-OfflineHives)
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            [void](Dismount-OfflineHives)
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
        Get-AppxProvisionedPackage -Path $MountFolder | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\SideloadedAppxPackages.txt
    }
    Else
    {
        Out-Log -Content "Missing the required Microsoft Store Application package files." -Level Error
        Start-Sleep 3
    }
}

If ($MicrosoftEdge -and $WimInfo.Name -like "*LTSC")
{
    If ($null -eq (Get-ChildItem -Path "$MountFolder\Windows\servicing\Packages" -Filter Microsoft-Windows-Internet-Browser-Package*.mum))
    {
        $EdgeAppPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\MicrosoftEdge"
        If (Test-Path -LiteralPath $EdgeAppPath -Filter Microsoft-Windows-Internet-Browser-Package*.cab)
        {
            $Host.UI.RawUI.WindowTitle = "Applying the Microsoft Edge Browser Application Packages."
            Out-Log -Content "Applying the Microsoft Edge Browser Application Packages." -Level Info
            Try
            {
                $EdgeBasePackage = @{
                    Path             = $MountFolder
                    PackagePath      = "$EdgeAppPath\Microsoft-Windows-Internet-Browser-Package~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                    IgnoreCheck      = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                [void](Add-WindowsPackage @EdgeBasePackage)
                $EdgeLanguagePackage = @{
                    Path             = $MountFolder
                    PackagePath      = "$EdgeAppPath\Microsoft-Windows-Internet-Browser-Package~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                    IgnoreCheck      = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                [void](Add-WindowsPackage @EdgeLanguagePackage)
            }
            Catch
            {
                Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
                Exit-Script
                Break
            }
            Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Internet-Browser* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\AppliedWindowsPackages.txt -Append
        }
        Else
        {
            Out-Log -Content "Missing the required Microsoft Edge Browser Application Packages." -Level Error
            Start-Sleep 3
        }
    }
    Else
    {
        Out-Log -Content "The Microsoft Edge Browser is already installed." -Level Error
        Start-Sleep 3
    }
}

If ($Win32Calc -and $WimInfo.Name -notlike "*LTSC")
{
    If ($null -eq (Get-ChildItem -Path "$MountFolder\Windows\servicing\Packages" -Filter Microsoft-Windows-win32calc-Package*.mum -ErrorAction SilentlyContinue))
    {
        $Host.UI.RawUI.WindowTitle = "Applying the Win32 Calculator Packages."
        Out-Log -Content "Applying the Win32 Calculator Packages." -Level Info
        $Win32CalcPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Win32Calc"
        If ($WimInfo.Build -ge '17763')
        {
            If (Test-Path -LiteralPath $Win32CalcPath -Filter Microsoft-Windows-win32calc-Package*.cab)
            {
                Try
                {
                    $CalcBasePackage = @{
                        Path             = $MountFolder
                        PackagePath      = "$Win32CalcPath\Microsoft-Windows-win32calc-Package~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                        IgnoreCheck      = $true
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorVariable    = '+ProcessError'
                        ErrorAction      = "Stop"
                    }
                    [void](Add-WindowsPackage @CalcBasePackage)
                    $CalcLanguagePackage = @{
                        Path             = $MountFolder
                        PackagePath      = "$Win32CalcPath\Microsoft-Windows-win32calc-Package~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                        IgnoreCheck      = $true
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorVariable    = '+ProcessError'
                        ErrorAction      = "Stop"
                    }
                    [void](Add-WindowsPackage @CalcLanguagePackage)
                }
                Catch
                {
                    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
                    Exit-Script
                    Break
                }
                Try
                {
                    [void](Mount-OfflineHives)
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\RegisteredApplications" -ErrorVariable +ProcessError -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -ErrorVariable +ProcessError -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -ErrorVariable +ProcessError -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -ErrorVariable +ProcessError -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\RegisteredApplications" -Name "Windows Calculator" -Value "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Calculator\\Capabilities" -Type String -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationName" -Value "@%SystemRoot%\system32\win32calc.exe" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationDescription" -Value "@%SystemRoot%\system32\win32calc.exe,-217" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -Name "calculator" -Value "calculator" -Type String -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationName" -Value "@%SystemRoot%\system32\win32calc.exe" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationDescription" -Value "@%SystemRoot%\system32\win32calc.exe,-217" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -Name "calculator" -Value "calculator" -Type String -ErrorVariable +ProcessError -ErrorAction Stop
                    [void](Dismount-OfflineHives)
                }
                Catch
                {
                    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
                    Exit-Script
                    Break
                }
                Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Windows-win32calc* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\AppliedWindowsPackages.txt -Append
            }
            Else
            {
                Out-Log -Content "Missing the required Win32 Calculator Packages." -Level Error
                Start-Sleep 3
            }
        }
        Else
        {
            If (Test-Path -LiteralPath $Win32CalcPath -Filter Win32Calc.cab)
            {
                Try
                {
                    Start-Process -FilePath EXPAND -ArgumentList ("-F:* `"$($Win32CalcPath)\Win32Calc.cab`" `"$MountFolder`"") -WindowStyle Hidden -Wait
                    [void](Mount-OfflineHives)
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -ErrorVariable +ProcessError -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -ErrorVariable +ProcessError -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -Name "(default)" -Value "@%SystemRoot%\System32\win32calc.exe,0" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -Name "(default)" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -Name "ShellExecute" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorVariable +ProcessError -ErrorAction Stop
                    [void](Dismount-OfflineHives)
                    $CalcShell = New-Object -ComObject WScript.Shell -ErrorVariable +ProcessError -ErrorAction Stop
                    $CalcShortcut = $CalcShell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk")
                    $CalcShortcut.TargetPath = "%SystemRoot%\System32\win32calc.exe"
                    $CalcShortcut.IconLocation = "%SystemRoot%\System32\win32calc.exe,0"
                    $CalcShortcut.Description = "Performs basic arithmetic tasks with an on-screen calculator."
                    $CalcShortcut.Save()
                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($CalcShell)
                    $IniFile = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini"
                    $CalcString = "Calculator.lnk=@%SystemRoot%\System32\shell32.dll,-22019"
                    If ((Get-Content -Path $IniFile -ErrorAction SilentlyContinue).Contains($CalcString) -eq $false) { Add-Content -Path $IniFile -Value $CalcString -Encoding Unicode -Force -ErrorAction SilentlyContinue }
                }
                Catch
                {
                    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
                    Exit-Script
                    Break
                }
                Try
                {
                    $SSDL = @'

D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
'@
                    $SSDL.Insert(0, "win32calc.exe") | Out-File -FilePath "$($WorkFolder)\SSDL.ini" -ErrorVariable +ProcessError -ErrorAction Stop
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\System32`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\SysWOW64`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    $SSDL.Insert(0, "win32calc.exe.mui") | Out-File -FilePath "$($WorkFolder)\SSDL.ini" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\System32\en-US`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\SysWOW64\en-US`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    Remove-Item -Path "$($WorkFolder)\SSDL.ini" -Force -ErrorAction SilentlyContinue
                    $TrustedInstaller = ((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')).Translate([System.Security.Principal.NTAccount]))
                    @("$MountFolder\Windows\System32\win32calc.exe", "$MountFolder\Windows\SysWOW64\win32calc.exe", "$MountFolder\Windows\System32\en-US\win32calc.exe.mui", "$MountFolder\Windows\SysWOW64\en-US\win32calc.exe.mui") | ForEach {
                        $ACL = Get-Acl -Path $($_) -ErrorVariable +ProcessError -ErrorAction Stop
                        $ACL.SetOwner($TrustedInstaller)
                        $ACL | Set-Acl -Path $($_) -ErrorVariable +ProcessError -ErrorAction Stop
                    }
                }
                Catch
                {
                    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
                    Exit-Script
                    Break
                }
            }
            Else
            {
                Out-Log -Content "Missing the required Win32 Calculator Packages." -Level Error
                Start-Sleep 3
            }
        }
    }
    Else
    {
        Out-Log -Content "The Win32 Calculator is already installed." -Level Error
        Start-Sleep 3
    }
}

If ($Dedup)
{
    $DedupPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Deduplication"
    If ((Test-Path -LiteralPath $DedupPath -Filter Microsoft-Windows-FileServer-ServerCore-Package*.cab) -and (Test-Path -LiteralPath $DedupPath -Filter Microsoft-Windows-Dedup-Package*.cab))
    {
        $Host.UI.RawUI.WindowTitle = "Applying the Data Deduplication Packages."
        Out-Log -Content "Applying the Data Deduplication Packages." -Level Info
        Try
        {
            $FileServerCore = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            [void](Add-WindowsPackage @FileServerCore)
            $FileServerLang = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            [void](Add-WindowsPackage @FileServerLang)
            $DedupCore = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            [void](Add-WindowsPackage @DedupCore)
            $DedupLang = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            [void](Add-WindowsPackage @DedupLang)
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Applying the Data Deduplication Firewall Rules."
            Out-Log -Content "Applying the Data Deduplication Firewall Rules." -Level Info
            Start-Sleep 3
            [void](Mount-OfflineHives)
            New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-DCOM-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=File Server Remote Management (DCOM-In)|Desc=Inbound rule to allow DCOM traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-SMB-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=File Server Remote Management (SMB-In)|Desc=Inbound rule to allow SMB traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-Winmgmt-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Winmgmt|Name=File Server Remote Management (WMI-In)|Desc=Inbound rule to allow WMI traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-DCOM-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=File Server Remote Management (DCOM-In)|Desc=Inbound rule to allow DCOM traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-SMB-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=File Server Remote Management (SMB-In)|Desc=Inbound rule to allow SMB traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-Winmgmt-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Winmgmt|Name=File Server Remote Management (WMI-In)|Desc=Inbound rule to allow WMI traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorVariable +ProcessError -ErrorAction Stop
            [void](Dismount-OfflineHives)
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Enabling Windows Feature: Dedup-Core"
            Out-Log -Content "Enabling Windows Feature: Dedup-Core" -Level Info
            $EnableDedup = @{
                Path             = $MountFolder
                FeatureName      = "Dedup-Core"
                All              = $true
                LimitAccess      = $true
                NoRestart        = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            [void](Enable-WindowsOptionalFeature @EnableDedup)
            Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt -Force -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
    }
}

If ($DaRT)
{
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Applying Microsoft DaRT 10."
    $DaRTPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\DaRT"
    If ((Test-Path -LiteralPath $DaRTPath -Filter MSDaRT10.wim) -and (Test-Path -LiteralPath $DaRTPath -Filter DebuggingTools_*.wim))
    {
        If ($WimInfo.Build -eq '17134') { $CodeName = "RS4" }
        ElseIf ($WimInfo.Build -eq '17763') { $CodeName = "RS5" }
        Try
        {
            If ($BootWim)
            {
                $BootMount = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "BootMount"))
                If ($BootMount) { $BootMount = Get-Item -LiteralPath (Join-Path -Path $ScriptDirectory -ChildPath $BootMount) -Force -ErrorAction Stop }
                $MountBootImage = @{
                    Path             = $BootMount
                    ImagePath        = $BootWim
                    Index            = 2
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
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
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                Out-Log -Content "Applying the Microsoft DaRT $($CodeName) Base Package to the Boot Image." -Level Info
                [void](Expand-WindowsImage @MSDaRT10Boot)
                Start-Sleep 3
                $DeguggingToolsBoot = @{
                    ImagePath        = "$DaRTPath\DebuggingTools_$($CodeName).wim"
                    Index            = 1
                    ApplyPath        = $BootMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                Out-Log -Content "Applying Windows 10 $($CodeName) Debugging Tools to the Boot Image." -Level Info
                [void](Expand-WindowsImage @DeguggingToolsBoot)
                Start-Sleep 3
                If (!(Test-Path -Path "$BootMount\Windows\System32\fmapi.dll"))
                {
                    Copy-Item -Path "$MountFolder\Windows\System32\fmapi.dll" -Destination "$BootMount\Windows\System32" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                }
                @'
[LaunchApps]
%WINDIR%\System32\wpeinit.exe
%WINDIR%\System32\netstart.exe
%SYSTEMDRIVE%\setup.exe
'@ | Out-File -FilePath "$BootMount\Windows\System32\winpeshl.ini" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                If (Test-Path -LiteralPath "$BootMount\`$Recycle.Bin") { Remove-Item -LiteralPath "$BootMount\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue }
                $DismountBootImage = @{
                    Path             = $BootMount
                    Save             = $true
                    CheckIntegrity   = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                Out-Log -Content "Saving and Dismounting the Boot Image." -Level Info
                [void](Dismount-WindowsImage @DismountBootImage)
                Out-Log -Content "Rebuilding the Boot Image." -Level Info
                $ExportPE = @{
                    SourceImagePath      = $BootWim
                    SourceIndex          = 1
                    DestinationImagePath = "$($WorkFolder)\boot.wim"
                    CompressionType      = "Maximum"
                    CheckIntegrity       = $true
                    ScratchDirectory     = $ScratchFolder
                    LogPath              = $DISMLog
                    ErrorVariable        = '+ProcessError'
                    ErrorAction          = "Stop"
                }
                [void](Export-WindowsImage @ExportPE)
                $ExportSetup = @{
                    SourceImagePath      = $BootWim
                    SourceIndex          = 2
                    DestinationImagePath = "$($WorkFolder)\boot.wim"
                    CompressionType      = "Maximum"
                    CheckIntegrity       = $true
                    ScratchDirectory     = $ScratchFolder
                    LogPath              = $DISMLog
                    ErrorVariable        = '+ProcessError'
                    ErrorAction          = "Stop"
                }
                [void](Export-WindowsImage @ExportSetup)
            }
            If (Test-Path -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -PathType Leaf)
            {
                [void](Invoke-Expression -Command ("ATTRIB -S -H -I `"$MountFolder\Windows\System32\Recovery\winre.wim`"") -ErrorAction SilentlyContinue)
                Copy-Item -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -Destination $ImageFolder -Force -ErrorVariable +ProcessError -ErrorAction Stop
                $RecoveryMount = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ScriptDirectory -ChildPath "RecoveryMount"))
                If ($RecoveryMount) { $RecoveryMount = Get-Item -LiteralPath (Join-Path -Path $ScriptDirectory -ChildPath $RecoveryMount) -Force -ErrorAction Stop }
                $MountRecoveryImage = @{
                    Path             = $RecoveryMount
                    ImagePath        = "$($ImageFolder)\winre.wim"
                    Index            = 1
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
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
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                Out-Log -Content "Applying the Microsoft DaRT $($CodeName) Base Package to the Recovery Image." -Level Info
                [void](Expand-WindowsImage @MSDaRT10Recovery)
                Start-Sleep 3
                $DeguggingToolsRecovery = @{
                    ImagePath        = "$DaRTPath\DebuggingTools_$($CodeName).wim"
                    Index            = 1
                    ApplyPath        = $RecoveryMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                Out-Log -Content "Applying Windows 10 $($CodeName) Debugging Tools to the Recovery Image." -Level Info
                [void](Expand-WindowsImage @DeguggingToolsRecovery)
                Start-Sleep 3
                If (!(Test-Path -Path "$RecoveryMount\Windows\System32\fmapi.dll"))
                {
                    Copy-Item -Path "$MountFolder\Windows\System32\fmapi.dll" -Destination "$RecoveryMount\Windows\System32" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                }
                @'
[LaunchApps]
%WINDIR%\System32\wpeinit.exe
%WINDIR%\System32\netstart.exe
%SYSTEMDRIVE%\sources\recovery\recenv.exe
'@ | Out-File -FilePath "$RecoveryMount\Windows\System32\winpeshl.ini" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                If (Test-Path -LiteralPath "$RecoveryMount\`$Recycle.Bin") { Remove-Item -LiteralPath "$RecoveryMount\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue }
                $DismountRecoveryImage = @{
                    Path             = $RecoveryMount
                    Save             = $true
                    CheckIntegrity   = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorVariable    = '+ProcessError'
                    ErrorAction      = "Stop"
                }
                Out-Log -Content "Saving and Dismounting the Recovery Image." -Level Info
                [void](Dismount-WindowsImage @DismountRecoveryImage)
                Out-Log -Content "Rebuilding the Recovery Image." -Level Info
                $ExportRecovery = @{
                    SourceImagePath      = "$($ImageFolder)\winre.wim"
                    SourceIndex          = 1
                    DestinationImagePath = "$($WorkFolder)\winre.wim"
                    CompressionType      = "Maximum"
                    CheckIntegrity       = $true
                    ScratchDirectory     = $ScratchFolder
                    LogPath              = $DISMLog
                    ErrorVariable        = '+ProcessError'
                    ErrorAction          = "Stop"
                }
                [void](Export-WindowsImage @ExportRecovery)
                Move-Item -Path "$WorkFolder\winre.wim" -Destination "$MountFolder\Windows\System32\Recovery" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                [void](Invoke-Expression -Command ("ATTRIB +S +H +I `"$MountFolder\Windows\System32\Recovery\winre.wim`"") -ErrorAction SilentlyContinue)
            }
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            If ((Get-WindowsImage -Mounted).ImagePath -match "boot.wim")
            {
                Write-Host "Dismounting and Discarding the Boot Image." -ForegroundColor Cyan
                [void](Dismount-WindowsImage -Path $BootMount -Discard)
            }
            If ((Get-WindowsImage -Mounted).ImagePath -match "winre.wim")
            {
                Write-Host "Dismounting and Discarding the Recovery Image." -ForegroundColor Cyan
                [void](Dismount-WindowsImage -Path $RecoveryMount -Discard)
            }
        }
        Finally
        {
            Clear-Host
        }
    }
}

If ($Drivers)
{
    $DriverPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Drivers"
    If (Get-ChildItem -Path $DriverPath -Filter *.inf -Recurse -ErrorAction SilentlyContinue)
    {
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Injecting Driver Packages."
            Out-Log -Content "Injecting Driver Packages." -Level Info
            $InjectDriverPackages = @{
                Path             = $MountFolder
                Driver           = $DriverPath
                Recurse          = $true
                ForceUnsigned    = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            [void](Add-WindowsDriver @InjectDriverPackages)
            Get-WindowsDriver -Path $MountFolder | Out-File -FilePath $WorkFolder\InjectedDriverList.txt
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
    }
}

If ($NetFx3 -and (Get-WindowsOptionalFeature -Path $MountFolder -FeatureName NetFx3).State -eq "DisabledWithPayloadRemoved")
{
    If ($WimInfo.Build -eq '17134') { $NetFx3Path = Join-Path -Path $PSScriptRoot -ChildPath "Resources\NetFx3\17134" }
    ElseIf ($WimInfo.Build -eq '17763') { $NetFx3Path = Join-Path -Path $PSScriptRoot -ChildPath "Resources\NetFx3\17763" }
    If (Get-ChildItem -LiteralPath $NetFx3Path -Filter *NetFx3*.cab -ErrorAction SilentlyContinue)
    {
        Try
        {
            $EnableNetFx3 = @{
                FeatureName      = "NetFx3"
                Path             = $MountFolder
                All              = $true
                LimitAccess      = $true
                LogPath          = $DISMLog
                NoRestart        = $true
                ScratchDirectory = $ScratchFolder
                Source           = $NetFx3Path
                ErrorVariable    = '+ProcessError'
                ErrorAction      = "Stop"
            }
            $Host.UI.RawUI.WindowTitle = "Applying the .NET Framework Payload Packages."
            Out-Log -Content "Applying the .NET Framework Payload Packages." -Level Info
            [void](Enable-WindowsOptionalFeature @EnableNetFx3)
            Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt -Force -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
            Exit-Script
            Break
        }
    }
}

#region Registry Optimizations.
If ($Registry)
{
    [void](New-Item -Path $WorkFolder -Name Registry-Optimizations.log -ItemType File -Force)
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Applying Optimized Registry Settings."
        Out-Log -Content "Applying Optimized Registry Settings." -Level Info
        [void](Mount-OfflineHives)
        #****************************************************************
        Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OOBE" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HasAboveLockTips" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Cortana Outgoing Network Traffic." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana ActionUriServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe|Name=Block Cortana ActionUriServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana PlacesServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe|Name=Block Cortana PlacesServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana RemindersServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana RemindersServer.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana RemindersShareTargetApp.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe|Name=Block Cortana RemindersShareTargetApp.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana SearchUI.exe" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block Cortana SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" `
            -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
            -Name "Block Cortana Package" `
            -Value "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Cortana Package|Desc=Block Cortana Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|Platform=2:6:2|Platform2=GTEQ|" `
            -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling System Telemetry and Data Collecting." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling System Location Sensors." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -ErrorAction SilentlyContinue
        If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration")
        {
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 100 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling WiFi Sense." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        If ($RemovedSystemApps -contains "Microsoft.BioEnrollment")
        {
            #****************************************************************
            Write-Output "Disabling Biometric and Microsoft Hello Services." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider" -ErrorVariable +ProcessError -ErrorAction Stop
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider" -Name "Domain Accounts" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        If ($RemovedSystemApps -contains "Microsoft.Windows.SecureAssessmentBrowser")
        {
            #****************************************************************
            Write-Output "Disabling Text Suggestions and Screen Monitoring." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Disabling Windows Asking for Feedback." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Explorer Document and History Tracking." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling System Advertisements and Windows Spotlight." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Toast Notifications." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Typing Data Telemetry." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Automatic Download of Content, Ads and Suggestions." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ErrorVariable +ProcessError -ErrorAction Stop
        @("ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RotatingLockScreenEnabled",
            "RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContent-202914Enabled",
            "SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled", "SubscribedContent-310091Enabled",
            "SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314559Enabled", "SubscribedContent-314563Enabled", "SubscribedContent-338380Enabled", 
            "SubscribedContent-338381Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled", 
            "SubscribedContent-353696Enabled", "SubscribedContent-353698Enabled") | ForEach {
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_ -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Automatic Download File Blocking." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Notifications on Lock Screen." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Automatic Map Updates." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\Maps" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling WSUS Advertising and Metadata Collection." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling WSUS Featured Ads, Auto-Update and Auto-Reboot." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "EnableFeaturedSoftware" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling Cross-Device Sharing and Shared Experiences." >>  "$WorkFolder\Registry-Optimizations.log"
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Hiding 'Recently Added Apps' on Start Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Error Reporting." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling First Log-on Animation." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Start-up Sound and Boot Animation." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableStartupSound" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Changing Search Bar Icon to Magnifying Glass Icon." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Moving Drive Letter Before Drive Label." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Increasing Taskbar and Theme Transparency." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Removing the '-Shortcut' Trailing Text for Shortcuts." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -Name "ShortcutNameTemplate" -Value "%s.lnk" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling Explorer opens to This PC." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling Microsoft Edge Desktop Shortcut Creation." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling Microsoft Edge Pre-Launching at Start-up." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling Microsoft Edge Tracking." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling Internet Explorer First Run Wizard." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Store Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Mail Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling the Windows Mail Application." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling People Icon from Taskbar." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Combine TaskBar Icons when Full." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Enabling Small TaskBar Icons." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling 'How do you want to open this file?' prompt." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Switching to Smaller Control Panel Icons." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding This PC Icon to Desktop." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Live Tiles." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling the Sets Feature." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSets" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Connected Drive Autoplay and Autorun." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Removing 'Edit with Paint 3D and 3D Print' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        @('.3mf', '.bmp', '.fbx', '.gif', '.jfif', '.jpe', '.jpeg', '.jpg', '.png', '.tif', '.tiff') | ForEach {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\Shell\3D Edit" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\3D Edit" -Recurse -Force -ErrorAction SilentlyContinue
        }
        @('.3ds', '.3mf', '.dae', '.dxf', '.obj', '.ply', '.stl', '.wrl') | ForEach {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\shell\3D Print" -Recurse -Force -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Restoring Windows Photo Viewer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        @(".bmp", ".cr2", ".gif", ".ico", ".jfif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".wdp") | ForEach {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids" -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value (New-Object Byte[] 0) -Type Binary -ErrorAction SilentlyContinue
        }
        @("Paint.Picture", "giffile", "jpegfile", "pngfile") | ForEach {
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command" -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open" -Name "MuiVerb" -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" -Type ExpandString -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type ExpandString -ErrorAction SilentlyContinue
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type ExpandString -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Type ExpandString -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Removing 'Share' and 'Give Access To' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ModernSharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\CopyHookHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing" -Recurse -Force -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Removing 'Cast To Device' from the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Recently and Frequently Used Items in Explorer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Hiding User Folders from This PC and Explorer." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Value "Hide" -Type String -ErrorAction SilentlyContinue
        If ($WimInfo.Name -notlike "*LTSC")
        {
            #****************************************************************
            Write-Output "Removing Microsoft OneDrive Default Integration." >> "$WorkFolder\Registry-Optimizations.log"
            #****************************************************************
            Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -ErrorVariable +ProcessError -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\OneDrive" -ErrorVariable +ProcessError -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableMeteredNetworkFileSync" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\OneDrive" -Name "DisablePersonalSync" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Disabling Automatic Sound Reduction." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling Windows to use latest .NET Framework." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling the Fraunhofer IIS MPEG Layer-3 (MP3) Codec." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc")
        {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction SilentlyContinue
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (Professional)" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Increasing Icon Cache Size." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 8192 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Sticky Keys Prompt." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling Strong .NET Framework Cryptography." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Open with Notepad' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" -Name "Icon" -Value "Notepad.exe,-2" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" -Name "(default)" -Value "Notepad.exe %1" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Copy-Move' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB630-2971-11D1-A18C-00C04FD75D13}" -ErrorAction SilentlyContinue
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB631-2971-11D1-A18C-00C04FD75D13}" -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Install CAB Package' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -Recurse -Force -ErrorAction SilentlyContinue
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB\command" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -Name "(default)" -Value "Install" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB\command" -Name "(default)" -Value "CMD /K Dism /Online /Add-Package /PackagePath:`"%1`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Elevated Command-Prompt' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Icon" -Value "cmd.exe" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "SeparatorAfter" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Position" -Value "Bottom" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Icon" -Value "cmd.exe" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "SeparatorAfter" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Position" -Value "Bottom" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Elevated PowerShell' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "SeparatorAfter" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -Name "(default)" -Value "Powershell Start-Process PowerShell -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''`"%V`"''' -Verb RunAs" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Icon" -Value "PowerShell.exe" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "SeparatorAfter" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -Name "(default)" -Value "Powershell Start-Process PowerShell -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''`"%V`"''' -Verb RunAs" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Take Ownership' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "(default)" -Value "Take Ownership" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "NoWorkingDirectory" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "Position" -Value "Middle" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /C /L & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Name "IsolatedCommand" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /C /L & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "(default)" -Value "Take Ownership" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "AppliesTo" -Value "NOT (System.ItemPathDisplay:=`"C:\Users`" OR System.ItemPathDisplay:=`"C:\ProgramData`" OR System.ItemPathDisplay:=`"C:\Windows`" OR System.ItemPathDisplay:=`"C:\Windows\System32`" OR System.ItemPathDisplay:=`"C:\Program Files`" OR System.ItemPathDisplay:=`"C:\Program Files (x86)`")" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "NoWorkingDirectory" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "Position" -Value "Middle" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" /R /D Y && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /C /L /Q & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Name "IsolatedCommand" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" /R /D Y && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /C /L /Q & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Restart Explorer' to the Context Menu." >> "$WorkFolder\Registry-Optimizations.log"
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer" -ErrorVariable +ProcessError -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer\command" -ErrorVariable +ProcessError -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer" -Name "Icon" -Value "Explorer.exe" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer" -Name "Position" -Value "Bottom" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"(Get-Process -Name explorer).Kill()`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        $SetRegistryComplete = $true
        [void](Dismount-OfflineHives)
    }
    Catch
    {
        Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
        Exit-Script
        Break
    }
}
#endregion Registry Optimizations

Try
{
    $Host.UI.RawUI.WindowTitle = "Cleaning-up the Start Menu Layout Tiles."
    Out-Log -Content "Cleaning-up the Start Menu Layout Tiles." -Level Info
    $LinkFile = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Explorer UWP.lnk"
    $WShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WShell.CreateShortcut($LinkFile)
    $Shortcut.TargetPath = "%SystemRoot%\explorer.exe"
    $Shortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
    $Shortcut.WorkingDirectory = "%SystemRoot%"
    $Shortcut.Description = "UWP File Explorer"
    $Shortcut.Save()
    Start-Sleep 3
    $LayoutFile = "$MountFolder\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
    @'
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6">
        <start:Group Name="">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationID="Microsoft.Windows.ControlPanel" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Explorer UWP.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
</LayoutModificationTemplate>
'@ | Set-Content -Path $LayoutFile -Encoding UTF8 -Force
}
Finally
{
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($WShell)
}

If ((Test-Connection $Env:COMPUTERNAME -Quiet) -eq $true)
{
    $Host.UI.RawUI.WindowTitle = "Updating the Default Hosts File."
    Out-Log -Content "Updating the Default Hosts File." -Level Info
    $HostsFile = "$MountFolder\Windows\System32\drivers\etc\hosts"
    $HostsUpdate = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    Rename-Item -Path $HostsFile -NewName hosts.bak -Force -ErrorAction SilentlyContinue
    (New-Object System.Net.WebClient).DownloadFile($HostsUpdate, $HostsFile)
    (Get-Content -Path $HostsFile) | Set-Content -Path $HostsFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
}

If ((Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState -eq "Healthy")
{
    Out-Log -Content "Post-Optimization Image Health State: [Healthy]" -Level Info
    Start-Sleep 3
}
Else
{
    Out-Log -Content "The image has been flagged for corruption. Discarding optimizations." -Level Error
    Exit-Script
    Break
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Saving and Dismounting the Image."
    Out-Log -Content "Saving and Dismounting the Image." -Level Info
    If (Test-Path -LiteralPath "$MountFolder\`$Recycle.Bin") { Remove-Item -LiteralPath "$MountFolder\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue }
    $DismountWindowsImage = @{
        Path             = $MountFolder
        Save             = $true
        CheckIntegrity   = $true
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        ErrorVariable    = '+ProcessError'
        ErrorAction      = "Stop"
    }
    [void](Dismount-WindowsImage @DismountWindowsImage)
}
Catch
{
    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
    Exit-Script
    Break
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Rebuilding and Exporting the Image."
    Out-Log -Content "Rebuilding and Exporting the Image." -Level Info
    $ExportInstall = @{
        SourceImagePath      = $InstallWim
        SourceIndex          = $Index
        DestinationImagePath = "$($WorkFolder)\install.wim"
        CompressionType      = "Maximum"
        CheckIntegrity       = $true
        ScratchDirectory     = $ScratchFolder
        LogPath              = $DISMLog
        ErrorVariable        = '+ProcessError'
        ErrorAction          = "Stop"
    }
    [void](Export-WindowsImage @ExportInstall)
}
Catch
{
    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
    Exit-Script
    Break
}

If ($ISOIsExported -eq $true)
{
    $Host.UI.RawUI.WindowTitle = "Optimizing the Windows Media File Structure."
    Out-Log -Content "Optimizing the Windows Media File Structure." -Level Info
    Start-Sleep 3
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
    If (Test-Path -Path "$ISOMedia\sources\$($WimInfo.Language)\setup.exe.mui") { Move-Item -Path "$ISOMedia\sources\$($WimInfo.Language)\setup.exe.mui" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\EI.CFG") { Move-Item -Path "$ISOMedia\sources\EI.CFG" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\*.clg") { Move-Item -Path "$ISOMedia\sources\*.clg" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\gatherosstate.exe") { Move-Item -Path "$ISOMedia\sources\gatherosstate.exe" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\setup.exe") { Move-Item -Path "$ISOMedia\sources\setup.exe" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\lang.ini") { Move-Item -Path "$ISOMedia\sources\lang.ini" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\sources\pid.txt") { Move-Item -Path "$ISOMedia\sources\pid.txt" -Destination $ISOMedia -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path "$ISOMedia\sources\$($WimInfo.Language)\*.adml" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\$($WimInfo.Language)\*.mui" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\$($WimInfo.Language)\*.rtf" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ISOMedia\sources\$($WimInfo.Language)\*.txt" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
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
    If (Test-Path -Path "$ISOMedia\setup.exe.mui") { Move-Item -Path "$ISOMedia\setup.exe.mui" -Destination "$ISOMedia\sources\$($WimInfo.Language)" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\EI.CFG") { Move-Item -Path "$ISOMedia\EI.CFG" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path "$ISOMedia\*.clg" -Recurse -Force -ErrorAction SilentlyContinue | Move-Item -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$ISOMedia\gatherosstate.exe") { Move-Item -Path "$ISOMedia\gatherosstate.exe" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\setup.exe") { Move-Item -Path "$ISOMedia\setup.exe" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\lang.ini") { Move-Item -Path "$ISOMedia\lang.ini" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$ISOMedia\pid.txt") { Move-Item -Path "$ISOMedia\pid.txt" -Destination "$ISOMedia\sources" -Force -ErrorAction SilentlyContinue }
}

If ($ISOIsExported -eq $true -and $ISO.IsPresent)
{
    $ADK_ROOT = @("HKLM:\Software\Wow6432Node\Microsoft\Windows Kits\Installed Roots", "HKLM:\Software\Microsoft\Windows Kits\Installed Roots") | ForEach {
        Get-ItemProperty -LiteralPath $($_) -Name KitsRoot10 -ErrorAction Ignore | Select-Object -ExpandProperty KitsRoot10
    }
    If ($ADK_ROOT)
    {
        $DEPLOYMENT_TOOLS = Join-Path -Path $ADK_ROOT -ChildPath ("Assessment and Deployment Kit" + '\' + "Deployment Tools")
        $OSCDIMG = Join-Path -Path $DEPLOYMENT_TOOLS -ChildPath ($Env:PROCESSOR_ARCHITECTURE + '\' + "Oscdimg")
        If (Test-Path -Path "$($OSCDIMG)\oscdimg.exe")
        {
            $BootData = '2#p0,e,b"{0}"#pEF,e,b"{1}"' -f "$ISOMedia\boot\etfsboot.com", "$ISOMedia\efi\Microsoft\boot\efisys.bin"
            $ISOLabel = $($WimInfo.Name)
            $ISOName = $($WimInfo.Edition) + '.iso'
            $ISOName = $ISOName.Replace(' ', '')
            $ISOPath = Join-Path -Path $WorkFolder -ChildPath $ISOName
            $OscdimgArgs = @("-bootdata:${BootData}", '-u2', '-udfver102', "-l`"${ISOLabel}`"", "`"${ISOMedia}`"", "`"${ISOPath}`"")
            Try
            {
                $Host.UI.RawUI.WindowTitle = "Creating a Bootable Windows Installation Media ISO."
                Out-Log -Content "Creating a Bootable Windows Installation Media ISO." -Level Info
                Get-ChildItem -Path "$($WorkFolder)\*" -Include *.wim -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination "$($ISOMedia)\sources" -Force -ErrorVariable +ProcessError -ErrorAction Stop
                $Run = Start-Process -FilePath "$($OSCDIMG)\oscdimg.exe" -ArgumentList $OscdimgArgs -WindowStyle Hidden -Wait -PassThru
                $ISOIsCreated = $true
            }
            Catch
            {
                Out-Log -Content "Execute command: Oscdimg exited with exit code $($Run.ExitCode)" -Level Error
                Start-Sleep 3
            }
        }
    }
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Finalizing Optimizations."
    Out-Log -Content "Finalizing Optimizations." -Level Info
    [void]($SaveFolder = New-SaveDirectory)
    If ($ISOIsCreated -eq $true)
    {
        Move-Item -Path $ISOPath -Destination $SaveFolder -Force -ErrorVariable +ProcessError -ErrorAction Stop
    }
    Else
    {
        If ($ISOIsExported -eq $true)
        {
            Get-ChildItem -Path "$($WorkFolder)\*" -Include *.wim -Recurse -ErrorAction SilentlyContinue | Move-Item -Destination "$ISOMedia\sources" -Force -ErrorVariable +ProcessError -ErrorAction Stop
            Move-Item -Path $ISOMedia -Destination $SaveFolder -Force -ErrorVariable +ProcessError -ErrorAction Stop
        }
        Else
        {
            Get-ChildItem -Path "$($WorkFolder)\*" -Include *.wim -Recurse -ErrorAction SilentlyContinue | Move-Item -Destination $SaveFolder -Force -ErrorVariable +ProcessError -ErrorAction Stop
        }
    }
}
Catch
{
    Out-Log -Content "$($ProcessError.Exception.Message)" -Level Error
    $RemoveDirectory = $false
    Start-Sleep 3
}
Finally
{
    $Timer.Stop()
    [void](Clear-WindowsCorruptMountPoint)
    If ($ProcessError.Count.Equals(0))
    {
        Out-Log -Content "$ScriptName completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($ProcessError.Count)] errors." -Level Info
    }
    Else
    {
        $ErrorLog = Join-Path -Path $WorkFolder -ChildPath ErrorLog.log
        ForEach ($Process In $ProcessError) { Add-Content -Path $ErrorLog -Value $Process.Exception.Message -Force -ErrorAction SilentlyContinue }
        Write-Warning "$ScriptName completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($ProcessError.Count)] errors."
    }
    $TimeStamp = Get-Date -Format "MM.dd.yyyy HH:mm:ss"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations finalized at [$($TimeStamp)]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Remove-Item -Path $DISMLog -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    [void](Get-ChildItem -Path "$($WorkFolder)\*" -Include *.txt, *.log -Recurse -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$SaveFolder\OptimizeLogs.Zip" -CompressionLevel Fastest -ErrorAction SilentlyContinue)
    If ($RemoveDirectory -ne $false) { Remove-Item -Path $ScriptDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    [void]$RemovedSystemApps.Clear()
    ((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $_ }
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
