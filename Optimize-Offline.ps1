#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Module Dism
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 builds 1803-to-1809 64-bit architectures.
	
	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, enhanced privacy, cleaner aesthetics, increased performance and a significantly better user experience.
	
	.PARAMETER ImagePath
		The full path to a Windows Installation ISO or an install WIM file.
	
	.PARAMETER MetroApps
		Select = Populates and outputs a Gridview list of all Provisioned Application Packages for selective removal.
		All = Automatically removes all Provisioned Application Packages found in the image.
		Whitelist = Automatically removes all Provisioned Application Packages NOT found in the AppxWhiteList.xml file.
	
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
		Creates a new bootable Windows Installation Media ISO
		Requires the installation of the Windows ADK (Assessment and Deployment Kit).
		Only applicable when a Windows Installation Media ISO image is used as the source image.
	
	.PARAMETER Additional
		Integrates content found in the "Resources/Additional" directory into the image.
		All content is copied to those locations specified by Microsoft. If a location does not exist, it will automatically be created.
	
	.EXAMPLE
		.\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro\Win10Pro_Full.iso" -MetroApps "Select" -SystemApps -Packages -Features -Win32Calc -Dedup -DaRT -Registry -NetFx3 -Drivers -ISO
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
		Version:        3.2.4.1
		Last updated:	03/13/2019
		===========================================================================
#>
[CmdletBinding(HelpUri = 'https://github.com/DrEmpiricism/Optimize-Offline')]
Param
(
    [Parameter(Mandatory = $true,
        HelpMessage = 'The full path to a Windows Installation ISO or an install WIM file.')]
    [ValidateScript( {
            If ((Test-Path $(Resolve-Path -Path $_)) -and ($_ -ilike "*.iso")) { $_ }
            ElseIf ((Test-Path $(Resolve-Path -Path $_)) -and ($_ -ilike "*.wim")) { $_ }
            Else { Write-Warning ('Image path is invalid: "{0}"' -f $($_)); Break }
        })]
    [String]$ImagePath,
    [Parameter(HelpMessage = 'Determines the method used for the removal of Provisioned Application Packages.')]
    [ValidateSet('Select', 'All', 'Whitelist')]
    [Alias('Appx')]
    [String]$MetroApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all System Applications for selective removal.')]
    [Switch]$SystemApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all installed Windows Capability Packages for selective removal.')]
    [Switch]$Packages,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all enabled Windows Optional Features for selective disabling.')]
    [Switch]$Features,
    [Parameter(HelpMessage = 'Integrates the Microsoft Windows Store, and its dependencies, into the image.')]
    [Alias('Store')]
    [Switch]$WindowsStore,
    [Parameter(HelpMessage = 'Integrates the Microsoft Edge Browser packages into the image.')]
    [Alias('Edge')]
    [Switch]$MicrosoftEdge,
    [Parameter(HelpMessage = 'Integrates the traditional Calculator packages from Windows 10 Enterprise LTSC 2019 into the image.')]
    [Alias('Calc')]
    [Switch]$Win32Calc,
    [Parameter(HelpMessage = 'Integrates the Windows Server Data Deduplication packages into the image.')]
    [Switch]$Dedup,
    [Parameter(HelpMessage = 'Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools to Windows Setup and Windows Recovery.')]
    [Switch]$DaRT,
    [Parameter(HelpMessage = 'Injects driver packages into the image.')]
    [Switch]$Drivers,
    [Parameter(HelpMessage = 'Integrates the .NET Framework 3 payload packages into the image and enables the NetFx3 Windows Feature.')]
    [Switch]$NetFx3,
    [Parameter(HelpMessage = 'Integrates optimized registry values into the registry hives of the image.')]
    [Alias('Reg')]
    [Switch]$Registry,
    [Parameter(HelpMessage = 'Creates a new bootable Windows Installation Media ISO.')]
    [Switch]$ISO,
    [Parameter(HelpMessage = 'Integrates content found in the "Resources/Additional" directory into the image.')]
    [Alias('Add')]
    [Switch]$Additional
)

#region Script Variables
$Host.UI.RawUI.BackgroundColor = 'Black'; Clear-Host
$ProgressPreference = 'SilentlyContinue'
$ScriptName = 'Optimize-Offline'
$ScriptVersion = '3.2.4.1'
$ErrorEvent = 'Error event logged. Terminating process'
$AdditionalPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Additional"
$DaRTPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\DaRT"
$DedupPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Deduplication"
$DriverPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Drivers"
$EdgeAppPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\MicrosoftEdge"
$NetFx3Path = Join-Path -Path $PSScriptRoot -ChildPath "Resources\NetFx3"
$StoreAppPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\WindowsStore"
$AppxWhiteListPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\AppxWhiteList.xml"
$AppAssocListPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\CustomAppAssociations.xml"
$Win32CalcPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Win32Calc"
#endregion Script Variables

#region Helper Functions
Function Out-Log
{
    [CmdletBinding(DefaultParameterSetName = 'Info')]
    Param
    (
        [Parameter(ParameterSetName = 'Info')]
        [string]$Info,
        [Parameter(ParameterSetName = 'Error')]
        [string]$Error,
        [Parameter(ParameterSetName = 'Error',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
	
    Process
    {
        $Timestamp = Get-Date -Format 's'
        $LogMutex = New-Object System.Threading.Mutex($false, 'SyncLogMutex')
        Switch ($PSBoundParameters.Keys)
        {
            'Info'
            {
                [void]$LogMutex.WaitOne()
                Add-Content -Path $ScriptLog -Value "$Timestamp [INFO]: $Info" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                [void]$LogMutex.ReleaseMutex()
                Write-Host $Info -ForegroundColor Cyan
            }
            'Error'
            {
                [void]$LogMutex.WaitOne()
                Add-Content -Path $ScriptLog -Value "$Timestamp [ERROR]: $Error" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                [void]$LogMutex.ReleaseMutex()
                Write-Host $Error -ForegroundColor Red
                If ($PSBoundParameters.ContainsKey('ErrorRecord'))
                {
                    $ExceptionMessage = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
                    $ErrorRecord.FullyQualifiedErrorId,
                    $ErrorRecord.InvocationInfo.ScriptName,
                    $ErrorRecord.InvocationInfo.ScriptLineNumber,
                    $ErrorRecord.InvocationInfo.OffsetInLine
                    [void]$LogMutex.WaitOne()
                    Add-Content -Path $ScriptLog -Value "$Timestamp [ERROR]: $ExceptionMessage" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                    [void]$LogMutex.ReleaseMutex()
                    Write-Host $ExceptionMessage -ForegroundColor Red
                }
            }
        }
    }
}

Function New-OfflineDirectory
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Scratch', 'Image', 'Work', 'InstallMount', 'BootMount', 'RecoveryMount', 'Save')]
        [string]$Directory
    )
	
    If ($Directory.Equals('Scratch'))
    {
        $ScratchDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'ScratchOffline'))
        $ScratchDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $ScratchDirectory) -Force -ErrorAction SilentlyContinue
        $ScratchDirectory.FullName
    }
    ElseIf ($Directory.Equals('Image'))
    {
        $ImageDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'ImageOffline'))
        $ImageDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $ImageDirectory) -Force -ErrorAction SilentlyContinue
        $ImageDirectory.FullName
    }
    ElseIf ($Directory.Equals('Work'))
    {
        $WorkDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'WorkOffline'))
        $WorkDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $WorkDirectory) -Force -ErrorAction SilentlyContinue
        $WorkDirectory.FullName
    }
    ElseIf ($Directory.Equals('InstallMount'))
    {
        $InstallMountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountInstallOffline'))
        $InstallMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $InstallMountDirectory) -Force -ErrorAction SilentlyContinue
        $InstallMountDirectory.FullName
    }
    ElseIf ($Directory.Equals('BootMount'))
    {
        $BootMountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountBootOffline'))
        $BootMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $BootMountDirectory) -Force -ErrorAction SilentlyContinue
        $BootMountDirectory.FullName
    }
    ElseIf ($Directory.Equals('RecoveryMount'))
    {
        $RecoveryMountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountRecoveryOffline'))
        $RecoveryMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $RecoveryMountDirectory) -Force -ErrorAction SilentlyContinue
        $RecoveryMountDirectory.FullName
    }
    ElseIf ($Directory.Equals('Save'))
    {
        $SaveDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline"_[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
        $SaveDirectory = Get-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $SaveDirectory) -Force -ErrorAction SilentlyContinue
        $SaveDirectory.FullName
    }
}

Function Get-OfflineHives
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Load', 'Unload', 'Test')]
        [string]$Process
    )
	
    If ($Process.Equals('Load'))
    {
        @("LOAD HKLM\WIM_HKLM_SOFTWARE `"$MountFolder\Windows\System32\config\software`"",
            "LOAD HKLM\WIM_HKLM_SYSTEM `"$MountFolder\Windows\System32\config\system`"",
            "LOAD HKLM\WIM_HKCU `"$MountFolder\Users\Default\NTUSER.DAT`"") | ForEach { Start-Process -FilePath REG -ArgumentList $($_) -WindowStyle Hidden -Wait }
    }
    ElseIf ($Process.Equals('Unload'))
    {
        [System.GC]::Collect()
        @('UNLOAD HKLM\WIM_HKLM_SOFTWARE',
            'UNLOAD HKLM\WIM_HKLM_SYSTEM',
            'UNLOAD HKLM\WIM_HKCU') | ForEach { Start-Process -FilePath REG -ArgumentList $($_) -WindowStyle Hidden -Wait }
    }
    ElseIf ($Process.Equals('Test'))
    {
        @('HKLM:\WIM_HKLM_SOFTWARE',
            'HKLM:\WIM_HKLM_SYSTEM',
            'HKLM:\WIM_HKCU') | ForEach { If (Test-Path -Path $($_)) { $HivesLoaded = $true } }
        If ($HivesLoaded) { Return $HivesLoaded }
    }
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
    Out-Log -Info "Cleaning-up and terminating script."
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
    [void](Clear-WindowsCorruptMountPoint)
    [void]($SaveFolder = New-OfflineDirectory -Directory Save)
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations finalized at [$(Get-Date -Format 'MM.dd.yyyy HH:mm:ss')]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Remove-Item -Path $DISMLog -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    [void](Get-ChildItem -Path $WorkFolder -Include *.txt, *.log -Recurse -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$SaveFolder\OptimizeLogs.zip" -CompressionLevel Fastest -ErrorAction SilentlyContinue)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Break
}
#endregion Helper Functions

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Warning "Elevation is required to process optimizations. Relaunch $ScriptName as an administrator."; Break
}
Else
{
    $OSCaption = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption
    If ($OSCaption -notlike "Microsoft Windows 10*")
    {
        Write-Warning "Optimizing Windows 10 offline should be performed on a Windows 10 system."; Break
    }
}

If (Get-WindowsImage -Mounted)
{
    $Host.UI.RawUI.WindowTitle = "Performing clean-up of current mount path."
    Write-Host "Performing clean-up of current mount path." -ForegroundColor Cyan
    $MountFolder = (Get-WindowsImage -Mounted).MountPath
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') -ErrorAction SilentlyContinue
    If ($QueryHives) { $QueryHives | ForEach { [void](Invoke-Expression -Command ('REG UNLOAD $_') -ErrorAction SilentlyContinue) } }
    [void](Dismount-WindowsImage -Path $($MountFolder) -Discard -ErrorAction SilentlyContinue)
    [void](Clear-WindowsCorruptMountPoint)
    $MountFolder = $null
    Clear-Host
}

Try
{
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $ParentDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "OptimizeOfflineTemp_$(Get-Random)"))
    If ($ParentDirectory) { $ParentDirectory = Get-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $ParentDirectory) -Force }
    $Host.UI.RawUI.WindowTitle = "Preparing image for optimizations."
    $Timer = New-Object System.Diagnostics.Stopwatch
    $Timer.Start()
}
Catch
{
    Write-Warning $($_.Exception.Message)
    Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}


If (([IO.FileInfo]$ImagePath).Extension -eq '.ISO')
{
    $SourceImage = ([System.IO.Path]::ChangeExtension($ImagePath, ([System.IO.Path]::GetExtension($ImagePath)).ToString().ToLower()))
    $SourceName = [System.IO.Path]::GetFileNameWithoutExtension($SourceImage)
    $DriveLetter = (Mount-DiskImage -ImagePath $SourceImage -StorageType ISO -PassThru | Get-Volume).DriveLetter + ':'
    If (!(Test-Path -Path "$($DriveLetter)\sources\install.wim"))
    {
        Write-Warning ('"{0}" does not contain valid Windows Installation media.' -f $(Split-Path -Path $SourceImage -Leaf))
        Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
    Else
    {
        Write-Host ('Exporting media from "{0}"' -f $(Split-Path -Path $SourceImage -Leaf)) -ForegroundColor Cyan
        Try
        {
            $ISODrive = Get-Item -Path $DriveLetter -ErrorAction Stop
            $ISOMedia = Join-Path -Path $ParentDirectory -ChildPath $SourceName
            New-Container -Path $ISOMedia -ErrorAction Stop
            ForEach ($File In Get-ChildItem -Path $ISODrive.FullName -Recurse)
            {
                $MediaPath = $ISOMedia + $File.FullName.Replace($ISODrive, '\')
                Copy-Item -Path $($File.FullName) -Destination $MediaPath -Force -ErrorAction Stop
            }
            $ISOIsExported = $true
        }
        Catch
        {
            Write-Warning ('Unable to export media from "{0}"' -f $(Split-Path -Path $SourceImage -Leaf))
            Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
        Finally
        {
            Dismount-DiskImage -ImagePath $SourceImage -StorageType ISO
        }
        Try
        {
            [void]($MountFolder = New-OfflineDirectory -Directory InstallMount)
            [void]($ImageFolder = New-OfflineDirectory -Directory Image)
            [void]($WorkFolder = New-OfflineDirectory -Directory Work)
            [void]($ScratchFolder = New-OfflineDirectory -Directory Scratch)
            Move-Item -Path "$ISOMedia\sources\install.wim" -Destination $ImageFolder -ErrorAction Stop
            Set-ItemProperty -LiteralPath "$ImageFolder\install.wim" -Name IsReadOnly -Value $false -ErrorAction Stop
            $InstallWim = Get-ChildItem -Path $ImageFolder -Filter install.wim -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            If ((Test-Path -Path "$ISOMedia\sources\boot.wim") -and $DaRT.IsPresent)
            {
                Move-Item -Path "$ISOMedia\sources\boot.wim" -Destination $ImageFolder -ErrorAction Stop
                Set-ItemProperty -LiteralPath "$ImageFolder\boot.wim" -Name IsReadOnly -Value $false -ErrorAction Stop
                $BootWim = Get-ChildItem -Path $ImageFolder -Filter boot.wim -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            }
        }
        Catch
        {
            Write-Warning $($_.Exception.Message)
            Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
    }
}
ElseIf (([IO.FileInfo]$ImagePath).Extension -eq '.WIM')
{
    $SourceImage = ([System.IO.Path]::ChangeExtension($ImagePath, ([System.IO.Path]::GetExtension($ImagePath)).ToString().ToLower()))
    If (Test-Path -Path $SourceImage -Filter install.wim)
    {
        Try
        {
            Write-Host ('Copying WIM from "{0}"' -f $(Split-Path -Path $SourceImage -Parent)) -ForegroundColor Cyan
            [void]($MountFolder = New-OfflineDirectory -Directory InstallMount)
            [void]($ImageFolder = New-OfflineDirectory -Directory Image)
            [void]($WorkFolder = New-OfflineDirectory -Directory Work)
            [void]($ScratchFolder = New-OfflineDirectory -Directory Scratch)
            Copy-Item -Path $SourceImage -Destination $ImageFolder -ErrorAction Stop
            Set-ItemProperty -LiteralPath "$ImageFolder\install.wim" -Name IsReadOnly -Value $false -ErrorAction Stop
            $InstallWim = Get-ChildItem -Path $ImageFolder -Filter install.wim -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
        }
        Catch
        {
            Write-Warning $($_.Exception.Message)
            Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Break
        }
    }
    Else
    {
        Write-Warning ('The source image is not an install.wim: "{0}"' -f $(Split-Path -Path $SourceImage -Leaf))
        Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
}

If ((Get-WindowsImage -ImagePath $InstallWim).ImageIndex -gt 1)
{
    $EditionList = Get-WindowsImage -ImagePath $InstallWim | Select -Property @{ Label = 'Index'; Expression = { ($_.ImageIndex) } }, @{ Label = 'Name'; Expression = { ($_.ImageName) } }, @{ Label = 'Size (GB)'; Expression = { '{0:N2}' -f ($_.ImageSize / 1GB) } } | Out-GridView -Title "Select Windows 10 Edition." -OutputMode Single
    $ImageIndex = $EditionList.Index
}
Else
{
    $ImageIndex = 1
}

If ($ImageIndex)
{
    $WimImage = (Get-WindowsImage -ImagePath $InstallWim -Index $ImageIndex)
    $WimInfo = [PSCustomObject]@{
        Name     = $($WimImage.ImageName)
        Edition  = $($WimImage.EditionID)
        Version  = $($WimImage.Version)
        Build    = $($WimImage.Build.ToString())
        Language = $($WimImage.Languages)
    }
    If ($WimImage.Architecture -eq 9)
    {
        $WimInfo | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '9', 'amd64')
    }
}
Else
{
    Write-Warning "No Windows 10 Edition was selected to optimize."
    Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

If ($WimInfo.Architecture -ne 'amd64')
{
    Write-Warning "$($ScriptName) currently only supports 64-bit architectures."
    Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

If ($WimInfo.Edition.Contains('Server'))
{
    Write-Warning "Unsupported Image Edition: [$($WimInfo.Edition)]"
    Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

If ($WimInfo.Version.StartsWith(10))
{
    If ($WimInfo.Build -lt '17134' -or $WimInfo.Build -gt '17763')
    {
        Write-Warning "Unsupported Image Build: [$($WimInfo.Build)]"
        Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Break
    }
}
Else
{
    Write-Warning "Unsupported Image Version: [$($WimInfo.Version)]"
    Remove-Item -Path $ParentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Break
}

If ($WimInfo.Name -like "*LTSC")
{
    $IsLTSC = $true
    If ($MetroApps) { Remove-Variable MetroApps }
    If ($Win32Calc.IsPresent) { $Win32Calc = $false }
}
Else
{
    If ($WindowsStore.IsPresent) { $WindowsStore = $false }
    If ($MicrosoftEdge.IsPresent) { $MicrosoftEdge = $false }
}

Try
{
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    [void]($MountFolder = New-OfflineDirectory -Directory InstallMount)
    [void]($WorkFolder = New-OfflineDirectory -Directory Work)
    [void]($ScratchFolder = New-OfflineDirectory -Directory Scratch)
    $DISMLog = Join-Path -Path $WorkFolder -ChildPath DISM.log
    $ScriptLog = Join-Path -Path $WorkFolder -ChildPath Optimize-Offline.log
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "$ScriptName v$ScriptVersion starting at [$(Get-Date -Format 'MM.dd.yyyy HH:mm:ss')]"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizing image: `"$($WimInfo.Name)`""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value ""
    $Error.Clear()
    Out-Log -Info "Supported Image Build: [$($WimInfo.Build)]"
    Start-Sleep 3
    Out-Log -Info "Mounting $($WimInfo.Name)"
    $MountWindowsImage = @{
        ImagePath        = $InstallWim
        Index            = $ImageIndex
        Path             = $MountFolder
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        Optimize         = $true
        ErrorAction      = 'Stop'
    }
    [void](Mount-WindowsImage @MountWindowsImage)
}
Catch
{
    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
    Exit-Script
    Break
}

If ((Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState -eq 'Healthy')
{
    Out-Log -Info "Pre-Optimization Image Health State: [Healthy]"
}
Else
{
    Out-Log -Error "The image has been flagged for corruption. Further servicing is required before the image can be optimized."
    Exit-Script
    Break
}

If ($MetroApps -and (Get-AppxProvisionedPackage -Path $MountFolder).Count -gt 0)
{
    Clear-Host
    $RemovedAppxPackages = [System.Collections.ArrayList]@()
    $Host.UI.RawUI.WindowTitle = "Removing Metro Apps."
    If ($MetroApps.Equals('Select'))
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
                    Out-Log -Info "Removing Appx Provisioned Package: $($_.Split('_')[0])"
                    $RemoveSelectAppx = @{
                        Path             = $MountFolder
                        PackageName      = $($_)
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorAction      = 'Stop'
                    }
                    [void](Remove-AppxProvisionedPackage @RemoveSelectAppx)
                    [void]$RemovedAppxPackages.Add($($_.Split('_')[0]))
                }
                Clear-Host
            }
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
    ElseIf ($MetroApps.Equals('All'))
    {
        Try
        {
            Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
                Out-Log -Info "Removing Appx Provisioned Package: $($_.DisplayName)"
                $RemoveAllAppx = @{
                    Path             = $MountFolder
                    PackageName      = $($_.PackageName)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Remove-AppxProvisionedPackage @RemoveAllAppx)
                [void]$RemovedAppxPackages.Add($($_.DisplayName))
            }
            Clear-Host
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
    ElseIf (($MetroApps.Equals('Whitelist')) -and (Test-Path -Path $AppxWhitelistPath))
    {
        Try
        {
            [XML]$Whitelist = Get-Content -Path $AppxWhitelistPath
            Get-AppxProvisionedPackage -Path $MountFolder | ForEach {
                If ($_.DisplayName -notin $Whitelist.Appx.DisplayName)
                {
                    Out-Log -Info "Removing Appx Provisioned Package: $($_.DisplayName)"
                    $RemoveAppx = @{
                        Path             = $MountFolder
                        PackageName      = $($_.PackageName)
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorAction      = 'Stop'
                    }
                    [void](Remove-AppxProvisionedPackage @RemoveAppx)
                    [void]$RemovedAppxPackages.Add($($_.DisplayName))
                }
            }
            Clear-Host
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
}

If ($MetroApps.GetType().Name -eq 'String' -and (Test-Path -Path $AppAssocListPath)) 
{
    $Host.UI.RawUI.WindowTitle = "Importing Updated App Associations."
    Out-Log -Info "Importing Updated App Associations."
    Start-Sleep 3
    $ImportAssoc = ('/Image:"{0}" /Import-DefaultAppAssociations:"{1}"' -f $MountFolder, $AppAssocListPath)
    Start-Process -FilePath DISM -ArgumentList $ImportAssoc -WindowStyle Hidden -Wait
}

If ($SystemApps.IsPresent)
{
    Clear-Host
    $RemovedSystemApps = [System.Collections.ArrayList]@()
    $Host.UI.RawUI.WindowTitle = "Removing System Applications."
    Try
    {
        Write-Warning "Do NOT remove any System Application if you are unsure of its impact on a live installation."
        Start-Sleep 5
        Get-OfflineHives -Process Load
        $InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
        $PackageList = (Get-ChildItem -Path $InboxAppsKey -ErrorAction SilentlyContinue).Name.Split('\').Where{ $_ -like "Microsoft.*" }
        $InboxApps = $PackageList | Select -Property @{ Label = 'Name'; Expression = { ($_.Split('_')[0]) } }, @{ Label = 'Package'; Expression = { ($_) } } | Out-GridView -Title "Remove System Applications." -PassThru
        $RemoveSystemApps = $InboxApps.Package
        If ($RemoveSystemApps)
        {
            Clear-Host
            $RemoveSystemApps | ForEach {
                $FullKeyPath = Join-Path -Path $InboxAppsKey -ChildPath $($_)
                $FullKeyPath = $FullKeyPath -replace "HKLM:", "HKLM"
                Out-Log -Info "Removing System Application: $($_.Split('_')[0])"
                [void](Invoke-Expression -Command ('REG DELETE $FullKeyPath /F') -ErrorAction Stop)
                [void]$RemovedSystemApps.Add($($_.Split('_')[0]))
                Start-Sleep 2
            }
        }
        Get-OfflineHives -Process Unload
        Clear-Host
    }
    Catch
    {
        Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
        Exit-Script
        Break
    }
}

If ($Packages.IsPresent)
{
    Clear-Host
    $RemovedWindowsPackages = [System.Collections.ArrayList]@()
    $Host.UI.RawUI.WindowTitle = "Removing Windows Capability Packages."
    Try
    {
        $GetCapability = Get-WindowsCapability -Path $MountFolder | Where State -EQ Installed
        $Int = 1
        ForEach ($Capability In $GetCapability)
        {
            $GetCapability = New-Object -TypeName PSObject
            $GetCapability | Add-Member -MemberType NoteProperty -Name Num -Value $Int
            $GetCapability | Add-Member -MemberType NoteProperty -Name Name -Value $Capability.Name
            $GetCapability | Add-Member -MemberType NoteProperty -Name State -Value $Capability.State
            $Int++
            [void]$RemovedWindowsPackages.Add($GetCapability)
        }
        $RemovePackage = $RemovedWindowsPackages | Out-GridView -Title "Remove Windows Capability Packages." -PassThru
        $PackageName = $RemovePackage.Name
        If ($RemovePackage)
        {
            $PackageName | ForEach {
                Out-Log -Info "Removing Windows Capability Package: $($_.Split('~')[0])"
                $CapabilityPackage = @{
                    Path             = $MountFolder
                    Name             = $($_)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Remove-WindowsCapability @CapabilityPackage)
            }
            Clear-Host
        }
    }
    Catch
    {
        Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
        Exit-Script
        Break
    }
}

If ($RemovedSystemApps -contains 'Microsoft.Windows.SecHealthUI')
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Removing Windows Defender Remnants."
        Out-Log -Info "Disabling Windows Defender Services, Drivers and SmartScreen Integration."
        Get-OfflineHives -Process Load
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MRT" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows Security Health\State" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction Stop
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
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        If (($IsLTSC -and $MicrosoftEdge.IsPresent) -or (!$IsLTSC -and !$MicrosoftEdge))
        {
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        If ($WimInfo.Build -eq '17763')
        {
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControlEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControl" -Value "Anywhere" -Type String -ErrorAction SilentlyContinue
        }
        If ((Get-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue) -match "Enabled")
        {
            Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Force -ErrorAction SilentlyContinue
        }
        If ((Get-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue) -match "SecurityHealth")
        {
            Remove-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force -ErrorAction Stop
        }
        @("SecurityHealthService", "WinDefend", "WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense") | ForEach {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderApiLogger" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\DefenderAuditLogger" -Recurse -Force -ErrorAction SilentlyContinue
        Get-OfflineHives -Process Unload
    }
    Catch
    {
        Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
        Exit-Script
        Break
    }
    If ((Get-WindowsOptionalFeature -Path $MountFolder -FeatureName Windows-Defender-Default-Definitions).State -eq 'Enabled')
    {
        Try
        {
            Out-Log -Info "Disabling Windows Feature: Windows-Defender-Default-Definitions"
            $DisableDefenderFeature = @{
                Path             = $MountFolder
                FeatureName      = 'Windows-Defender-Default-Definitions'
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Disable-WindowsOptionalFeature @DisableDefenderFeature)
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
}

Try
{
    If ($RemovedAppxPackages -like "*Xbox*" -or $RemovedSystemApps -contains 'Microsoft.XboxGameCallableUI')
    {
        $Host.UI.RawUI.WindowTitle = "Removing Xbox Remnants."
        Out-Log -Info "Disabling Xbox Services and Drivers."
        Get-OfflineHives -Process Load
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -ErrorAction Stop
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
        Get-OfflineHives -Process Unload
    }
}
Catch
{
    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
    Exit-Script
    Break
}

If (Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -Like *SMB1* | Where State -EQ Enabled)
{
    $Host.UI.RawUI.WindowTitle = "Disabling the SMBv1 Protocol Windows Feature."
    Out-Log -Info "Disabling the SMBv1 Protocol Windows Feature."
    [void](Get-WindowsOptionalFeature -Path $MountFolder | Where FeatureName -Like *SMB1* | Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
}

If ($Features.IsPresent)
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
                Out-Log -Info "Disabling Windows Feature: $($_)"
                $DisableFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $($_)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Disable-WindowsOptionalFeature @DisableFeature)
            }
            Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt -Force -ErrorAction SilentlyContinue
        }
    }
    Catch
    {
        Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
        Exit-Script
        Break
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
                Out-Log -Info "Enabling Windows Feature: $($_)"
                $EnableFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $($_)
                    All              = $true
                    LimitAccess      = $true
                    NoRestart        = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Enable-WindowsOptionalFeature @EnableFeature)
            }
            Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt -Force -ErrorAction SilentlyContinue
            Clear-Host
        }
    }
    Catch
    {
        Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
        Exit-Script
        Break
    }
}

If ($WindowsStore.IsPresent)
{
    If (Test-Path -LiteralPath $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle)
    {
        $Host.UI.RawUI.WindowTitle = "Integrating the Microsoft Store Application Packages."
        Out-Log -Info "Integrating the Microsoft Store Application Packages."
        Try
        {
            $StoreBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $PurchaseBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.appxbundle -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $XboxBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.appxbundle -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $InstallerBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.appxbundle -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $StoreLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.xml -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $PurchaseLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.xml -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $IdentityLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.xml -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $InstallerLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.xml -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $DepAppx = @()
            $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter Microsoft.VCLibs*.appx -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Framework*.appx -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            Get-OfflineHives -Process Load
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord -ErrorAction Stop
            Get-OfflineHives -Process Unload
            $StorePackage = @{
                Path                  = $MountFolder
                PackagePath           = $StoreBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $StoreLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                ErrorAction           = 'Stop'
            }
            [void](Add-AppxProvisionedPackage @StorePackage)
            $PurchasePackage = @{
                Path                  = $MountFolder
                PackagePath           = $PurchaseBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $PurchaseLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                ErrorAction           = 'Stop'
            }
            [void](Add-AppxProvisionedPackage @PurchasePackage)
            $IdentityPackage = @{
                Path                  = $MountFolder
                PackagePath           = $XboxBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $IdentityLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                ErrorAction           = 'Stop'
            }
            [void](Add-AppxProvisionedPackage @IdentityPackage)
            $DepAppx = @()
            $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx -ErrorAction SilentlyContinue | Select -ExpandProperty FullName
            $InstallerPackage = @{
                Path                  = $MountFolder
                PackagePath           = $InstallerBundle
                DependencyPackagePath = $DepAppx
                LicensePath           = $InstallerLicense
                ScratchDirectory      = $ScratchFolder
                LogPath               = $DISMLog
                ErrorAction           = 'Stop'
            }
            [void](Add-AppxProvisionedPackage @InstallerPackage)
            Get-OfflineHives -Process Load
            Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Get-OfflineHives -Process Unload
            Get-AppxProvisionedPackage -Path $MountFolder | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\IntegratedPackages.txt -Append -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
    Else
    {
        Out-Log -Error "Missing the required Microsoft Store Application package files."
        Start-Sleep 3
    }
}

If ($MicrosoftEdge.IsPresent)
{
    If ($null -eq (Get-ChildItem -Path "$MountFolder\Windows\servicing\Packages" -Filter Microsoft-Windows-Internet-Browser-Package*.mum))
    {
        If (Test-Path -LiteralPath $EdgeAppPath -Filter Microsoft-Windows-Internet-Browser-Package*.cab)
        {
            $Host.UI.RawUI.WindowTitle = "Integrating the Microsoft Edge Browser Application Packages."
            Out-Log -Info "Integrating the Microsoft Edge Browser Application Packages."
            Try
            {
                $EdgeBasePackage = @{
                    Path             = $MountFolder
                    PackagePath      = "$EdgeAppPath\Microsoft-Windows-Internet-Browser-Package~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                    IgnoreCheck      = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Add-WindowsPackage @EdgeBasePackage)
                $EdgeLanguagePackage = @{
                    Path             = $MountFolder
                    PackagePath      = "$EdgeAppPath\Microsoft-Windows-Internet-Browser-Package~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                    IgnoreCheck      = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Add-WindowsPackage @EdgeLanguagePackage)
                Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Internet-Browser* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\IntegratedPackages.txt -Append -ErrorAction SilentlyContinue
            }
            Catch
            {
                Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
                Exit-Script
                Break
            }
        }
        Else
        {
            Out-Log -Error "Missing the required Microsoft Edge Browser Application Packages."
            Start-Sleep 3
        }
    }
    Else
    {
        Out-Log -Error "The Microsoft Edge Browser is already installed."
        Start-Sleep 3
    }
}

If ($Win32Calc.IsPresent)
{
    If ($null -eq (Get-ChildItem -Path "$MountFolder\Windows\servicing\Packages" -Filter Microsoft-Windows-win32calc-Package*.mum))
    {
        $Host.UI.RawUI.WindowTitle = "Integrating the Win32 Calculator Packages."
        Out-Log -Info "Integrating the Win32 Calculator Packages."
        If ($WimInfo.Build -eq '17763')
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
                        ErrorAction      = 'Stop'
                    }
                    [void](Add-WindowsPackage @CalcBasePackage)
                    $CalcLanguagePackage = @{
                        Path             = $MountFolder
                        PackagePath      = "$Win32CalcPath\Microsoft-Windows-win32calc-Package~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                        IgnoreCheck      = $true
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorAction      = 'Stop'
                    }
                    [void](Add-WindowsPackage @CalcLanguagePackage)
                    Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Windows-win32calc* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\IntegratedPackages.txt -Append -ErrorAction SilentlyContinue
                }
                Catch
                {
                    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
                    Exit-Script
                    Break
                }
                Try
                {
                    Get-OfflineHives -Process Load
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\RegisteredApplications" -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\RegisteredApplications" -Name "Windows Calculator" -Value "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Calculator\\Capabilities" -Type String -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationName" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationDescription" -Value "@%SystemRoot%\System32\win32calc.exe,-217" -Type ExpandString -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -Name "calculator" -Value "calculator" -Type String -ErrorAction SilentlyContinue
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationName" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities" -Name "ApplicationDescription" -Value "@%SystemRoot%\System32\win32calc.exe,-217" -Type ExpandString -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Applets\Calculator\Capabilities\URLAssociations" -Name "calculator" -Value "calculator" -Type String -ErrorAction Stop
                    Get-OfflineHives -Process Unload
                }
                Catch
                {
                    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
                    Exit-Script
                    Break
                }
            }
            Else
            {
                Out-Log -Error "Missing the required Win32 Calculator Packages."
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
                    Get-OfflineHives -Process Load
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -ErrorAction Stop
                    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon" -Name "(default)" -Value "@%SystemRoot%\System32\win32calc.exe,0" -Type ExpandString -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command" -Name "(default)" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorAction Stop
                    Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18" -Name "ShellExecute" -Value "@%SystemRoot%\System32\win32calc.exe" -Type ExpandString -ErrorAction Stop
                    Get-OfflineHives -Process Unload
                    $CalcLnk = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk"
                    $CalcShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
                    $CalcShortcut = $CalcShell.CreateShortcut($CalcLnk)
                    $CalcShortcut.TargetPath = "%SystemRoot%\System32\win32calc.exe"
                    $CalcShortcut.IconLocation = "%SystemRoot%\System32\win32calc.exe,0"
                    $CalcShortcut.Description = "Performs basic arithmetic tasks with an on-screen calculator."
                    $CalcShortcut.Save()
                    $IniFile = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini"
                    $CalcString = "Calculator.lnk=@%SystemRoot%\System32\shell32.dll,-22019"
                    If ((Get-Content -Path $IniFile).Contains($CalcString) -eq $false) { Add-Content -Path $IniFile -Value $CalcString -Encoding Unicode -Force -ErrorAction SilentlyContinue }
                }
                Catch
                {
                    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
                    Exit-Script
                    Break
                }
                Finally
                {
                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($CalcShell)
                }
                Try
                {
                    $SSDL = @'

D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
'@
                    $SSDL.Insert(0, "win32calc.exe") | Out-File -FilePath "$($WorkFolder)\SSDL.ini" -ErrorAction Stop
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\System32`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\SysWOW64`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    $SSDL.Insert(0, "win32calc.exe.mui") | Out-File -FilePath "$($WorkFolder)\SSDL.ini" -Force -ErrorAction Stop
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\System32\en-US`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    Start-Process -FilePath ICACLS -ArgumentList ("`"$MountFolder\Windows\SysWOW64\en-US`" /RESTORE `"$($WorkFolder)\SSDL.ini`" /T /C /Q") -WindowStyle Hidden -Wait
                    Remove-Item -Path "$($WorkFolder)\SSDL.ini" -Force
                    $TrustedInstaller = ((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')).Translate([System.Security.Principal.NTAccount]))
                    @("$MountFolder\Windows\System32\win32calc.exe", "$MountFolder\Windows\SysWOW64\win32calc.exe", "$MountFolder\Windows\System32\en-US\win32calc.exe.mui", "$MountFolder\Windows\SysWOW64\en-US\win32calc.exe.mui") | ForEach {
                        $ACL = Get-Acl -Path $($_) -ErrorAction Stop
                        $ACL.SetOwner($TrustedInstaller)
                        $ACL | Set-Acl -Path $($_) -ErrorAction Stop
                    }
                }
                Catch
                {
                    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
                    Exit-Script
                    Break
                }
            }
            Else
            {
                Out-Log -Error "Missing the required Win32 Calculator Packages."
                Start-Sleep 3
            }
        }
    }
    Else
    {
        Out-Log -Error "The Win32 Calculator is already installed."
        Start-Sleep 3
    }
}

If ($Dedup.IsPresent)
{
    If ((Test-Path -LiteralPath $DedupPath -Filter Microsoft-Windows-FileServer-ServerCore-Package*.cab) -and (Test-Path -LiteralPath $DedupPath -Filter Microsoft-Windows-Dedup-Package*.cab))
    {
        $Host.UI.RawUI.WindowTitle = "Integrating the Data Deduplication Packages."
        Out-Log -Info "Integrating the Data Deduplication Packages."
        Try
        {
            $FileServerCore = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Add-WindowsPackage @FileServerCore)
            $FileServerLang = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-FileServer-ServerCore-Package~31bf3856ad364e35~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Add-WindowsPackage @FileServerLang)
            $DedupCore = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($WimInfo.Architecture)~~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Add-WindowsPackage @DedupCore)
            $DedupLang = @{
                Path             = $MountFolder
                PackagePath      = "$DedupPath\Microsoft-Windows-Dedup-Package~31bf3856ad364e35~$($WimInfo.Architecture)~$($WimInfo.Language)~10.0.$($WimInfo.Build).1.cab"
                IgnoreCheck      = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Add-WindowsPackage @DedupLang)
            Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Windows-FileServer* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\IntegratedPackages.txt -Append -ErrorAction SilentlyContinue
            Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Windows-Dedup* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\IntegratedPackages.txt -Append -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Applying Data Deduplication Firewall Rules."
            Out-Log -Info "Applying Data Deduplication Firewall Rules."
            Start-Sleep 3
            Get-OfflineHives -Process Load
            New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-DCOM-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\System32\\svchost.exe|Svc=RPCSS|Name=File Server Remote Management (DCOM-In)|Desc=Inbound rule to allow DCOM traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-SMB-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=File Server Remote Management (SMB-In)|Desc=Inbound rule to allow SMB traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-Winmgmt-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\System32\\svchost.exe|Svc=Winmgmt|Name=File Server Remote Management (WMI-In)|Desc=Inbound rule to allow WMI traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-DCOM-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\System32\\svchost.exe|Svc=RPCSS|Name=File Server Remote Management (DCOM-In)|Desc=Inbound rule to allow DCOM traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-SMB-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=File Server Remote Management (SMB-In)|Desc=Inbound rule to allow SMB traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -Name "FileServer-ServerManager-Winmgmt-TCP-In" `
                -Value "v2.22|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\System32\\svchost.exe|Svc=Winmgmt|Name=File Server Remote Management (WMI-In)|Desc=Inbound rule to allow WMI traffic to manage the File Services role.|EmbedCtxt=File Server Remote Management|" `
                -Type String -ErrorAction Stop
            Get-OfflineHives -Process Unload
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Enabling Windows Feature: Dedup-Core"
            Out-Log -Info "Enabling Windows Feature: Dedup-Core"
            $EnableDedup = @{
                Path             = $MountFolder
                FeatureName      = "Dedup-Core"
                All              = $true
                LimitAccess      = $true
                NoRestart        = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Enable-WindowsOptionalFeature @EnableDedup)
            Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt -Force -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
}

If ($DaRT.IsPresent)
{
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Integrating Microsoft DaRT 10."
    If ((Test-Path -LiteralPath $DaRTPath -Filter MSDaRT10.wim) -and (Test-Path -LiteralPath $DaRTPath -Filter DebuggingTools_*.wim))
    {
        If ($WimInfo.Build -eq '17134') { $CodeName = 'RS4' }
        ElseIf ($WimInfo.Build -eq '17763') { $CodeName = 'RS5' }
        Try
        {
            If ($BootWim)
            {
                [void]($BootMount = New-OfflineDirectory -Directory BootMount)
                $MountBootImage = @{
                    Path             = $BootMount
                    ImagePath        = $BootWim
                    Index            = 2
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    Optimize         = $true
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Mounting the Boot Image."
                [void](Mount-WindowsImage @MountBootImage)
                $MSDaRT10Boot = @{
                    ImagePath        = "$DaRTPath\MSDaRT10.wim"
                    Index            = 1
                    ApplyPath        = $BootMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Integrating the Microsoft DaRT $($CodeName) Base Package into Windows Setup."
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
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Integrating the Windows 10 $($CodeName) Debugging Tools into Windows Setup."
                [void](Expand-WindowsImage @DeguggingToolsBoot)
                Start-Sleep 3
                If (!(Test-Path -Path "$BootMount\Windows\System32\fmapi.dll"))
                {
                    Copy-Item -Path "$MountFolder\Windows\System32\fmapi.dll" -Destination "$BootMount\Windows\System32" -Force
                }
                @'
[LaunchApps]
%WINDIR%\System32\wpeinit.exe
%WINDIR%\System32\netstart.exe
%SYSTEMDRIVE%\setup.exe
'@ | Out-File -FilePath "$BootMount\Windows\System32\winpeshl.ini" -Force
                If (Test-Path -LiteralPath "$BootMount\`$Recycle.Bin") { Remove-Item -LiteralPath "$BootMount\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue }
                $DismountBootImage = @{
                    Path             = $BootMount
                    Save             = $true
                    CheckIntegrity   = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Saving and Dismounting the Boot Image."
                [void](Dismount-WindowsImage @DismountBootImage)
                Out-Log -Info "Rebuilding the Boot Image."
                $ExportBoot = ('/Export-Image /SourceImageFile:"{0}" /All /DestinationImageFile:"{1}" /Compress:Max /CheckIntegrity /Quiet' -f "$($ImageFolder)\boot.wim", "$($WorkFolder)\boot.wim")
                Start-Process -FilePath DISM -ArgumentList $ExportBoot -WindowStyle Hidden -Wait
            }
            If (Test-Path -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -PathType Leaf)
            {
                $RemAttrib = ('-S -H -I "{0}"' -f "$MountFolder\Windows\System32\Recovery\winre.wim")
                Start-Process -FilePath ATTRIB -ArgumentList $RemAttrib -WindowStyle Hidden -Wait
                Copy-Item -Path "$MountFolder\Windows\System32\Recovery\winre.wim" -Destination $ImageFolder -Force
                [void]($RecoveryMount = New-OfflineDirectory -Directory RecoveryMount)
                $MountRecoveryImage = @{
                    Path             = $RecoveryMount
                    ImagePath        = "$($ImageFolder)\winre.wim"
                    Index            = 1
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    Optimize         = $true
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Mounting the Recovery Image."
                [void](Mount-WindowsImage @MountRecoveryImage)
                $MSDaRT10Recovery = @{
                    ImagePath        = "$DaRTPath\MSDaRT10.wim"
                    Index            = 1
                    ApplyPath        = $RecoveryMount
                    CheckIntegrity   = $true
                    Verify           = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Integrating the Microsoft DaRT $($CodeName) Base Package into Windows Recovery."
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
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Integrating the Windows 10 $($CodeName) Debugging Tools into Windows Recovery."
                [void](Expand-WindowsImage @DeguggingToolsRecovery)
                Start-Sleep 3
                If (!(Test-Path -Path "$RecoveryMount\Windows\System32\fmapi.dll"))
                {
                    Copy-Item -Path "$MountFolder\Windows\System32\fmapi.dll" -Destination "$RecoveryMount\Windows\System32" -Force
                }
                @'
[LaunchApps]
%WINDIR%\System32\wpeinit.exe
%WINDIR%\System32\netstart.exe
%SYSTEMDRIVE%\sources\recovery\recenv.exe
'@ | Out-File -FilePath "$RecoveryMount\Windows\System32\winpeshl.ini" -Force
                If (Test-Path -LiteralPath "$RecoveryMount\`$Recycle.Bin") { Remove-Item -LiteralPath "$RecoveryMount\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue }
                $DismountRecoveryImage = @{
                    Path             = $RecoveryMount
                    Save             = $true
                    CheckIntegrity   = $true
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                Out-Log -Info "Saving and Dismounting the Recovery Image."
                [void](Dismount-WindowsImage @DismountRecoveryImage)
                Out-Log -Info "Rebuilding the Recovery Image."
                $ExportRecovery = ('/Export-Image /SourceImageFile:"{0}" /All /DestinationImageFile:"{1}" /Compress:Max /CheckIntegrity /Quiet' -f "$($ImageFolder)\winre.wim", "$($WorkFolder)\winre.wim")
                Start-Process -FilePath DISM -ArgumentList $ExportRecovery -WindowStyle Hidden -Wait
                Move-Item -Path "$WorkFolder\winre.wim" -Destination "$MountFolder\Windows\System32\Recovery" -Force
                $AddAttrib = ('+S +H +I "{0}"' -f "$MountFolder\Windows\System32\Recovery\winre.wim")
                Start-Process -FilePath ATTRIB -ArgumentList $AddAttrib -WindowStyle Hidden -Wait
            }
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            @($BootMount, $RecoveryMount) | ForEach {
                [void](Dismount-WindowsImage -Path $($_) -Discard -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
            }
        }
        Finally
        {
            Clear-Host
        }
    }
}

If ($Drivers.IsPresent)
{
    If (Get-ChildItem -Path $DriverPath -Filter *.inf -Exclude ReadMe.txt -Recurse)
    {
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Injecting Driver Packages."
            Out-Log -Info "Injecting Driver Packages."
            $InjectDriverPackages = @{
                Path             = $MountFolder
                Driver           = $DriverPath
                Recurse          = $true
                ForceUnsigned    = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Add-WindowsDriver @InjectDriverPackages)
            Get-WindowsDriver -Path $MountFolder | Out-File -FilePath $WorkFolder\InjectedDrivers.txt -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
}

If ($NetFx3.IsPresent -and (Get-WindowsOptionalFeature -Path $MountFolder -FeatureName NetFx3).State -eq 'DisabledWithPayloadRemoved')
{
    If ($WimInfo.Build -eq '17134') { $NetFx3Path = Join-Path -Path $NetFx3Path -ChildPath '17134' }
    ElseIf ($WimInfo.Build -eq '17763') { $NetFx3Path = Join-Path -Path $NetFx3Path -ChildPath '17763' }
    If (Get-ChildItem -LiteralPath $NetFx3Path -Filter *NetFx3*.cab)
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
                ErrorAction      = 'Stop'
            }
            $Host.UI.RawUI.WindowTitle = "Integrating the .NET Framework Payload Packages."
            Out-Log -Info "Integrating the .NET Framework Payload Packages."
            [void](Enable-WindowsOptionalFeature @EnableNetFx3)
            Get-WindowsOptionalFeature -Path $MountFolder | Select -Property FeatureName, State | Out-File -FilePath $WorkFolder\WindowsFeatures.txt -Force -ErrorAction SilentlyContinue
            Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Windows-NetFx3* | Select -ExpandProperty PackageName | Out-File -FilePath $WorkFolder\IntegratedPackages.txt -Append -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
            Exit-Script
            Break
        }
    }
}

#region Registry Optimizations.
If ($Registry.IsPresent)
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Applying Registry Hive Settings."
        Out-Log -Info "Applying Optimizations to the Offline Registry Hives."
        $RegLog = Join-Path -Path $WorkFolder -ChildPath Registry-Optimizations.log
        If ($null -ne (Get-WindowsPackage -Path $MountFolder | Where PackageName -Like *Internet-Browser*)) { $EdgeIntegrated = $true }
        Get-OfflineHives -Process Load
        #****************************************************************
        Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OOBE" -ErrorAction Stop
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
        Write-Output "Disabling Cortana Outgoing Network Traffic." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ErrorAction Stop
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
        Write-Output "Disabling System Telemetry and Data Collecting." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -ErrorAction Stop
        If ($IsLTSC -or $WimInfo.Name -like "*Enterprise*") { $TelemetryLevel = 0 }
        Else { $TelemetryLevel = 1 }
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value $TelemetryLevel -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value $TelemetryLevel -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value $TelemetryLevel -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling System Location Sensors." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -ErrorAction SilentlyContinue
        If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration")
        {
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        If ($WimInfo.Build -eq '17763')
        {
            #****************************************************************
            Write-Output "Disabling Clipboard History and Service." >> $RegLog
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Clipboard" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\cbdhsvc")
            {
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\cbdhsvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        #****************************************************************
        Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 100 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling WiFi Sense." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        If ($RemovedAppxPackages -contains 'Microsoft.WindowsMaps')
        {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker")
            {
                #****************************************************************	
                Write-Output "Disabling the Windows Maps Appx Service." >> $RegLog
                #****************************************************************
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\MapsBroker" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        If ($RemovedAppxPackages -contains 'Microsoft.Wallet')
        {
            If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService")
            {
                #****************************************************************	
                Write-Output "Disabling the Microsoft Wallet Appx Service." >> $RegLog
                #****************************************************************
                Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WalletService" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        If ($RemovedSystemApps -contains 'Microsoft.BioEnrollment')
        {
            #****************************************************************
            Write-Output "Disabling Biometric and Microsoft Hello Service." >> $RegLog
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider" -ErrorAction Stop
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
            Write-Output "Disabling Text Suggestions and Screen Monitoring." >> $RegLog
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowScreenMonitoring" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "AllowTextSuggestions" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\SecureAssessment" -Name "RequirePrinting" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Disabling Activity History." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Asking for Feedback." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Explorer Document and History Tracking." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling System Advertisements and Windows Spotlight." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Toast Notifications." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Typing Data Telemetry." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Automatic Download of Content, Ads and Suggestions." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ErrorAction Stop
        @("ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RotatingLockScreenEnabled",
            "RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContent-202914Enabled",
            "SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled", "SubscribedContent-310091Enabled",
            "SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314559Enabled", "SubscribedContent-314563Enabled", "SubscribedContent-338380Enabled",
            "SubscribedContent-338381Enabled", "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled",
            "SubscribedContent-353696Enabled", "SubscribedContent-353698Enabled") | ForEach {
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_ -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Automatic Download File Blocking." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Notifications on Lock Screen." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Automatic Map Updates." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\Maps" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Advertising ID for Apps." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling WSUS Advertising and Metadata Collection." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling WSUS Featured Ads, Auto-Update and Auto-Reboot." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "EnableFeaturedSoftware" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Microsoft Account Sign-in Assistant." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling Cross-Device Sharing and Shared Experiences." >>  $RegLog
        #***************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Hiding 'Recently Added Apps' list from the Start Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Hiding 'Most Used Apps' list from the Start Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Error Reporting." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling First Log-on Animation." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Start-up Sound." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableStartupSound" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Changing Search Bar Icon to Magnifying Glass Icon." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Moving Drive Letter Before Drive Label." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Increasing Taskbar and Theme Transparency." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Removing the '-Shortcut' Trailing Text for Shortcuts." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -Name "ShortcutNameTemplate" -Value "%s.lnk" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling the Shortcut Arrow for Shortcuts." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Value "%SystemRoot%\System32\imageres.dll,-1015" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling Explorer opens to This PC." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        (($IsLTSC -and $MicrosoftEdge.IsPresent) -or (!$IsLTSC -and !$MicrosoftEdge))
        {
            #****************************************************************
            Write-Output "Disabling Microsoft Edge Desktop Shortcut Creation." >> $RegLog
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            #****************************************************************
            Write-Output "Disabling Microsoft Edge Pre-Launching at Start-up." >> $RegLog
            #****************************************************************
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "PreventTabPreloading" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            #****************************************************************	
            Write-Output "Disabling Microsoft Edge Tracking." >> $RegLog
            #****************************************************************
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
        #****************************************************************	
        Write-Output "Disabling Internet Explorer First Run Wizard." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Store Icon from Taskbar." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Windows Mail Icon from Taskbar." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling the Windows Mail Application." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Disabling People Icon from Taskbar." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Combine TaskBar Icons when Full." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Enabling Small TaskBar Icons." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling 'How do you want to open this file?' prompt." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling the Classic Control Panel Icons." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding Classic Personalization to the Control Panel." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\DefaultIcon" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\shell" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\shell\Open" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\shell\Open\Command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "(default)" -Value "Personalization (Classic)" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "InfoTip" -Value "@%SystemRoot%\\System32\\themecpl.dll,-2#immutable1" -Type ExpandString -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "System.ApplicationName" -Value "Microsoft.Personalization" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "System.ControlPanel.Category" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "System.Software.TasksFileUrl" -Value "Internal" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\DefaultIcon" -Name "(default)" -Value "%SystemRoot%\\System32\\themecpl.dll,-1" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}\shell\Open\Command" -Name "(default)" -Value "explorer.exe shell:::{ED834ED6-4B5A-4bfe-8F11-A626DCB6A921}" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{580722FF-16A7-44C1-BF74-7E1ACD00F4F9}" -Name "(default)" -Value "Personalization" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding This PC Icon to Desktop." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Live Tiles." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling the Sets Feature." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSets" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Connected Drive Autoplay and Autorun." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************	
        Write-Output "Removing 'Edit with Paint 3D and 3D Print' from the Context Menu." >> $RegLog
        #****************************************************************
        @('.3mf', '.bmp', '.fbx', '.gif', '.jfif', '.jpe', '.jpeg', '.jpg', '.png', '.tif', '.tiff') | ForEach {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\Shell\3D Edit" -Recurse -Force -ErrorAction SilentlyContinue
        }
        @('.3ds', '.3mf', '.dae', '.dxf', '.obj', '.ply', '.stl', '.wrl') | ForEach {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\shell\3D Print" -Recurse -Force -ErrorAction SilentlyContinue
        }
        #****************************************************************
        Write-Output "Restoring Windows Photo Viewer." >> $RegLog
        #****************************************************************
        @(".bmp", ".cr2", ".gif", ".ico", ".jfif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".wdp") | ForEach {
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value (New-Object Byte[] 0) -Type Binary -ErrorAction SilentlyContinue
        }
        @("Paint.Picture", "giffile", "jpegfile", "pngfile") | ForEach {
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open" -ErrorAction Stop
            New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command" -ErrorAction Stop
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open" -Name "MuiVerb" -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" -Type ExpandString -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type String -ErrorAction SilentlyContinue
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Removing 'Share' and 'Give Access To' from the Context Menu." >> $RegLog
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
        Write-Output "Removing 'Cast To Device' from the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Recently and Frequently Used Items in Explorer." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Hiding User Folders from This PC and Explorer." >> $RegLog
        #****************************************************************
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ErrorAction Stop
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
        #****************************************************************
        Write-Output "Disabling Automatic Sound Reduction." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling Windows to use latest .NET Framework." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Increasing Icon Cache Size." >> $RegLog
        #****************************************************************
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 8192 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Disabling Sticky Keys Prompt." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Enabling Strong .NET Framework Cryptography." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Open with Notepad' to the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" -Name "Icon" -Value "Notepad.exe,-2" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" -Name "(default)" -Value "Notepad.exe %1" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Copy-Move' to the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB630-2971-11D1-A18C-00C04FD75D13}" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB631-2971-11D1-A18C-00C04FD75D13}" -ErrorAction Stop
        #****************************************************************
        Write-Output "Adding 'Install CAB Package' to the Context Menu." >> $RegLog
        #****************************************************************
        If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB")
        {
            Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB\command" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -Name "(default)" -Value "Install" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\shell\InstallCAB\command" -Name "(default)" -Value "CMD /K Dism /Online /Add-Package /PackagePath:`"%1`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Elevated Command-Prompt' to the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -ErrorAction Stop
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
        Write-Output "Adding 'Elevated PowerShell' to the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -ErrorAction Stop
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
        Write-Output "Adding 'Take Ownership' to the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "(default)" -Value "Take Ownership" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "NoWorkingDirectory" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership" -Name "Position" -Value "Middle" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /C /L /Q & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shell\TakeOwnership\command" -Name "IsolatedCommand" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /C /L /Q & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "(default)" -Value "Take Ownership" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "AppliesTo" -Value "NOT (System.ItemPathDisplay:=`"C:\Users`" OR System.ItemPathDisplay:=`"C:\ProgramData`" OR System.ItemPathDisplay:=`"C:\Windows`" OR System.ItemPathDisplay:=`"C:\Windows\System32`" OR System.ItemPathDisplay:=`"C:\Program Files`" OR System.ItemPathDisplay:=`"C:\Program Files (x86)`")" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "HasLUAShield" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "NoWorkingDirectory" -Value "" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership" -Name "Position" -Value "Middle" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" /R /D Y && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /T /C /L /Q & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -Name "IsolatedCommand" -Value "PowerShell -WindowStyle Hidden -Command `"Start-Process CMD -ArgumentList '/C TAKEOWN /F \`"%1\`" /R /D Y && ICACLS \`"%1\`" /GRANT *S-1-3-4:F /T /C /L /Q & PAUSE' -Verb RunAs`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Write-Output "Adding 'Restart Explorer' to the Context Menu." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer" -ErrorAction Stop
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer\command" -ErrorAction Stop
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer" -Name "Icon" -Value "Explorer.exe" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer" -Name "Position" -Value "Bottom" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Restart Explorer\command" -Name "(default)" -Value "PowerShell -WindowStyle Hidden -Command `"(Get-Process -Name explorer).Kill()`"" -Type String -ErrorAction SilentlyContinue
        #****************************************************************
        Get-OfflineHives -Process Unload
    }
    Catch
    {
        Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
        Exit-Script
        Break
    }
}
#endregion Registry Optimizations

Try
{
    $Host.UI.RawUI.WindowTitle = "Cleaning-up the Start Menu Layout."
    Out-Log -Info "Cleaning-up the Start Menu Layout."
    $UWPLnk = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Explorer UWP.lnk"
    $UWPShell = New-Object -ComObject WScript.Shell
    $UWPShortcut = $UWPShell.CreateShortcut($UWPLnk)
    $UWPShortcut.TargetPath = "%SystemRoot%\explorer.exe"
    $UWPShortcut.Arguments = "shell:AppsFolder\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App"
    $UWPShortcut.WorkingDirectory = "%SystemRoot%"
    $UWPShortcut.Description = "UWP File Explorer"
    $UWPShortcut.Save()
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
Catch
{
    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
    Exit-Script
    Break
}
Finally
{
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($UWPShell)
}

If ((Test-Connection $Env:COMPUTERNAME -Quiet) -eq $true)
{
    $Host.UI.RawUI.WindowTitle = "Updating the Default Hosts File."
    Out-Log -Info "Updating the Default Hosts File."
    $HostsFile = "$MountFolder\Windows\System32\drivers\etc\hosts"
    $HostsUpdate = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    Rename-Item -Path $HostsFile -NewName hosts.bak -Force -ErrorAction SilentlyContinue
    (New-Object System.Net.WebClient).DownloadFile($HostsUpdate, $HostsFile)
    (Get-Content -Path $HostsFile) | Set-Content -Path $HostsFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
}

Try
{
    If ($Additional.IsPresent -and (Get-ChildItem -Path $AdditionalPath -Directory | Measure-Object).Count -gt 0)
    {
        $Host.UI.RawUI.WindowTitle = "Copying Additional Setup Content."
        Out-Log -Info "Copying Additional Setup Content."
        If (Test-Path -Path "$AdditionalPath\Unattend" -Filter unattend.xml)
        {
            New-Container -Path "$MountFolder\Windows\Panther" -ErrorAction SilentlyContinue
            Get-ChildItem -Path "$AdditionalPath\Unattend" -Filter unattend.xml -Recurse | Copy-Item -Destination "$MountFolder\Windows\Panther"
        }
        If (Test-Path -Path "$AdditionalPath\Setup\*")
        {
            New-Container -Path "$MountFolder\Windows\Setup\Scripts" -ErrorAction SilentlyContinue
            Get-ChildItem -Path "$AdditionalPath\Setup" -Recurse | Copy-Item -Destination "$MountFolder\Windows\Setup\Scripts" -Recurse
        }
        If (Test-Path -Path "$AdditionalPath\Wallpaper" -PathType Container)
        {
            Get-ChildItem -Path "$AdditionalPath\Wallpaper" -Directory | Copy-Item -Destination "$MountFolder\Windows\Web\Wallpaper" -Recurse
        }
        If (Test-Path -Path "$AdditionalPath\Wallpaper\*" -Include *.jpg, *.png, *.bmp, *.gif)
        {
            Get-ChildItem -Path "$AdditionalPath\Wallpaper\*" -Include *.jpg, *.png, *.bmp, *.gif -File | Copy-Item -Destination "$MountFolder\Windows\Web\Wallpaper"
        }
        If (Test-Path -Path "$AdditionalPath\Logo" -Filter *.bmp)
        {
            New-Container -Path "$MountFolder\Windows\System32\oobe\info\logo" -ErrorAction SilentlyContinue
            Get-ChildItem -Path "$AdditionalPath\Logo" -Filter *.bmp -File | Copy-Item -Destination "$MountFolder\Windows\System32\oobe\info\logo"
        }
    }
}
Catch
{
    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
    If (Test-Path -Path "$MountFolder\Windows\Panther") { Remove-Item -Path "$MountFolder\Windows\Panther" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\Setup\Scripts") { Remove-Item -Path "$MountFolder\Windows\Setup\Scripts" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Test-Path -Path "$MountFolder\Windows\System32\oobe\info\logo") { Remove-Item -Path "$MountFolder\Windows\System32\oobe\info" -Recurse -Force -ErrorAction SilentlyContinue }
    Start-Sleep 3
}

If ((Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState -eq 'Healthy')
{
    Out-Log -Info "Post-Optimization Image Health State: [Healthy]"
    Start-Sleep 3
}
Else
{
    Out-Log -Error "The image has been flagged for corruption. Discarding optimizations."
    Exit-Script
    Break
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Saving and Dismounting the Image."
    Out-Log -Info "Saving and Dismounting the Image."
    If (Test-Path -LiteralPath "$MountFolder\`$Recycle.Bin") { Remove-Item -LiteralPath "$MountFolder\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue }
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    $DismountWindowsImage = @{
        Path             = $MountFolder
        Save             = $true
        CheckIntegrity   = $true
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        ErrorAction      = 'Stop'
    }
    [void](Dismount-WindowsImage @DismountWindowsImage)
}
Catch
{
    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
    Exit-Script
    Break
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Rebuilding and Exporting the Image."
    Out-Log -Info "Rebuilding and Exporting the Image."
    $ExportInstall = ('/Export-Image /SourceImageFile:"{0}" /All /DestinationImageFile:"{1}" /Compress:Max /CheckIntegrity /Quiet' -f $InstallWim, "$($WorkFolder)\install.wim")
    $RunExport = Start-Process -FilePath DISM -ArgumentList $ExportInstall -WindowStyle Hidden -Wait -PassThru
}
Catch
{
    Out-Log -Error ('Rebuild and export failed with error code "{0}"' -f $($RunExport.ExitCode))
    If (Test-Path -Path "$($WorkFolder)\install.wim") { Remove-Item -Path "$($WorkFolder)\install.wim" -Force -ErrorAction SilentlyContinue }
    Move-Item -Path $InstallWim -Destination $WorkFolder -Force -ErrorAction SilentlyContinue
}

If ($ISOIsExported)
{
    $Host.UI.RawUI.WindowTitle = "Optimizing the Windows Media File Structure."
    Out-Log -Info "Optimizing the Windows Media File Structure."
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
    Get-ChildItem -Path $WorkFolder -Filter *.wim -ErrorAction SilentlyContinue | Copy-Item -Destination "$($ISOMedia)\sources" -Force -ErrorAction SilentlyContinue
    If ($ISO.IsPresent)
    {
        $ADK_ROOT = @("HKLM:\Software\Wow6432Node\Microsoft\Windows Kits\Installed Roots", "HKLM:\Software\Microsoft\Windows Kits\Installed Roots") | ForEach {
            Get-ItemProperty -LiteralPath $($_) -Name KitsRoot10 -ErrorAction Ignore | Select -ExpandProperty KitsRoot10 | Where { $($_) }
        }
        $OSCDIMG = Join-Path -Path $ADK_ROOT -ChildPath ('Assessment and Deployment Kit' + '\' + 'Deployment Tools' + '\' + $Env:PROCESSOR_ARCHITECTURE + '\' + 'Oscdimg')
        If (Test-Path -Path "$($OSCDIMG)\oscdimg.exe")
        {
            $BootData = '2#p0,e,b"{0}"#pEF,e,b"{1}"' -f "$ISOMedia\boot\etfsboot.com", "$ISOMedia\efi\Microsoft\boot\efisys.bin"
            $ISOLabel = $($WimInfo.Name)
            $ISOName = $($WimInfo.Edition).Replace(' ', '') + "_$($WimInfo.Build).iso"
            $ISOPath = Join-Path -Path $WorkFolder -ChildPath $ISOName
            $OscdimgArgs = @("-bootdata:${BootData}", '-u2', '-udfver102', "-l`"$($ISOLabel)`"", "`"$($ISOMedia)`"", "`"$($ISOPath)`"")
            Try
            {
                $Host.UI.RawUI.WindowTitle = "Creating a Bootable Windows Installation Media ISO."
                Out-Log -Info "Creating a Bootable Windows Installation Media ISO."
                $Run = Start-Process -FilePath "$($OSCDIMG)\oscdimg.exe" -ArgumentList $OscdimgArgs -WindowStyle Hidden -Wait -PassThru
                $ISOIsCreated = $true
            }
            Catch
            {
                $Run = "Execute command: Oscdimg exited with exit code $($Run.ExitCode)"
                Out-Log -Error $Run
                Start-Sleep 3
            }
        }
        Else
        {
            Out-Log -Error "Oscdimg premastering tool not found. Skipping ISO creation."
            Start-Sleep 3
        }
    }
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Finalizing Optimizations."
    Out-Log -Info "Finalizing Optimizations."
    [void]($SaveFolder = New-OfflineDirectory -Directory Save)
    If ($ISOIsCreated) { Move-Item -Path $ISOPath -Destination $SaveFolder -Force -ErrorAction Stop }
    Else
    {
        If ($ISOIsExported) { Move-Item -Path $ISOMedia -Destination $SaveFolder -Force -ErrorAction Stop }
        Else { Get-ChildItem -Path $WorkFolder -Filter *.wim -ErrorAction SilentlyContinue | Move-Item -Destination $SaveFolder -Force -ErrorAction Stop }
    }
}
Catch
{
    Out-Log -Error $ErrorEvent -ErrorRecord $Error[0]
    Start-Sleep 3
}
Finally
{
    $Timer.Stop()
    Out-Log -Info "$ScriptName completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($Error.Count)] errors."
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations finalized at [$(Get-Date -Format 'MM.dd.yyyy HH:mm:ss')]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Remove-Item -Path $DISMLog -Force -ErrorAction SilentlyContinue
    If (Test-Path -Path "$Env:SystemRoot\Logs\DISM\dism.log") { Remove-Item -Path "$Env:SystemRoot\Logs\DISM\dism.log" -Force -ErrorAction SilentlyContinue }
    [void](Get-ChildItem -Path $WorkFolder -Include *.txt, *.log -Recurse -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$SaveFolder\OptimizeLogs.zip" -CompressionLevel Fastest -ErrorAction SilentlyContinue)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeOfflineTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    [void](Clear-WindowsCorruptMountPoint)
    $Host.UI.RawUI.WindowTitle = "Optimizations Complete."
}
# SIG # Begin signature block
# MIIMCAYJKoZIhvcNAQcCoIIL+TCCC/UCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5Ky8aATA2G24++Yxdg5MCAPw
# jDKgggj8MIIDfTCCAmWgAwIBAgIQfY66zkudTZ9EnV2nSZm8oDANBgkqhkiG9w0B
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
# FiUxggJ2MIICcgIBATBcMEUxFDASBgoJkiaJk/IsZAEZFgRURUNIMRUwEwYKCZIm
# iZPyLGQBGRYFT01OSUMxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0ECEyEAAAAFfOz8
# 2RcyuMQAAAAAAAUwCQYFKw4DAhoFAKCB8DAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUkIXyyBAodNa3otBkpodoWG9QBQ4wgY8GCisGAQQBgjcCAQwxgYAwfqBQgE4A
# VwBpAG4AZABvAHcAcwAgADEAMAAgAE8AZgBmAGwAaQBuAGUAIABPAHAAdABpAG0A
# aQB6AGEAdABpAG8AbgAgAFMAYwByAGkAcAB0AC6hKoAoV2luZG93cyAxMCBPZmZs
# aW5lIE9wdGltaXphdGlvbiBTY3JpcHQuIDANBgkqhkiG9w0BAQEFAASCAQAUwW5h
# TaOY2iBU6BASUG2nMgEgvOmpce2bgm9I+WeUR7cdjsFfuuhjNYGOcxi9rmIPy/Gb
# 9jwBMImUUVbhBu8jkLd6zHcyX/TczxBTRa+3I0/OuKO0uvACrzqvtNq4267Juxlc
# h98lWBaF7dMiEAKKDGqI3TutK90MXQvD/dz+7I3RXu2GkKj7uk8FMRvTup1+6S9V
# lS1CuiY9r2IACznoL5kzbW34o5zMtiBCZdasouTF4raCF7S6QPniEP1b3e7yEWWr
# fqSPYSaLAguO55KDHXLJRqMDT6pI/9Tm8hXccMd7yShqlNEYjeDyYRbyEAedbPdb
# SI3z4Dz8ODViN+K9
# SIG # End signature block
