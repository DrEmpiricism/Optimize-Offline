Function Additional-Features {
    <#
	.SYNOPSIS
		This is a function that can be called by the main Optimize-Offline script that will add additional features for a more device-specific final image.
	
	.DESCRIPTION
		If the switch for this function is used by the main Optimize-Offline script, it will be called before the image is finalized.
	
	.PARAMETER ContextMenu
		Adds Copy-Move, Create a Quick Restore Point, Extended Disk Clean-up, Install CAB File, Restart Explorer, Elevated Command-Prompt and Elevated PowerShell to the context menu.
	
	.PARAMETER NetFx3
		Adds the .NET Framework 3.5 Windows packages to the image and enables the NetFx3 optional feature.
	
	.PARAMETER SystemImages
		Adds custom system images to the image or replaces default system images.
	
	.PARAMETER OfflineServicing
		Applies an OfflineServicing answer file directly to the image.
	
	.PARAMETER Unattend
		Adds the supplied unattend.xml to the image.
	
	.PARAMETER GenuineTicket
		Adds a supplied GenuineTicket.xml to the image for auto-activation.
	
	.PARAMETER HostsFile
		Downloads Steven Black's master Hosts File from GitHub and adds it to the image (https://github.com/StevenBlack/hosts).
	
	.PARAMETER Win32Calc
		Applies the Windows 10 Enterprise 2016 LTSB Win32 Calculator to the image. This is useful when removing the Calculator Provisionining Application Packages.
	
	.PARAMETER SysPrep
		Sets the image up for automatic booting into Audit System for System Preparation and imaging.
	
	.NOTES
		Image and package path variables can point to a single file or a directory of files. If a directory is detected, the script will recursively add those files to the image.
		If replacing default images, ensure they meet Windows' dimentional requirements.
	
	.NOTES
		===========================================================================
		Created on:   	12/26/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Additional-Features.ps1
		Version:        2.0.7
		Last updated:	04/06/2018
		===========================================================================
#>
    [CmdletBinding()]
    Param
    (
        [string]$ContextMenu,
        [string]$NetFx3,
        [string]$SystemImages,
        [string]$OfflineServicing,
        [string]$Unattend,
        [string]$GenuineTicket,
        [string]$HostsFile,
        [string]$Win32Calc,
        [string]$SysPrep
    )
	
    $ComputerName = "*"
    
    $ProgressPreference = "SilentlyContinue"
    $NetFX3PackagePath = "$PSScriptRoot\Additional\NetFx3"
    $WallpaperPath = "$PSScriptRoot\Additional\Images\Wallpaper"
    $LockScreenPath = "$PSScriptRoot\Additional\Images\LockScreen"
    $SystemLogoPath = "$PSScriptRoot\Additional\Images\Logo"
    $AccountPicturePath = "$PSScriptRoot\Additional\Images\Account"
    $UnattendPath = "$PSScriptRoot\Additional\Unattend"
    $GenuineTicketPath = "$PSScriptRoot\Additional\GenuineTicket"
    $Win32CalcImagePath = "$PSScriptRoot\Additional\Win32Calc"
	
    Function Set-FileOwnership($Path) {
        Invoke-Expression -Command ('TAKEOWN /F $Path /A')
        $ACL = Get-Acl -Path $Path
        $SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $Admin = $SID.Translate([System.Security.Principal.NTAccount])
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Admin, "FullControl", "None", "None", "Allow")
        $ACL.AddAccessRule($Rule)
        $ACL | Set-Acl -Path $Path
    }
	
    Function Set-FolderOwnership($Path) {
        Set-FileOwnership $Path
        ForEach ($Object in Get-ChildItem $Path -Recurse -Force) {
            If (Test-Path $Object -PathType Container) {
                Set-FolderOwnership $Object.FullName
            }
            Else {
                Set-FileOwnership $Object.FullName
            }
        }
    }
	
    Function New-Container($Path) {
        If (!(Test-Path -Path $Path)) {
            [void](New-Item -Path $Path -ItemType Directory -Force)
        }
    }
	
    If ($Unattend -and $SysPrep) {
        $SysPrep = ''
    }
	
    If ($ContextMenu) {
        Write-Output ''
        Write-Output "Adding Context Menu features."
        [void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\Windows\System32\config\software")
        Start-Sleep 3
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Open with Notepad' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        [void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" /v "Icon" /t REG_SZ /d "notepad.exe,-2" /f)
        [void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" /ve /t REG_SZ /d "notepad.exe %1" /f)
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Copy-Move' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB630-2971-11D1-A18C-00C04FD75D13}"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB631-2971-11D1-A18C-00C04FD75D13}"
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Extended Disk Clean-up' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up\command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up" -Name "Icon" -Value "cleanmgr.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Extended Disk Clean-up\command" -Name "(default)" `
            -Value "WScript C:\Windows\Extended-Disk-Cleanup.vbs" -Type String
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Quick Restore Point' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point\command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" -Name "Icon" -Value "SystemPropertiesProtection.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point\command" -Name "(default)" `
            -Value "WScript C:\Windows\Create-Restore-Point.vbs" -Type String
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Elevated Command-Prompt' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Icon" -Value "cmd.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "SeparatorAfter" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "(default)" -Value "Elevated Command-Prompt" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Icon" -Value "cmd.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "SeparatorAfter" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\runas\command" -Name "(default)" -Value "CMD /S /K PUSHD `"%V`"" -Type ExpandString
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Elevated PowerShell' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Icon" -Value "powershell.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\ElevatedPowerShell\command" -Name "(default)" `
            -Value "Powershell Start-Process PowerShell -Verb runas -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''`"%V`"'''" -Type ExpandString
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "(default)" -Value "Elevated PowerShell" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Icon" -Value "powershell.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "SeparatorBefore" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell" -Name "Position" -Value "Bottom" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shell\ElevatedPowerShell\command" -Name "(default)" `
            -Value "Powershell Start-Process PowerShell -Verb runas -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''`"%V`"'''" -Type ExpandString
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Install CAB' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs\Command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -Name "(default)" -Value "Install" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs" -Name "HasLUAShield" -Value "" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CABFolder\Shell\RunAs\Command" -Name "(default)" `
            -Value "CMD /K DISM /ONLINE /ADD-PACKAGE /PACKAGEPATH:`"%1`"" -Type ExpandString
        #****************************************************************
        Write-Output '' >> $WorkFolder\Registry-Optimizations.log
        Write-Output "Adding 'Restart Explorer' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "icon" -Value "explorer.exe" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer" -Name "Position" -Value "bottom" -Type String
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\Shell\Restart Explorer\command" -Name "(default)" -Value "Restart-Explorer.cmd" -Type String
        #****************************************************************
        [System.GC]::Collect()
        [void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
        Start-Sleep 3
        
        $ExtendedDiskStr = @'
If WScript.Arguments.length =0 Then
  Set Cleanup1 = CreateObject("Shell.Application")
  Cleanup1.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " Run", , "runas", 1
Else
   Set Cleanup2 = WScript.CreateObject("WSCript.shell")
   Cleanup2.run ("cmd.exe /c cleanmgr /sageset:65535 & cleanmgr /sagerun:65535"), 0
End If
'@

        $RestorePointStr = @'
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
	sDesc = InputBox ("Enter a restore point description.", "Create Quick System Restore Point","Quick Restore Point")
	If Trim(sDesc) <> "" Then
		sOut = SRP.createrestorepoint (sDesc, 0, 100)
		If sOut <> 0 Then
	 		WScript.echo "Error " & sOut & ": Unable to create Restore Point."
                else 
                MsgBox "The restore point " & Chr(34) & sDesc & Chr(34) & " was created successfully.", 0, "Create Quick System Restore Point"
		End If
	End If
End Sub
'@

        $RestartExplorerStr = @'
@ECHO OFF
ECHO:
ECHO Killing Explorer.exe
ECHO:
TASKKILL /F /IM Explorer.exe
ECHO:
ECHO Ready to restart Explorer.exe
TIMEOUT /T -1
START "Starting Explorer.exe" Explorer.exe
TIMEOUT /T 5 /NOBREAK >NUL
ECHO:
ECHO Explorer.exe has started successfully.
TIMEOUT /T 3 /NOBREAK >NUL
EXIT
'@
        $ExtendedDiskScript = Join-Path -Path "$MountFolder\Windows" -ChildPath "Extended-Disk-Cleanup.vbs"
        Set-Content -Path $ExtendedDiskScript -Value $ExtendedDiskStr -Force
        $RestorePointScript = Join-Path -Path "$MountFolder\Windows" -ChildPath "Create-Restore-Point.vbs"
        Set-Content -Path $RestorePointScript -Value $RestorePointStr -Force
        $RestartExplorerScript = Join-Path -Path "$MountFolder\Windows" -ChildPath "Restart-Explorer.cmd"
        Set-Content -Path $RestartExplorerScript -Value $RestartExplorerStr -Encoding ASCII -Force
    }
	
    If ($NetFx3) {
        If (Test-Path -Path $NetFX3PackagePath -Filter "*.cab") {
            Write-Output ''
            Write-Output "Adding the .NET Framework Package."
            [void](Add-WindowsPackage -Path $MountFolder -PackagePath $NetFX3PackagePath)
            [void](Enable-WindowsOptionalFeature -Path $MountFolder -FeatureName NetFx3)
        }
        Else {
            Write-Output ''
            Write-Warning "$NetFX3PackagePath contains no valid .CAB files."
            Start-Sleep 3
        }
    }
	
    If ($SystemImages) {
        Write-Output ''
        Write-Output "Adding or replacing System Images."
        Start-Sleep 3
        If ((Get-ChildItem -Path $LockScreenPath -Recurse) -ne $null) {
            [void](Set-FolderOwnership "$MountFolder\Windows\Web\Screen")
            Copy-Item -Path "$LockScreenPath\*" -Destination "$MountFolder\Windows\Web\Screen" -Recurse -Force
        }
        If ((Get-ChildItem -Path $WallpaperPath -Recurse) -ne $null) {
            Copy-Item -Path "$WallpaperPath\*" -Destination "$MountFolder\Windows\Web\Wallpaper" -Recurse -Force
        }
        If ((Get-ChildItem -Path $SystemLogoPath -Recurse) -ne $null) {
            New-Container -Path "$MountFolder\Windows\System32\oobe\info\logo"
            Copy-Item -Path "$SystemLogoPath\*" -Filter "*.bmp" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Recurse -Force
        }
        If ((Get-ChildItem -Path $AccountPicturePath -Recurse) -ne $null) {
            [void](Set-FolderOwnership "$MountFolder\ProgramData\Microsoft\User Account Pictures")
            Copy-Item -Path "$AccountPicturePath\*" -Destination "$MountFolder\ProgramData\Microsoft\User Account Pictures" -Recurse -Force
        }
    }
	
    If ($OfflineServicing) {
        Write-Output ''
        Write-Output "Applying an OfflineServicing answer file to the image."
        Start-Sleep 3

        $OfflineServicingStr = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="offlineServicing">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
            <DoNotCleanTaskBar>false</DoNotCleanTaskBar>
            <BluetoothTaskbarIconEnabled>false</BluetoothTaskbarIconEnabled>
        </component>
        <component name="Microsoft-Windows-WiFiNetworkManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <WiFiSenseAllowed>0</WiFiSenseAllowed>
        </component>
        <component name="Security-Malware-Windows-Defender" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DisableAntiSpyware>true</DisableAntiSpyware>
        </component>
        <component name="Microsoft-Windows-Embedded-EmbeddedLogon" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="NonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UIVerbosityLevel>1</UIVerbosityLevel>
            <HideAutoLogonUI>1</HideAutoLogonUI>
            <BrandingNeutral>13</BrandingNeutral>
            <AnimationDisabled>1</AnimationDisabled>
        </component>
    </settings>
</unattend>
"@
        $OfflineServicingXML = Join-Path -Path $TempFolder -ChildPath "OfflineServicing.xml"
        Set-Content -Path $OfflineServicingXML -Value $OfflineServicingStr -Encoding UTF8 -Force
        [void](Use-WindowsUnattend -Path $MountFolder -UnattendPath "$TempFolder\OfflineServicing.xml")
    }
	
    If ($Unattend) {
        If ((Get-ChildItem -Path $UnattendPath).Name -match "unattend.xml") {
            Write-Output ''
            Write-Output "Adding an unattend.xml answer file to the image."
            Start-Sleep 3
            New-Container -Path "$MountFolder\Windows\Panther"
            Copy-Item -Path "$UnattendPath\unattend.xml" -Destination "$MountFolder\Windows\Panther\unattend.xml" -Force
            If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd")) {

                $AppendSetup = @'
DEL /F /Q "%WINDIR%\System32\Sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\Panther\unattend.xml" >NUL
DEL "%~f0""
'@
                If (Test-Path -Path "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd") {
                    $SetupScript = "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd"
                    $SetupContent = (Get-Content -Path $SetupScript)
                    $SetupContent.Replace('DEL "%~f0"', $AppendSetup) | Set-Content -Path $SetupScript -Encoding ASCII -Force
                }
                Else {
                    New-Container -Path "$MountFolder\Windows\Setup\Scripts\Scripts"
                    $SetupScript = "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd"
                    $BeginSetup = "@ECHO OFF`n"
                    Set-Content -Path $SetupScript -Value $BeginSetup, $AppendSetup -Encoding ASCII -Force
                }
            }
        }
        Else {
            Write-Output ''
            Write-Warning "$UnattendPath does not contain an unattend.xml file."
            Start-Sleep 3
        }
    }
	
    If ($GenuineTicket) {
        If ((Get-ChildItem -Path $GenuineTicketPath).Name -match "GenuineTicket.xml") {
            Write-Output ''
            Write-Output "Adding a GenuineTicket.xml to the image."
            Start-Sleep 3
            Copy-Item -Path "$GenuineTicketPath\GenuineTicket.xml" -Destination "$MountFolder\ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket\GenuineTicket.xml" -Force
        }
        Else {
            Write-Output ''
            Write-Warning "$GenuineTicketPath does not contain a GenuineTicket.xml file."
            Start-Sleep 3
        }
    }
	
    If ($HostsFile) {
        If ((Test-Connection $env:COMPUTERNAME -Quiet) -eq $true) {
            Write-Output ''
            Write-Output "Replacing the default Hosts File."
            Start-Sleep 3
            $URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
            $Output = "$TempFolder\hosts"
            (New-Object System.Net.WebClient).DownloadFile($URL, $Output)
            (Get-Content -Path "$TempFolder\hosts") | Set-Content -Path "$TempFolder\hosts" -Encoding UTF8 -Force
            Rename-Item -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -NewName hosts.bak -Force
            Copy-Item -Path "$TempFolder\hosts" -Destination "$MountFolder\Windows\System32\drivers\etc\hosts" -Force
        }
        Else {
            Write-Output ''
            Write-Warning "Connection test failed. Unable to replace the default Hosts File."
            Start-Sleep 3
        }
    }
	
    If ($Win32Calc) {
        If ((Test-Path -Path "$Win32CalcImagePath\win32calc.exe") -and (Test-Path -Path "$Win32CalcImagePath\win32calc.exe.mui")) {
            Write-Output ''
            Write-Output "Applying the Win32 Calculator."
            Start-Sleep 3
            Copy-Item -Path "$Win32CalcImagePath\win32calc.exe" -Destination "$MountFolder\Windows\System32"
            Copy-Item -Path "$Win32CalcImagePath\win32calc.exe.mui" -Destination "$MountFolder\Windows\System32\en-US"
			
            $W32CalcStr = @'
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\calculator\DefaultIcon]
@="C:\\Windows\\System32\\win32calc.exe,0"

[HKEY_CLASSES_ROOT\calculator\shell\open\command]
@="C:\\Windows\\System32\\win32calc.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey\18]
"ShellExecute"="C:\\Windows\\System32\\win32calc.exe"

'@
            $W32Shell = New-Object -ComObject WScript.Shell
            $W32CShortcut = $W32Shell.CreateShortcut("$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk")
            $W32CShortcut.TargetPath = "%SystemRoot%\System32\win32calc.exe"
            $W32CShortcut.IconLocation = "%SystemRoot%\System32\win32calc.exe,0"
            $W32CShortcut.Description = "Performs basic arithmetic tasks with an on-screen calculator."
            $W32CShortcut.Save()
			
            $W32RegFile = Join-Path -Path $WorkFolder -ChildPath "Win32Calc.reg"
            Set-Content -Path $W32RegFile -Value $W32CalcStr -Encoding Unicode -Force
            [void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\windows\system32\config\software")
            REGEDIT /S "$WorkFolder\Win32Calc.reg"
            [System.GC]::Collect()
            [void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
            $LnkINI = "$MountFolder\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini"
            $W32CalcLnk = "Calculator.lnk=@%SystemRoot%\system32\shell32.dll,-22019"
            $LnkContent = (Get-Content -Path $LnkINI)
            If ((Select-String -InputObject $LnkContent -Pattern $W32CalcLnk -NotMatch -Quiet) -eq $true) {
                ATTRIB -S -H $LnkINI
                Add-Content -Path $LnkINI -Value $W32CalcLnk -Encoding Unicode -Force
                ATTRIB +S +H $LnkINI
            }
        }
        Else {
            Write-Output ''
            Write-Warning "$Win32CalcImagePath does not contain the required Win32Calc files."
            Start-Sleep 3
        }
    }
	
    If ($SysPrep) {
        Write-Output ''
        Write-Output "Setting image up for Audit Booting and System Preparation"
        Start-Sleep 3

        $AuditTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Reseal>
                <Mode>Audit</Mode>
            </Reseal>
        </component>
    </settings>
    <settings pass="auditSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DisableAutoDaylightTimeSet>false</DisableAutoDaylightTimeSet>
            <TimeZone>Eastern Standard Time</TimeZone>
            <DoNotCleanTaskBar>false</DoNotCleanTaskBar>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AuditComputerName>
                <MustReboot>true</MustReboot>
                <Name>$ComputerName</Name>
            </AuditComputerName>
        </component>
    </settings>
</unattend>
"@

        $RemOneDriveCmd = @'
TASKKILL /F /IM OneDrive.exe >NUL 2>&1
IF EXIST %SystemRoot%\System32\OneDriveSetup.exe (
START /WAIT %SystemRoot%\System32\OneDriveSetup.exe /UNINSTALL
) ELSE (
START /WAIT %SystemRoot%\SysWOW64\OneDriveSetup.exe /UNINSTALL
)
RMDIR /S /Q "%UserProfile%\OneDrive" >NUL 2>&1
RMDIR /S /Q "%LocalAppData%\Microsoft\OneDrive" >NUL 2>&1
RMDIR /S /Q "%SystemDrive%\OneDriveTemp" >NUL 2>&1
RMDIR /S /Q "%ProgramData%\Microsoft OneDrive" >NUL 2>&1
'@

        $ReadMeTxt = @"
- Run "Disable-OneDrive.cmd" to uninstall OneDrive and remove its directories.
- There is a bug when doing a SysPrep where OneDrive will continue to point to the BUILTIN\Administrator account after Copy Profile is initiated.`n- This bug breaks all OneDrive links for any users created on the live installation. Removing OneDrive via the Remove-OneDrive.cmd will prevent this from occuring, `n- OneDrive will have to be re-installed after the image has been generalized and installed unless you plan to keep it disabled permanently.
`n- Before generalizing the image, rename the OOBE.txt and SetupComplete.txt files in %WINDIR%\Setup\Scripts to OOBE.cmd and SetupComplete.cmd so they run during Windows Setup.
"@

        $AppendSetup = @'
DEL /F /Q "%WINDIR%\System32\Sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\Panther\unattend.xml" >NUL
DEL "%~f0"
'@

        New-Container -Path "$MountFolder\Windows\Panther"
        New-Container -Path "$MountFolder\OneDrive-Info"
        $AuditBootXML = Join-Path -Path "$MountFolder\Windows\Panther" -ChildPath "unattend.xml"
        $OneDriveScript = Join-Path -Path "$MountFolder\OneDrive-Info" -ChildPath "Remove-OneDrive.cmd"
        $ReadMeText = Join-Path -Path "$MountFolder\OneDrive-Info" -ChildPath "ReadMe.txt"
        Set-Content -Path $AuditBootXML -Value $AuditTemplate -Encoding UTF8 -Force
        Set-Content -Path $OneDriveScript -Value $RemOneDriveCmd -Encoding ASCII -Force
        Set-Content -Path $ReadMeText -Value $ReadMeTxt -Force
        If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd")) {
            If (Test-Path -Path "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd") {
                $SetupScript = "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd"
                $SetupContent = (Get-Content -Path $SetupScript)
                $SetupContent.Replace('DEL "%~f0"', $AppendSetup) | Set-Content -Path $SetupScript -Encoding ASCII -Force
                Copy-Item -Path $SetupScript -Destination "$MountFolder\Windows\Setup\Scripts\SetupComplete.txt" -Force
            }
            Else {
                New-Container -Path "$MountFolder\Windows\Setup\Scripts"
                $SetupScript = "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd"
                $BeginSetup = "@ECHO OFF`n"
                Set-Content -Path $SetupScript -Value $BeginSetup, $AppendSetup -Encoding ASCII -Force
                Copy-Item -Path $SetupScript -Destination "$MountFolder\Windows\Setup\Scripts\SetupComplete.txt" -Force
            }
        }
        Else {
            $OOBEScript = "$MountFolder\Windows\Setup\Scripts\OOBE.cmd"
            Rename-Item -Path $OOBEScript -NewName "$OOBE.txt" -Force
        }
        If (Test-Path -Path "$MountFolder\Windows\SysWOW64\OneDriveSetup.exe") {
            Copy-Item -Path "$MountFolder\Windows\SysWOW64\OneDriveSetup.exe" -Destination "$MountFolder\OneDrive-Info" -Force
        }
        Else {
            Copy-Item -Path "$MountFolder\Windows\System32\OneDriveSetup.exe" -Destination "$MountFolder\OneDrive-Info" -Force
        }
    }
}
# SIG # Begin signature block
# MIII2QYJKoZIhvcNAQcCoIIIyjCCCMYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwH0Auzi/0zeqEPE4C/RyvbHs
# dW+gggYxMIIDFDCCAgCgAwIBAgIQgnJLApNodKpGiwFxYC7KeTAJBgUrDgMCHQUA
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
# iuBBshmR3TGCAhIwggIOAgEBMCwwGDEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQQIQ
# VJ8qdzf/f7xETWjhXWNf/jAJBgUrDgMCGgUAoIG8MBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3
# DQEJBDEWBBR8hy8HtQFSBVA/gT7ShTEa6bcQjTBcBgorBgEEAYI3AgEMMU4wTKBK
# gEgAQQBkAGQAaQB0AGkAbwBuAGEAbAAtAEYAZQBhAHQAdQByAGUAcwAgAGYAdQBu
# AGMAdABpAG8AbgAgAHMAYwByAGkAcAB0AC4wDQYJKoZIhvcNAQEBBQAEggEAudZy
# NFXDRBcZYvns3fcXe4BYSrbfTrydKGpglxGOAFDZbVbzb7ZNniBRm6Bozz3Jf2pF
# DBIaCGnHZEzACTVGpK2y1JAQy3LlZoi80cUUZLjoP/F9HITA9vEQEfeEjmBKjr3e
# ea9mpPKnhVY3zYgh8iEbx7YaLOhjL5Q4+eVFdsVHuD627ujzxcj/AXjZn+X8LdNF
# Dz2NUvtGox7fvboVBty8iv6WinmVd4udjq2I6OxcAZX8hTjYKy0htU10Rk2KZvJq
# /OyxuCTJ3jSHQYlQXuyQF3VEWmDsnnqxXi2kjJn8Qs95CjoRoP+lSJa9mHIzQM2y
# mqeMlisuWY1+sE+FeQ==
# SIG # End signature block
