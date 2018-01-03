Function Additional-Features
{
<#
	.SYNOPSIS
		This is a function that can be called by the main Optimize-Offline script that will add additional features for a more device-specific final image.
	
	.DESCRIPTION
		If the switch for this function is used by the main Optimize-Offline script, it will be called before the image is finalized.
	
	.PARAMETER ContextMenu
		Adds Copy-Move, Open with Notepad, Create a restore-point, Extended disk clean-up, Install CAB, Elevated command-prompt and Elevated PowerShell to the context menu.
	
	.PARAMETER NetFx3
		Adds the .NET Framework 3.5 Windows packages to the image and enables the NetFx3 optional feature.
	
	.PARAMETER SystemImages
		Adds custom system images to the image or replaces default system images.
	
	.PARAMETER OfflineServicing
		Applies an OfflineServicing answer file directly to the image.
	
	.PARAMETER Unattend
		Adds the supplied unattend or autounattend answer file to the image.
	
	.PARAMETER HostsFile
		Downloads Steven Black's master Hosts File from GitHub and adds it to the image (https://github.com/StevenBlack/hosts).
	
	.NOTES
		- Image and package path variables can point to a single file or a directory of files. If a directory is detected, the script will recursively add those files to the image.
		- If replacing default images, ensure they meet Windows' dimentional requirements.
	
	.NOTES
		===========================================================================
		Created on:   	12/26/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Additional-Features.ps1
		Version:        1.0.4
		Last updated:	01/03/2018
		===========================================================================
#>
	[CmdletBinding()]
	Param
	(
		[switch]$ContextMenu,
		[switch]$NetFx3,
		[switch]$SystemImages,
		[switch]$OfflineServicing,
		[ValidateNotNullOrEmpty()][string]$Unattend,
		[switch]$HostsFile
	)
	
	## *************************************************************************************************
	## *          					THE VARIABLES BELOW CAN BE EDITED.          			           *
	## *************************************************************************************************
	
	## Location path variables.
	$WallpaperPath = "$PSScriptRoot\Images\Wallpaper"
	$LockScreenPath = "$PSScriptRoot\Images\LockScreen"
	$SystemLogoPath = "$PSScriptRoot\Images\Logo"
	$AccountPicturePath = "$PSScriptRoot\Images\Account"
	$NetFX3PackagePath = "$PSScriptRoot\Packages\NetFx3\16299"
	
	## OfflineServicing answer file variables.
	$ComputerName = "MY-PC"
	$Manufacturer = "Gigabyte."
	$Model = "GA‑Z170X‑Gaming G1"
	$SystemLogo = "%WINDIR%\System32\oobe\info\logo\GIGABYTE_BADGE.bmp"
	$Owner = "My Name"
	$Organization = "My Org"
	
	## *************************************************************************************************
	## *                                      END VARIABLES.                                           *
	## *************************************************************************************************
	
	If ($ContextMenu)
	{
		ECHO ''
		ECHO "Adding context menu features."
		[void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\windows\system32\config\software")
		#****************************************************************
		ECHO '' >> $WorkFolder\Registry-Optimizations.log
		ECHO "Adding 'Copy-Move' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************		
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f)
		#****************************************************************
		ECHO '' >> $WorkFolder\Registry-Optimizations.log
		ECHO "Adding 'Open with Notepad' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************		
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad" /v "Icon" /t REG_SZ /d "notepad.exe,-2" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\*\shell\Open with Notepad\command" /ve /t REG_SZ /d "notepad.exe %1" /f)
		#****************************************************************
		ECHO '' >> $WorkFolder\Registry-Optimizations.log
		ECHO "Adding 'Extended Disk Clean-up' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************		
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Extended Disk Clean-up" /v "HasLUAShield" /t REG_SZ /d "" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Extended Disk Clean-up" /v "Icon" /t REG_SZ /d "cleanmgr.exe" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\DesktopBackground\shell\Extended Disk Clean-up\command" /ve /t REG_SZ /d "WScript C:\Windows\Extended-Disk-Cleanup.vbs" /f)
		#****************************************************************
		ECHO '' >> $WorkFolder\Registry-Optimizations.log
		ECHO "Adding 'Quick Restore Point' to the Context Menu." >> $WorkFolder\Registry-Optimizations.log
		#****************************************************************		
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" /v "HasLUAShield" /t REG_SZ /d "" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point" /v "Icon" /t REG_SZ /d "SystemPropertiesProtection.exe" /f)
		[void](REG ADD "HKLM\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shell\Create Restore Point\command" /ve /t REG_SZ /d "WScript C:\Windows\Create-Restore-Point.vbs" /f)
		#****************************************************************
		SLEEP 3
		[gc]::collect()
		[void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
	}
	
	If ($ContextMenu)
	{
		$AddContextScripts = {
			$ExtendedDiskCleanupStr = @"
If WScript.Arguments.length =0 Then
  Set Cleanup1 = CreateObject("Shell.Application")
  Cleanup1.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " Run", , "runas", 1
Else
   Set Cleanup2 = WScript.CreateObject("WSCript.shell")
   Cleanup2.run ("cmd.exe /c cleanmgr /sageset:65535 & cleanmgr /sagerun:65535"), 0
End If
"@
			$CreateRestorePointStr = @"
Function SystemOS    
    Set objWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & ".\root\cimv2")
    Set colOS = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
    For Each objOS in colOS
        If instr(objOS.Caption, "Windows 10") Then
        	SystemOS = "Windows 10"
        elseIf instr(objOS.Caption, "Windows 8") Then
        	SystemOS = "Windows 8"
        elseIf instr(objOS.Caption, "Windows 7") Then
        	SystemOS = "Windows 7"    
        End If
	Next
End Function

If SystemOS = "Windows 7" Then
	If WScript.Arguments.length =0 Then
  		Set objShell = CreateObject("Shell.Application")
		objShell.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " Run", , "runas", 1
	Else
  		CreateSRP
  	End If
End If

If SystemOS = "Windows 8" Or SystemOS = "Windows 10" Then
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
"@
			$ExtendedDiskCleanupScript = Join-Path -Path "$MountFolder\Windows" -ChildPath "Extended-Disk-Cleanup.vbs"
			SC -Path $ExtendedDiskCleanupScript -Value $ExtendedDiskCleanupStr
			$CreateRestorePointScript = Join-Path -Path "$MountFolder\Windows" -ChildPath "Create-Restore-Point.vbs"
			SC -Path $CreateRestorePointScript -Value $CreateRestorePointStr -Force
		}
		& $AddContextScripts
	}
	
	If ($ContextMenu)
	{
		If (Test-Path -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd")
		{
			$AddToContextMenuCMD = {
				$ElevatedConsoles = @"
REGEDIT /S "%WINDIR%\Setup\Scripts\ElevatedConsoles-To-ContextMenu.reg"
"@
				$InstallCAB = @"
REGEDIT /S "%WINDIR%\Setup\Scripts\InstallCAB-to-ContextMenu.reg"
"@
				$ElevatedConsolesFile = @"
Windows Registry Editor Version 5.00

; Elevated Command-Prompt

[HKEY_CLASSES_ROOT\Directory\Background\shell\runas]
@="Elevated Command-Prompt"
"Icon"="cmd.exe"
"HasLUAShield"=""
"SeparatorAfter"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command]
@="CMD /S /K PUSHD \"%V\""

[HKEY_CLASSES_ROOT\Directory\shell\runas]
@="Elevated Command-Prompt"
"Icon"="cmd.exe"
"HasLUAShield"=""
"SeparatorAfter"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\shell\runas\command]
@="CMD /S /K PUSHD \"%V\""

; Elevated PowerShell

[HKEY_CLASSES_ROOT\Directory\Background\shell\ElevatedPowerShell]
@="Elevated PowerShell"
"Icon"="powershell.exe"
"HasLUAShield"=""
"SeparatorBefore"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\Background\shell\ElevatedPowerShell\command]
@="Powershell Start-Process PowerShell -Verb runas -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''\"%V\"'''"

[HKEY_CLASSES_ROOT\Directory\shell\ElevatedPowerShell]
@="Elevated PowerShell"
"Icon"="powershell.exe"
"HasLUAShield"=""
"SeparatorBefore"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\shell\ElevatedPowerShell\command]
@="Powershell Start-Process PowerShell -Verb runas -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''\"%V\"'''"

"@
				$InstallCABFile = @"
Windows Registry Editor Version 5.00

[-HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs]

[HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs]
@="Install"
"HasLUAShield"=""

[HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command]
@="CMD /K DISM /ONLINE /ADD-PACKAGE /PACKAGEPATH:\"%1\""

"@
				AC -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value ($ElevatedConsoles, $InstallCAB) -Encoding ASCII -Force
				$CreateElevatedRegFile = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "ElevatedConsoles-To-ContextMenu.reg"
				SC -Path $CreateElevatedRegFile -Value $ElevatedConsolesFile -Encoding Unicode -Force
				$CreateCABRegFile = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "InstallCAB-to-ContextMenu.reg"
				SC -Path $CreateCABRegFile -Value $InstallCABFile -Encoding Unicode -Force
			}
			& $AddToContextMenuCMD
		}
		Else
		{
			$AddToContextMenuCMD = {
				$ElevatedConsoles = @"
REGEDIT /S "%WINDIR%\Setup\Scripts\ElevatedConsoles-To-ContextMenu.reg"
"@
				$InstallCAB = @"
REGEDIT /S "%WINDIR%\Setup\Scripts\InstallCAB-to-ContextMenu.reg"
"@
				$ElevatedConsolesFile = @"
Windows Registry Editor Version 5.00

; Elevated Command-Prompt

[HKEY_CLASSES_ROOT\Directory\Background\shell\runas]
@="Elevated Command-Prompt"
"Icon"="cmd.exe"
"HasLUAShield"=""
"SeparatorAfter"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command]
@="CMD /S /K PUSHD \"%V\""

[HKEY_CLASSES_ROOT\Directory\shell\runas]
@="Elevated Command-Prompt"
"Icon"="cmd.exe"
"HasLUAShield"=""
"SeparatorAfter"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\shell\runas\command]
@="CMD /S /K PUSHD \"%V\""

; Elevated PowerShell

[HKEY_CLASSES_ROOT\Directory\Background\shell\ElevatedPowerShell]
@="Elevated PowerShell"
"Icon"="powershell.exe"
"HasLUAShield"=""
"SeparatorBefore"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\Background\shell\ElevatedPowerShell\command]
@="Powershell Start-Process PowerShell -Verb runas -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''\"%V\"'''"

[HKEY_CLASSES_ROOT\Directory\shell\ElevatedPowerShell]
@="Elevated PowerShell"
"Icon"="powershell.exe"
"HasLUAShield"=""
"SeparatorBefore"=""
"Position"="Bottom"

[HKEY_CLASSES_ROOT\Directory\shell\ElevatedPowerShell\command]
@="Powershell Start-Process PowerShell -Verb runas -ArgumentList '-NoExit', 'Push-Location -LiteralPath ''\"%V\"'''"

"@
				$InstallCABFile = @"
Windows Registry Editor Version 5.00

[-HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs]

[HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs]
@="Install"
"HasLUAShield"=""

[HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command]
@="CMD /K DISM /ONLINE /ADD-PACKAGE /PACKAGEPATH:\"%1\""

"@
				$CreateOOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
				SC -Path "$CreateOOBEScript" -Value ($ElevatedConsoles, $InstallCAB) -Encoding ASCII -Force
				$CreateElevatedRegFile = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "ElevatedConsoles-To-ContextMenu.reg"
				SC -Path $CreateElevatedRegFile -Value $ElevatedConsolesFile -Encoding Unicode -Force
				$CreateCABRegFile = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "InstallCAB-to-ContextMenu.reg"
				SC -Path $CreateCABRegFile -Value $InstallCABFile -Encoding Unicode -Force
			}
			& $AddToContextMenuCMD
		}
	}
	
	If ($NetFx3)
	{
		If (([IO.FileInfo]$NetFX3PackagePath).Extension -like ".CAB")
		{
			ECHO ''
			ECHO "Adding .NET Framework Package and Enabling NetFx3."
			[void](Add-WindowsPackage -Path $MountFolder -PackagePath $NetFX3PackagePath)
			[void](Enable-WindowsOptionalFeature -Path $MountFolder -FeatureName NetFx3)
			Get-WindowsOptionalFeature -Path $MountFolder | Format-Table | Out-File $WorkFolder\WindowsOptionalFeatureList.txt -Force
		}
		ElseIf (Test-Path -Path $NetFX3PackagePath -Type Container)
		{
			ECHO ''
			ECHO "Adding .NET Framework Packages and Enabling NetFx3."
			[void](Add-WindowsPackage -Path $MountFolder -PackagePath $NetFX3PackagePath)
			[void](Enable-WindowsOptionalFeature -Path $MountFolder -FeatureName NetFx3)
			Get-WindowsOptionalFeature -Path $MountFolder | Format-Table | Out-File $WorkFolder\WindowsOptionalFeatureList.txt -Force
		}
		Else
		{
			ECHO ''
			Write-Warning -Message "$NetFX3PackagePath is invalid."
		}
	}
	
	If ($SystemImages)
	{
		ECHO ''
		ECHO "Adding or replacing any System Images."
		SLEEP 3
		If ((DIR -Path $LockScreenPath).Name -contains "img100.jpg")
		{
			$ReplaceDefaultLockScreen = {
				$DefaultLockScreenImage = "$MountFolder\Windows\Web\Screen\img100.jpg"
				$Grant = "/Grant"
				$User = "Administrators"
				$Permission = ":F"
				[void](TAKEOWN /F $DefaultLockScreenImage /A)
				[void](IEX -Command ('ICACLS $DefaultLockScreenImage $Grant "${User}${Permission}" /Q'))
				COPY -Path "$LockScreenPath\img100.jpg" -Destination $DefaultLockScreenImage -Force
			}
			& $ReplaceDefaultLockScreen
		}
		Else
		{
			$DefaultLockScreenDir = "$MountFolder\Windows\Web\Screen"
			COPY -Path "$LockScreenPath\*" -Destination $DefaultLockScreenDir -Recurse -Force
		}
		If (Test-Path -Path $WallpaperPath -Type Container)
		{
			$DefaultWallpaperDir = "$MountFolder\Windows\Web\Wallpaper"
			COPY -Path "$WallpaperPath\*" -Destination $DefaultWallpaperDir -Recurse -Force
		}
		If (Test-Path -Path $SystemLogoPath -Type Leaf)
		{
			If (!(Test-Path -Path "$MountFolder\Windows\System32\oobe\info\logo"))
			{
				[void](NI -Path "$MountFolder\Windows\System32\oobe\info\logo" -Type Directory -Force)
				COPY -Path "$SystemLogoPath\*" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Force
			}
			Else
			{
				COPY -Path "$SystemLogoPath\*" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Force
			}
		}
		ElseIf (Test-Path -Path $SystemLogoPath -Type Container)
		{
			If (!(Test-Path -Path "$MountFolder\Windows\System32\oobe\info\logo"))
			{
				[void](NI -Path "$MountFolder\Windows\System32\oobe\info\logo" -Type Directory -Force)
				COPY -Path "$SystemLogoPath\*" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Recurse -Force
			}
			Else
			{
				COPY -Path "$SystemLogoPath\*" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Recurse -Force
			}
		}
		
		If (Test-Path -Path $AccountPicturePath -Type Container)
		{
			$ReplaceDefaultAccountPictures = {
				$DefaultAccountPictures = "$MountFolder\ProgramData\Microsoft\User Account Pictures"
				$Grant = "/Grant"
				$User = "Administrators"
				$Permission = ":(OI)(CI)F"
				[void](TAKEOWN /F $DefaultAccountPictures /A /R /D Y)
				[void](IEX -Command ('ICACLS $DefaultAccountPictures $Grant "${User}${Permission}" /T /C /Q'))
				COPY -Path "$AccountPicturePath\*" -Destination "$MountFolder\ProgramData\Microsoft\User Account Pictures" -Recurse -Force
			}
			& $ReplaceDefaultAccountPictures
		}
	}
	
	## Add or remove desired components or settings. All additional components must be placed under the "offlineServicing" settings pass in order to be applied directly to the image.
	If ($OfflineServicing)
	{
		$ApplyOfflineServicing = {
			$OfflineServicingStr = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="offlineServicing">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OEMInformation>
                <HelpCustomized>false</HelpCustomized>
                <Logo>$SystemLogo</Logo>
                <Manufacturer>$Manufacturer</Manufacturer>
                <Model>$Model</Model>
            </OEMInformation>
            <ComputerName>$ComputerName</ComputerName>
            <RegisteredOrganization>$Organization</RegisteredOrganization>
            <RegisteredOwner>$Owner</RegisteredOwner>
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
			SC -Path $OfflineServicingXML -Value $OfflineServicingStr -Force
			[void](Apply-WindowsUnattend -Path $MountFolder -UnattendPath $TempFolder\OfflineServicing.xml)
		}
		ECHO ''
		ECHO "Applying an OfflineServicing answer file to the image."
		& $ApplyOfflineServicing
		SLEEP 3
	}
	
	If ($Unattend)
	{
		If (([IO.FileInfo]$Unattend).Extension -like ".XML")
		{
			ECHO ''
			ECHO "Adding an unattend.xml answer file to the image."
			SLEEP 3
			If (!(Test-Path -Path "$MountFolder\Windows\Panther"))
			{
				[void](NI -Path "$MountFolder\Windows\Panther" -Type Directory -Force)
			}
			COPY -Path $Unattend -Destination "$MountFolder\Windows\Panther\unattend.xml" -Force
		}
		Else
		{
			ECHO ''
			Write-Warning -Message "$Unattend is not a valid path."
			SLEEP 3
		}
	}
	
	If ($HostsFile)
	{
		If ((Test-Connection $env:COMPUTERNAME -Quiet) -eq $true)
		{
			ECHO ''
			ECHO "Replacing the default Hosts File."
			SLEEP 3
			(CURL "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts").Content | SC -Path "$TempFolder\hosts"
			(CAT -Path "$TempFolder\hosts") | SC -Path "$TempFolder\hosts" -Encoding ASCII -Force
			REN -Path "$MountFolder\Windows\System32\drivers\etc\hosts" -NewName hosts.skel -Force
			COPY -Path "$TempFolder\hosts" -Destination "$MountFolder\Windows\System32\drivers\etc\hosts" -Force
		}
		Else
		{
			ECHO ''
			Write-Warning "Connection test failed. Unable to replace the default Hosts File."
			SLEEP 3
		}
	}
}
# SIG # Begin signature block
# MIIJcwYJKoZIhvcNAQcCoIIJZDCCCWACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEMUEaMFhneepCY5kwvD1XHwA
# 4xKgggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
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
# qHcndUPZwjGCAkwwggJIAgEBMD0wKTEnMCUGA1UEAxMeT01OSUMuVEVDSC1DQSBD
# ZXJ0aWZpY2F0ZSBSb290AhB0u1Cd2puAkkG+oZic5rsmMAkGBSsOAwIaBQCggeUw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJikEV7RAvdCG7ahyk3UnKrIU/uZMIGE
# BgorBgEEAYI3AgEMMXYwdKBygHAATwBwAHQAaQBtAGkAegBlAC0ATwBmAGYAbABp
# AG4AZQAnAHMAIABhAGQAZABpAHQAaQBvAG4AYQBsACAAZgBlAGEAdAB1AHIAZQAn
# AHMAIABmAHUAbgBjAHQAaQBvAG4AIABzAGMAcgBpAHAAdAAuMA0GCSqGSIb3DQEB
# AQUABIIBAD1+JQP+Qz2l9Lch9r2vaaEnHIuYrp6lVrg/Hv2OBNymxnhYlN7kOSqH
# PoHFLtAerefBYZIlgO1aQSF2oloxeruCucSLp6dI/SnOiXAECJeieb6O5j3qqrC+
# xtxC2M89ft7jFGZoyHjH3mDvKY1EybnZTtsr1HquH60+OIiAX85kbcKBDYu7O2Qk
# KUR1aansVvEQ7tHTjoABSqhqjDymgS6GTqrarWTxw/z5YOLkaaQTeQSLWI3GrUNR
# 9D+oIT+89N/d3sWGWNjbFnDo9PFoitDx6Cm7SaU2yulExIkTV1nptTyzRSZOyqDe
# 4TEaY7AZaf8sSBXumcTrSNENIxJaymw=
# SIG # End signature block
