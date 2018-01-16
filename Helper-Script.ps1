<#	
	.DESCRIPTION
		Optimize-Offline's helper script.

	.NOTES
		This script must remain in the same location that the Optimize-Offline.ps1 script is located.

	.NOTES
		===========================================================================
		Created on:   	01/12/2018
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	Helper-Script.ps1
		Version:        1.0.2
		Last updated:	01/16/2018
		===========================================================================
#>

####################################################################################################################################################

## Modifying anything herein may result in processes not functioning, optimizations not applying, terminating errors and/or a corrupted final image.

#####################################################################################################################################################

#region Helper Primary Functions
Function Verify-Admin
{
	[CmdletBinding()]
	Param ()
	
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	$IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	Write-Verbose "IsUserAdmin? $IsAdmin" -Verbose
	Return $IsAdmin
	ECHO ''
	SLEEP 3
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
			ECHO ''
			SLEEP 2
			$CreateLogFile = NI $LogPath -ItemType File -Force
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

Function Create-WorkDirectory
{
	$WorkDir = [System.IO.Path]::GetTempPath()
	$WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($WorkDir)
	$WorkDir
}

Function Create-TempDirectory
{
	$TempDir = [System.IO.Path]::GetTempPath()
	$TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($TempDir)
	$TempDir
}

Function Create-ImageDirectory
{
	$ImageDir = [System.IO.Path]::GetTempPath()
	$ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($ImageDir)
	$ImageDir
}

Function Create-MountDirectory
{
	$MountDir = [System.IO.Path]::GetTempPath()
	$MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($MountDir)
	$MountDir
}

Function Create-SaveDirectory
{
	NI -ItemType Directory -Path $HOME\Desktop\Optimize-Offline"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
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
	SLEEP 3
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

Function Terminate-Script
{
	[CmdletBinding()]
	Param ()
	
	SLEEP 3
	ECHO ''
	Write-Verbose "Cleaning-up and terminating script. Please wait." -Verbose
	If (Verify-OfflineHives)
	{
		[void](Unload-OfflineHives)
	}
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
	[void](Move-Item -Path $LogFile -Destination $HOME\Desktop\Optimize-Offline.log -Force)
	[void](Remove-Item -Path $WorkFolder -Recurse -Force)
	[void](Remove-Item -Path $TempFolder -Recurse -Force)
	[void](Remove-Item -Path $ImageFolder -Recurse -Force)
	[void](Remove-Item -Path $MountFolder -Recurse -Force)
	[void](Clear-WindowsCorruptMountPoint)
}
#endregion Helper Primary Functions

#region Helper Script-Blocks

$OOBE1 = {
	$OOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
	If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
	{
		[void](NI -Type Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
		$OOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
		SC -Path $OOBEScript -Value $OOBE -Encoding ASCII -Force
	}
	Else
	{
		AC -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $OOBE -Encoding ASCII -Force
	}
}

$OOBE2 = {
	$OOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
	If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
	{
		[void](NI -Type Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
		$OOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
		SC -Path $OOBEScript -Value $OOBE -Encoding ASCII -Force
	}
	Else
	{
		AC -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $OOBE -Encoding ASCII -Force
	}
}

$OOBE3 = {
	$OOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
	If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
	{
		[void](NI -Type Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
		$OOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
		SC -Path $OOBEScript -Value $OOBE -Encoding ASCII -Force
	}
	Else
	{
		AC -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $OOBE -Encoding ASCII -Force
	}
}

$OOBE4 = {
	$OOBE = @"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids\{2b2cad40-19c1-4794-b32d-397e41d5e8a7}" /v "AutoElevationAllowed" /t REG_DWORD /d "1" /f
"@
	If (!(Test-Path -Path "$MountFolder\Windows\Setup\Scripts"))
	{
		[void](NI -Type Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
		$OOBEScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "OOBE.cmd"
		SC -Path $OOBEScript -Value $OOBE -Encoding ASCII -Force
	}
	Else
	{
		AC -Path "$MountFolder\Windows\Setup\Scripts\OOBE.cmd" -Value $OOBE -Encoding ASCII -Force
	}
}

$SETUPCOMPLETE1 = {
	$SetupComplete = @"
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
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cache Maintenance" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Cleanup" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Scheduled Scan" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Windows Defender Verification" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
TASKKILL /F /IM MSASCuiL.exe >NUL
REGSVR32 /S /U "%PROGRAMFILES%\Windows Defender\shellext.dll" >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\ElevatedConsoles-To-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\InstallCAB-to-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\OOBE.cmd" >NUL
DEL "%~f0"
"@
	$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
	SC -Path $SetupCompleteScript -Value $SetupComplete -Encoding ASCII -Force
}

$SETUPCOMPLETE2 = {
	$SetupComplete = @"
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
SCHTASKS /QUERY | FINDSTR /B /I "Notifications" >NUL && SCHTASKS /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "QueueReporting" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "Uploader" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "UsbCeip" >NUL && SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >NUL
SCHTASKS /QUERY | FINDSTR /B /I "XblGameSaveTask" >NUL && SCHTASKS /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable >NUL
DEL /F /Q "%WINDIR%\system32\sysprep\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\panther\unattend.xml" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\ElevatedConsoles-To-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\InstallCAB-to-ContextMenu.reg" >NUL
DEL /F /Q "%WINDIR%\Setup\Scripts\OOBE.cmd" >NUL
DEL "%~f0"
"@
	$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
	SC -Path $SetupCompleteScript -Value $SetupComplete -Encoding ASCII -Force
}

$SETUPCOMPLETE3 = {
	$SetupComplete = @"
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
		[void](NI -Type Directory -Path "$MountFolder\Windows\Setup\Scripts" -Force)
		$SetupCompleteScript = Join-Path -Path "$MountFolder\Windows\Setup\Scripts" -ChildPath "SetupComplete.cmd"
		SC -Path $SetupCompleteScript -Value $SetupComplete -Encoding ASCII -Force
	}
	Else
	{
		AC -Path "$MountFolder\Windows\Setup\Scripts\SetupComplete.cmd" -Value $SetupComplete -Encoding ASCII -Force
	}
}
#endregion Helper Script-Blocks
# SIG # Begin signature block
# MIIJRAYJKoZIhvcNAQcCoIIJNTCCCTECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxCbna3VhASyRkpUNvCwt5el+
# mcagggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
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
# qHcndUPZwjGCAh0wggIZAgEBMD0wKTEnMCUGA1UEAxMeT01OSUMuVEVDSC1DQSBD
# ZXJ0aWZpY2F0ZSBSb290AhB0u1Cd2puAkkG+oZic5rsmMAkGBSsOAwIaBQCggbYw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGkXcpzyjxYlcjIOwRCiraCsR99hMFYG
# CisGAQQBgjcCAQwxSDBGoESAQgBPAHAAdABpAG0AaQB6AGUALQBPAGYAZgBsAGkA
# bgBlACcAcwAgAGgAZQBsAHAAZQByACAAcwBjAHIAaQBwAHQALjANBgkqhkiG9w0B
# AQEFAASCAQCA1BfV30C1cA10NKUVfjCZPt3lCL85AVT8AuSAtHuqmwMib/pMueDm
# GGWTSRylr674uRrNictSRLGTJ86pFzK7kmMAlqIv159Iub5MCG0JKP86Yv7r8rDd
# lv8peFtKPktJo/1Av5e+cC4AxBAfPvaxqwe6YvyXKA2bJPqveFaXuCG9jY+LoBB3
# 80Fp2tMVL+TqWHSiJF18Wmmjr6sCegi5qPIREULXUq6aYaHBFyRtYA2+pBJ2ctjS
# oaaUyeMLOvMnJ3VxhY/q/mhJNCicfG3ePBwVVDS4xfQuLHm/7EwDjWpsCxwCkw7r
# tU9W7urA5ly74qtZ+rSO75rF8gSh7D7G
# SIG # End signature block
