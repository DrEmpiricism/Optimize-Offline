Function Additional-Features {
    [CmdletBinding()]
    Param ()
	
    $ProgressPreference = "SilentlyContinue"
    $WallpaperPath = "$PSScriptRoot\Additional\Images\Wallpaper"
    $LockScreenPath = "$PSScriptRoot\Additional\Images\LockScreen"
    $SystemLogoPath = "$PSScriptRoot\Additional\Images\Logo"
    $AccountPicturePath = "$PSScriptRoot\Additional\Images\Account"
    $UnattendPath = "$PSScriptRoot\Additional\Unattend"
    $Win32Calc = "$PSScriptRoot\Additional\Win32Calc"
	
    Function Set-FileOwnership($Path) {
        Invoke-Expression -Command ('TAKEOWN /F $Path /A')
        $ACL = Get-Acl -Path $Path
        $SID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
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
	
    Try {
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
    Finally {
        [System.GC]::Collect()
        [void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
        Start-Sleep 3
    }
	
    If ((Get-ChildItem -Path $LockScreenPath -Recurse) -ne $null) {
        Write-Output ''
        Write-Output "Adding Lock Screen."
        Start-Sleep 2
        [void](Set-FolderOwnership "$MountFolder\Windows\Web\Screen")
        Copy-Item -Path "$LockScreenPath\*" -Destination "$MountFolder\Windows\Web\Screen" -Recurse -Force
    }

    If ((Get-ChildItem -Path $WallpaperPath -Recurse) -ne $null) {
        Write-Output ''
        Write-Output "Adding Wallpaper."
        Start-Sleep 2
        Copy-Item -Path "$WallpaperPath\*" -Destination "$MountFolder\Windows\Web\Wallpaper" -Recurse -Force
    }

    If ((Get-ChildItem -Path $SystemLogoPath -Recurse) -ne $null) {
        Write-Output ''
        Write-Output "Adding System Logo."
        Start-Sleep 2
        New-Container -Path "$MountFolder\Windows\System32\oobe\info\logo"
        Copy-Item -Path "$SystemLogoPath\*" -Filter "*.bmp" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Recurse -Force
    }

    If ((Get-ChildItem -Path $AccountPicturePath -Recurse) -ne $null) {
        Write-Output ''
        Write-Output "Replacing Account Pictures."
        Start-Sleep 2
        [void](Set-FolderOwnership "$MountFolder\ProgramData\Microsoft\User Account Pictures")
        Copy-Item -Path "$AccountPicturePath\*" -Destination "$MountFolder\ProgramData\Microsoft\User Account Pictures" -Recurse -Force
    }
	
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
	
    If ((Test-Path -Path "$Win32Calc\Win32Calc.wim") -and (Test-Path -Path "$Win32Calc\Win32Calc_en-US.wim")) {
        Write-Output ''
        Write-Output "Applying the Win32 Calculator."
        [void](Expand-WindowsImage -ApplyPath $MountFolder -ImagePath "$Win32Calc\Win32Calc.wim" -Index 1 -CheckIntegrity -Verify)
        [void](Expand-WindowsImage -ApplyPath $MountFolder -ImagePath "$Win32Calc\Win32Calc.wim" -Index 2 -CheckIntegrity -Verify)
        [void](Expand-WindowsImage -ApplyPath $MountFolder -ImagePath "$Win32Calc\Win32Calc_en-US.wim" -Index 1 -CheckIntegrity -Verify)
        [void](Expand-WindowsImage -ApplyPath $MountFolder -ImagePath "$Win32Calc\Win32Calc_en-US.wim" -Index 2 -CheckIntegrity -Verify)
        $W32CalcStr = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes\calculator]
@="URL:calculator"
"URL Protocol"=""

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes\calculator\DefaultIcon]
@="C:\\Windows\\System32\\win32calc.exe,0"

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes\calculator\shell\open\command]
@="C:\\Windows\\System32\\win32calc.exe"

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\App Management\WindowsFeatureCategories]
"COMMONSTART/Programs/Accessories/Calculator.lnk"="SOFTWARE_CATEGORY_UTILITIES"

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\InboxApp]
"56230F2FD0CC3EB4_Calculator_lnk_amd64.lnk"=hex(2):43,00,3a,00,5c,00,50,00,72,\
  00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,00,61,00,5c,00,4d,00,69,00,\
  63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,\
  00,77,00,73,00,5c,00,53,00,74,00,61,00,72,00,74,00,20,00,4d,00,65,00,6e,00,\
  75,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,73,00,5c,00,41,00,63,\
  00,63,00,65,00,73,00,73,00,6f,00,72,00,69,00,65,00,73,00,5c,00,43,00,61,00,\
  6c,00,63,00,75,00,6c,00,61,00,74,00,6f,00,72,00,2e,00,6c,00,6e,00,6b,00,00,\
  00

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Debug]
"OwningPublisher"="{75f48521-4131-4ac3-9887-65473224fcb2}"
"Enabled"=dword:00000000
"Isolation"=dword:00000000
"ChannelAccess"="O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)"
"Type"=dword:00000003

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Calculator/Diagnostic]
"OwningPublisher"="{75f48521-4131-4ac3-9887-65473224fcb2}"
"Enabled"=dword:00000000
"Isolation"=dword:00000000
"ChannelAccess"="O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)"
"Type"=dword:00000002

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}]
@="Microsoft-Windows-Calculator"
"ResourceFileName"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,77,00,69,00,6e,00,33,00,32,00,63,00,61,00,6c,00,63,00,2e,00,65,00,78,\
  00,65,00,00,00
"MessageFileName"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,\
  6f,00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,\
  00,77,00,69,00,6e,00,33,00,32,00,63,00,61,00,6c,00,63,00,2e,00,65,00,78,00,\
  65,00,00,00

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences]
"Count"=dword:00000002

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\0]
@="Microsoft-Windows-Calculator/Diagnostic"
"Id"=dword:00000010
"Flags"=dword:00000000

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{75f48521-4131-4ac3-9887-65473224fcb2}\ChannelReferences\1]
@="Microsoft-Windows-Calculator/Debug"
"Id"=dword:00000011
"Flags"=dword:00000000

[HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Management\WindowsFeatureCategories]
"COMMONSTART/Programs/Accessories/Calculator.lnk"="SOFTWARE_CATEGORY_UTILITIES"

'@
		
        $W32RegFile = Join-Path -Path $WorkFolder -ChildPath "Win32Calc.reg"
        Set-Content -Path $W32RegFile -Value $W32CalcStr -Encoding Unicode -Force
        [void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\Windows\System32\config\software")
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
}
# SIG # Begin signature block
# MIIMrQYJKoZIhvcNAQcCoIIMnjCCDJoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2PbJ9yM4LsSMJlrhsvGrCbYE
# FfGgggj8MIIDfTCCAmWgAwIBAgIQfY66zkudTZ9EnV2nSZm8oDANBgkqhkiG9w0B
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
# FiUxggMbMIIDFwIBATBcMEUxFDASBgoJkiaJk/IsZAEZFgRURUNIMRUwEwYKCZIm
# iZPyLGQBGRYFT01OSUMxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0ECEyEAAAAFfOz8
# 2RcyuMQAAAAAAAUwCQYFKw4DAhoFAKCCAZQwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFL21DgA0xhTJNhUDzikyG3hfcEwPMIIBMgYKKwYBBAGCNwIBDDGCASIwggEe
# oIIBGoCCARYAQQAgAGYAdQBuAGMAdABpAG8AbgAgAHQAaABhAHQAIABjAGEAbgAg
# AGIAZQAgAGMAYQBsAGwAZQBkACAAYgB5ACAAdABoAGUAIABtAGEAaQBuACAATwBw
# AHQAaQBtAGkAegBlAC0ATwBmAGYAbABpAG4AZQAgAHMAYwByAGkAcAB0ACAAdABo
# AGEAdAAgAHcAaQBsAGwAIABhAGQAZAAgAGEAZABkAGkAdABpAG8AbgBhAGwAIABm
# AGUAYQB0AHUAcgBlAHMAIABmAG8AcgAgAGEAIABtAG8AcgBlACAAZABlAHYAaQBj
# AGUALQBzAHAAZQBjAGkAZgBpAGMAIABmAGkAbgBhAGwAIABpAG0AYQBnAGUALjAN
# BgkqhkiG9w0BAQEFAASCAQDNJH7nL7DWCq5FJSzrlSbCK6q2IDjubouy5pb31F9T
# 7q3ehiCbYZM1f1QO15A8Y0U0YELH992jEoIYpEJj3nu+NS1oSrwLHCii/VNwp4G9
# Rv5kn/CsfyoS9MvhJknDFh2Ko3DnMY3Rar2PiUXWAOgC71gGBJYDOsiClayrhVdc
# cZfp5O4jcV0zP+JABnhL4EuOKGms67Y/0x9I68WDxo9cW8wG04hZJAbwrhMbRqd3
# nRSWMMpZhWRddeKaQT9qoeWR8mrroW6hm+JTEBG5labLrVHrZpU0dmYdMaTdVm2S
# bJIdO1b55m/NxGp8JOOj9TLgK5uGjei5cN2FVfKt4wZ+
# SIG # End signature block
