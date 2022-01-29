CD /D "%~dp0"

REM Answer files should ALWAYS be removed from the 'Windows\Panther' and 'Windows\System32\Sysprep' directories immediately after they've been processed.

PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%WINDIR%\Setup\Scripts\Refresh-Explorer.ps1"
DEL /F /Q "%WINDIR%\Setup\Scripts\Refresh-Explorer.ps1" >NUL 2>&1
DEL /F /Q "%WINDIR%\Setup\Scripts\Run_TI_SetupComplete_online.cmd >NUL 2>&1
DEL /F /Q "%WINDIR%\Panther\unattend.xml" >NUL 2>&1
DEL /F /Q "%WINDIR%\System32\Sysprep\unattend.xml" >NUL 2>&1
DEL "%~f0"
