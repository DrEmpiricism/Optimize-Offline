@ECHO OFF
CD /D "%~dp0"

REM After setting the SourcePath and SourceBuild variables, run this script as an administrator to quickly call Optimize-Offline without having to manually do it.
REM The variables carry over to the PowerShell script, as do the switches.

REM Start PowerShell Variables
SET "C:\ESD\install.wim"
REM End PowerShell Variables

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    ECHO Running as Administrator.
    TIMEOUT /T 2 >NUL
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -MetroApps "Select" -SystemApps -Packages -Features -Win32Calc -Dedup -DaRT -Registry
    REM PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -MetroApps "All" -SystemApps -Packages -Registry -Win32Calc -DaRT -Drivers -NetFx3
    REM PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -MetroApps "Whitelist" -SystemApps -Packages -NetFx3
    REM PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -SystemApps -Packages -Registry -DaRT -WindowsStore -MicrosoftEdge -ISO
)
PAUSE
EXIT
