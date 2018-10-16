@ECHO OFF
CD /D "%~dp0"

REM After setting the SourcePath and SourceBuild variables, run this script as an administrator to quickly call Optimize-Offline without having to manually do it.
REM The variables carry over to the PowerShell script, as do the switches.

REM Start PowerShell Variables
SET "SourcePath=X:\PathToImage"
SET "SourceBuild=17134"
SET "DriverPath=X:\PathToDrivers"
SET "NetFx3Path=X:\PathToPayload" -OR- $true
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
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -Build %SourceBuild% -MetroApps "Select" -SystemApps -Packages -OneDrive -Registry "Default" -DaRT -Drivers "%DriverPath%" -NetFx3 "%NetFx3Path%"
    REM PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -Build %SourceBuild% -MetroApps "All" -SystemApps -Packages -Registry "Harden" -DaRT -NetFx3 $true -NoSetup -WindowsStore
)
PAUSE
EXIT