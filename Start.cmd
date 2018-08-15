@ECHO OFF
CD /D "%~dp0"

REM After setting the SourcePath and SourceBuild variables, run this script as an administrator to quickly call Optimize-Offline without having to manually do it.
REM The variables carry over to the PowerShell script, as do the switches.

REM Start PowerShell Variables
SET "SourcePath=X:\PathToImage"
SET "SourceBuild=17134"
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
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -Build %SourceBuild% -MetroApps "Select" -SystemApps -Registry "Default" -Packages -DaRT -Drivers -NetFx3
)
PAUSE
EXIT
