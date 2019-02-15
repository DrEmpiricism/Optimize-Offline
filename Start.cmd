@ECHO OFF
CD /D "%~dp0"

REM After setting the appropriate variables and switches, run this script as an administrator to quickly call Optimize-Offline.
REM A list of all available variables and switches can be found on the main GitHub page.

REM Set the Optimize-Offline Source Path variable.
SET "SourcePath=X:\PathToImage"

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    ECHO Running as Administrator.
    TIMEOUT /T 2 >NUL
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-Offline.ps1 -ImagePath "%SourcePath%" -MetroApps "Select" -SystemApps -Packages -Features -Win32Calc -Dedup -Registry -ISO
)
PAUSE
EXIT