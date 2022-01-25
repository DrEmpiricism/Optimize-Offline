@ECHO OFF
CD /D "%~dp0"

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-Additional.ps1 -Argument 2> .\Set-Additional.error
)
PAUSE
EXIT

