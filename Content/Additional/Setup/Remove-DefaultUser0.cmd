@ECHO OFF
CD /D "%~dp0"

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remove-DefaultUser0.ps1 -Argument 2> .\Remove-DefaultUser0.error
    DEL /F /Q "%~dp0Remove-DefaultUser0.error" >NUL 2>&1
    DEL /F /Q "%~dp0Remove-DefaultUser0.ps1" >NUL 2>&1
    DEL /F /Q "%~f0" >NUL 2>&1
)
PAUSE
EXIT

