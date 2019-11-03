Function Test-Requirements
{
    [CmdletBinding()]
    Param ()

    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Warning "Elevation is required to process optimizations. Please relaunch $($ScriptInfo.Name) as an administrator."; Break
    }

    If (((Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "Microsoft Windows 10*") -and ((Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "Microsoft Windows Server 2016*"))
    {
        Write-Warning "$($ScriptInfo.Name) requires a Windows 10 or Windows Server 2016 environment."; Break
    }

    If (Test-Path -Path HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT)
    {
        Write-Warning "$($ScriptInfo.Name) cannot be run in a Preinstallation environment."; Break
    }
}