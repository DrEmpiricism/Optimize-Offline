Function Test-Requirements
{
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Warning ('Elevation is required to process optimizations. Please relaunch {0} as an administrator.' -f $ManifestData.ModuleName); Break
    }
    If ((Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "$($ManifestData.HostEnvironment[0])*" -and (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "$($ManifestData.HostEnvironment[1])*" -and (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "$($ManifestData.HostEnvironment[2])*")
    {
        Write-Warning ('{0} requires "{1}", "{2}" or "{3}" host environments.' -f $ManifestData.ModuleName, $ManifestData.HostEnvironment[0], $ManifestData.HostEnvironment[1], $ManifestData.HostEnvironment[2]); Break
    }
    If ($Env:PROCESSOR_ARCHITECTURE -ne $ManifestData.ProcessorArchitecture)
    {
        Write-Warning ('{0} requires an "{1}" processor architecture.' -f $ManifestData.ModuleName, $ManifestData.ProcessorArchitecture); Break
    }
    If (Test-Path -Path HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT)
    {
        Write-Warning ('{0} cannot be run in a Preinstallation environment.' -f $ManifestData.ModuleName); Break
    }
    If ($PSCulture -ne $ManifestData.Culture)
    {
        Write-Warning ('{0} is designed for the "{1}" regional culture. Not all optimizations will be available for the current "{2}" regional culture.' -f $ManifestData.ModuleName, $ManifestData.Culture, $PSCulture); Start-Sleep 5
    }
}