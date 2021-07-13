Function Test-Requirements
{
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Warning ('Elevation is required to process optimizations. Please relaunch {0} as an administrator.' -f $OptimizeOffline.BaseName); Break }
    If ($PSVersionTable.PSVersion.Major -lt 5) { Write-Warning ('{0} does not support PowerShell version {1}' -f $OptimizeOffline.BaseName, $PSVersionTable.PSVersion.ToString()); Break }
    #$OSCaption = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
    #$HostEnvironment = @('Microsoft Windows 10', 'Microsoft Windows Server 2016', 'Microsoft Windows Server 2019')
    #If ($OSCaption -notlike "$($HostEnvironment[0])*" -and $OSCaption -notlike "$($HostEnvironment[1])*" -and $OSCaption -notlike "$($HostEnvironment[2])*") { Write-Warning ('{0} requires one of the following host environments: {1}.' -f $OptimizeOffline.BaseName, ($HostEnvironment -join ', ')); Break }
    If ($Env:PROCESSOR_ARCHITECTURE -ne $ManifestData.ProcessorArchitecture) { Write-Warning ('{0} requires an "{1}" processor architecture.' -f $OptimizeOffline.BaseName, $ManifestData.ProcessorArchitecture); Break }
    If (Test-Path -Path HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT) { Write-Warning ('{0} cannot be run in a Preinstallation environment.' -f $OptimizeOffline.BaseName); Break }
    If ((Get-UICulture).Name -ne $OptimizeOffline.Culture) { Write-Warning ('{0} is designed for the "{1}" regional culture. Not all optimizations will be available for the "{2}" regional culture.' -f $OptimizeOffline.BaseName, $OptimizeOffline.Culture, (Get-UICulture).Name); Start-Sleep 5 }
}