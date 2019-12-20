Function Get-DISMPath
{
    [CmdletBinding()]
    [OutputType([IO.DirectoryInfo])]
    Param ()

    [IO.DirectoryInfo]$DISMPath = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots", "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots") | ForEach-Object -Process { Get-ItemProperty -Path $PSItem -ErrorAction Ignore } | Select-Object -Unique -ExpandProperty KitsRoot10 -ErrorAction Ignore | Join-Path -ChildPath "Assessment and Deployment Kit\Deployment Tools\$Env:PROCESSOR_ARCHITECTURE\DISM" -ErrorAction Ignore
    If ($DISMPath.Exists) { $DISMPath.FullName }
}