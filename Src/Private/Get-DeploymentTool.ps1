Function Get-DeploymentTool
{
    [CmdletBinding(DefaultParameterSetName = 'DISM')]
    [OutputType([IO.DirectoryInfo])]
    Param
    (
        [Parameter(ParameterSetName = 'DISM',
            Position = 0)]
        [Switch]$DISM,
        [Parameter(ParameterSetName = 'OSCDIMG',
            Position = 0)]
        [Switch]$OSCDIMG
    )

    [IO.DirectoryInfo]$DeploymentTool = @("HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots") | ForEach-Object -Process { Get-ItemProperty -Path $PSItem -ErrorAction Ignore } | Select-Object -Unique -ExpandProperty KitsRoot10 -ErrorAction Ignore | Join-Path -ChildPath ("Assessment and Deployment Kit\Deployment Tools\$Env:PROCESSOR_ARCHITECTURE\{0}" -f $PSCmdlet.ParameterSetName) -ErrorAction Ignore
    If ($DeploymentTool.Exists) { $DeploymentTool.FullName }
}