Function Get-Path
{
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType([IO.FileSystemInfo])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Alias('FullName')]
        [String[]]$Path,
        [Parameter(ParameterSetName = 'Join',
            Position = 1)]
        [String]$ChildPath,
        [Parameter(ParameterSetName = 'Split',
            Position = 1)]
        [ValidateSet('Parent', 'Leaf')]
        [String]$Split = 'Parent'
    )

    Process
    {
        ForEach ($Item In $Path)
        {
            $IsRegistry = $null
            If (Test-Path -LiteralPath $Item)
            {
                If ((Get-Item -LiteralPath $Item -Force -ErrorAction:$ErrorActionPreference) -is [Microsoft.Win32.RegistryKey]) { $IsRegistry = $true }
                Else { $Item = (Resolve-Path -LiteralPath $Item -ErrorAction:$ErrorActionPreference).ProviderPath }
            }
            If ($PSCmdlet.ParameterSetName -eq 'Join' -and $ChildPath)
            {
                If ($IsRegistry -eq $true) { Join-Path -Path $Item -ChildPath $ChildPath -ErrorAction:$ErrorActionPreference }
                Else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Join-Path -Path $Item -ChildPath $ChildPath -ErrorAction:$ErrorActionPreference)) }
            }
            ElseIf ($PSCmdlet.ParameterSetName -eq 'Split')
            {
                Switch ($PSBoundParameters.Split)
                {
                    'Parent'
                    {
                        If ($IsRegistry -eq $true) { Split-Path -Path $Item -Parent -ErrorAction:$ErrorActionPreference }
                        Else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Split-Path -Path $Item -Parent -ErrorAction:$ErrorActionPreference)) }
                    }
                    'Leaf'
                    {
                        Split-Path -Path $Item -Leaf -ErrorAction:$ErrorActionPreference
                    }
                }
            }
            Else
            {
                If ($IsRegistry -eq $true) { $Item }
                Else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Item) }
            }
        }
    }
}